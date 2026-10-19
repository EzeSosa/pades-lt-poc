import base64
from datetime import datetime

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool

from ....application.use_cases.certificate_chains import SignatureChains
from ....application.use_cases.inspect_certificates import InspectedCertificate
from ....domain.chains import ChainLink, ChainResult
from ....domain.signatures import SignatureKind
from .dependencies import ClockDep, ExtractCertificateChainsDep, InspectCertificatesDep

router = APIRouter(tags=["Certificados"])


@router.post("/certificates")
async def certificates(
    extractor: ExtractCertificateChainsDep, pdf: UploadFile = File(...), fetch_missing: bool = Form(True)
) -> dict:
    """Cadena de certificados (hoja -> raíz) de cada firma criptográficamente válida.

    No exige confianza: la cadena se arma con los certificados que trae el propio
    PDF (CMS de la firma + DSS), verificando que cada uno haya firmado al anterior.
    Si falta algún emisor y `fetch_missing` es true, se descarga desde la URL AIA
    caIssuers del certificado (cada cert indica su origen en `source`).
    """
    data = await pdf.read()
    # Las descargas AIA son bloqueantes: fuera del event loop.
    results = await run_in_threadpool(extractor.extract, data, fetch_missing)
    return {"signatures": [present_signature(r) for r in results]}


@router.post("/certificates/inspect")
async def inspect_certificate(
    inspector: InspectCertificatesDep,
    clock: ClockDep,
    crt: UploadFile | None = File(None, description="Archivo .crt/.cer/.pem/.p7c: DER, PEM o PKCS#7."),
    b64: str | None = Form(None, description="Alternativa al archivo: el base64 de un DER (p. ej. un der_b64)."),
) -> dict:
    """Detalle de cada certificado recibido: sujeto, emisor, vigencia, clave, huellas y extensiones.

    Un PKCS#7 puede traer varios certificados: se devuelven todos, en el orden en que vienen.
    """
    if (crt is None) == (b64 is None):
        raise HTTPException(422, "Mandá un archivo `crt` o un `b64`, uno solo de los dos")
    data = await crt.read() if crt is not None else b64.encode()
    now = clock.now()
    return {"certificates": [present_inspected(c, now) for c in inspector.inspect(data)]}


# --------------------------------------------------------------------------- presenters
def present_signature(result: SignatureChains) -> dict:
    entry = {"field": result.field_name, "type": result.kind.value, **present_chain(result.chain)}
    if result.kind is SignatureKind.SIGNATURE:
        ts = result.timestamp
        entry["signature_timestamp"] = {"time": ts.time.isoformat(), **present_chain(ts.chain)} if ts else None
    return entry


def present_chain(chain: ChainResult) -> dict:
    out = {"crypto_valid": chain.crypto_valid, "intact": chain.intact, "valid": chain.valid}
    if not chain.crypto_valid:
        out["error"] = chain.error
        out["certificates"] = None
        return out
    out["chain_complete"] = chain.chain_complete
    out["certificates"] = [_present_link(link, i) for i, link in enumerate(chain.links)]
    if chain.aia_errors:
        out["aia_errors"] = list(chain.aia_errors)
    return out


def _present_link(link: ChainLink, position: int) -> dict:
    cert = link.certificate
    return {
        "type": "end_entity" if position == 0 else "root" if cert.self_signed else "intermediate",
        "source": link.source.value,
        "self_signed": cert.self_signed,
        "subject": cert.subject,
        "issuer": cert.issuer,
        "serial_number": format(cert.serial_number, "x"),
        "not_before": cert.not_before.isoformat(),
        "not_after": cert.not_after.isoformat(),
        "sha256_fingerprint": cert.sha256,
        "der_b64": base64.b64encode(cert.der).decode(),
        "in_store": link.in_store,
    }


def present_inspected(inspected: InspectedCertificate, now: datetime) -> dict:
    cert, details = inspected.certificate, inspected.details
    public_key = {"type": details.public_key.type, "size": details.public_key.size}
    if details.public_key.curve is not None:
        public_key["curve"] = details.public_key.curve
    return {
        "version": details.version,
        "serial_number": format(cert.serial_number, "x"),
        "subject": [{"oid": a.oid, "name": a.name, "value": a.value} for a in details.subject],
        "issuer": [{"oid": a.oid, "name": a.name, "value": a.value} for a in details.issuer],
        "subject_rfc4514": cert.subject,
        "issuer_rfc4514": cert.issuer,
        "self_signed": cert.self_signed,
        "is_ca": cert.is_ca,
        "validity": {
            "not_before": cert.not_before.isoformat(),
            "not_after": cert.not_after.isoformat(),
            "status": cert.validity_status(now).value,
            "days_left": cert.days_left(now),
        },
        "signature_algorithm": details.signature_algorithm,
        "public_key": public_key,
        "fingerprints": {"sha1": cert.sha1, "sha256": cert.sha256},
        "extensions": [
            {"oid": e.oid, "name": e.name, "critical": e.critical, "values": list(e.values)} for e in details.extensions
        ],
        "der_b64": base64.b64encode(cert.der).decode(),
        "in_store": inspected.in_store,
    }
