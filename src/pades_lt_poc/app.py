"""
PoC FastAPI: firma PAdES B-LT (opcionalmente B-LTA) con pyHanko.

Endpoints:
  GET  /pki/{root|intermediate}.crt   certificados de las CAs (PEM)
  GET  /pki/{root|intermediate}.crl   CRLs (DER)
  POST /pki/revoke/{entidad}          revoca intermediate|signer|tsa (para pruebas)
  POST /pki/unrevoke-all              deshace todas las revocaciones
  POST /ocsp  | GET /ocsp/{b64}       respondedor OCSP RFC 6960
  POST /tsa                           TSA RFC 3161
  POST /sign                          sube un PDF, devuelve el PDF firmado PAdES B-LT
  POST /verify                        valida offline usando sólo el DSS embebido
  POST /certificates                  extrae la cadena de certificados de cada firma válida
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable
from contextlib import asynccontextmanager
from io import BytesIO

import requests
from asn1crypto import cms, tsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import AuthorityInformationAccessOID
from fastapi import FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.concurrency import run_in_threadpool
from pyhanko.keys import load_cert_from_pemder, load_private_key_from_pemder
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers
from pyhanko.sign.timestamps import DummyTimeStamper, HTTPTimeStamper
from pyhanko.sign.validation import DocumentSecurityStore, async_validate_pdf_signature
from pyhanko.sign.validation.errors import SignatureValidationError
from pyhanko.sign.validation.generic_cms import (
    extract_certs_for_validation,
    extract_tst_data_iter,
    message_imprint_checker,
    validate_sig_integrity,
)
from pyhanko.sign.validation.pdf_embedded import EmbeddedPdfSignature
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore

from . import pki


@asynccontextmanager
async def lifespan(app: FastAPI):
    pki.ensure_pki()
    root = load_cert_from_pemder(str(pki.entity(pki.ROOT).cert_path))
    intermediate = load_cert_from_pemder(str(pki.entity(pki.INTERMEDIATE).cert_path))
    tsa_cert = load_cert_from_pemder(str(pki.entity(pki.TSA).cert_path))

    # El "motor" de la TSA: pyHanko ya trae un emisor de tokens RFC 3161.
    # Nosotros lo exponemos por HTTP en /tsa para que la firma lo consuma
    # como si fuera una TSA externa.
    app.state.tsa_engine = DummyTimeStamper(
        tsa_cert=tsa_cert,
        tsa_key=load_private_key_from_pemder(str(pki.entity(pki.TSA).key_path), passphrase=None),
        certs_to_embed=SimpleCertificateStore.from_certs([tsa_cert, intermediate, root]),
    )
    app.state.signer = signers.SimpleSigner.load(
        key_file=str(pki.entity(pki.SIGNER).key_path),
        cert_file=str(pki.entity(pki.SIGNER).cert_path),
        ca_chain_files=(
            str(pki.entity(pki.INTERMEDIATE).cert_path),
            str(pki.entity(pki.ROOT).cert_path),
        ),
    )
    app.state.root = root  # único ancla de confianza
    yield


app = FastAPI(title="PoC PAdES B-LT", lifespan=lifespan)


# --------------------------------------------------------------------------- PKI
def _ca(name: str) -> str:
    if name not in pki.CAS:
        raise HTTPException(404, f"CA desconocida, usar: {', '.join(pki.CAS)}")
    return name


@app.get("/pki/{ca}.crt")
def get_ca_cert(ca: str) -> Response:
    return Response(pki.entity(_ca(ca)).cert_path.read_bytes(), media_type="application/x-pem-file")


@app.get("/pki/{ca}.crl")
def get_crl(ca: str) -> Response:
    return Response(pki.build_crl(_ca(ca)), media_type="application/pkix-crl")


@app.post("/pki/revoke/{who}")
def revoke(who: str) -> dict:
    """Sólo para probar: revoca un certificado y las próximas firmas fallarán."""
    if who not in pki.ISSUER_OF or who == pki.OCSP_RESPONDER:
        raise HTTPException(404, "usar 'intermediate', 'signer' o 'tsa'")
    return {"revoked": who, "serial": pki.revoke(who)}


@app.post("/pki/unrevoke-all")
def unrevoke_all() -> dict:
    pki.unrevoke_all()
    return {"ok": True}


# --------------------------------------------------------------------------- OCSP
@app.post("/ocsp")
async def ocsp_post(request: Request) -> Response:
    return Response(pki.ocsp_respond(await request.body()), media_type="application/ocsp-response")


@app.get("/ocsp/{b64_request:path}")
def ocsp_get(b64_request: str) -> Response:
    # RFC 6960 Apéndice A.1: GET {url}/{url-encoding de base64(DER)}
    return Response(
        pki.ocsp_respond(base64.b64decode(b64_request)), media_type="application/ocsp-response"
    )


# --------------------------------------------------------------------------- TSA
@app.post("/tsa")
async def tsa(request: Request) -> Response:
    if request.headers.get("content-type") != "application/timestamp-query":
        raise HTTPException(415, "se esperaba application/timestamp-query")
    req = tsp.TimeStampReq.load(await request.body())
    resp = await app.state.tsa_engine.async_request_tsa_response(req)
    return Response(resp.dump(), media_type="application/timestamp-reply")


# --------------------------------------------------------------------------- Firma
@app.post("/sign")
async def sign(
    request: Request,
    pdf: UploadFile = File(...),
    reason: str = Form("Conformidad"),
    location: str = Form("Buenos Aires, AR"),
    lta: bool = Form(False, description="Agregar además un Document TimeStamp (B-LTA)"),
) -> Response:
    writer = IncrementalPdfFileWriter(BytesIO(await pdf.read()))
    base = str(request.base_url).rstrip("/")
    # Nombre de campo único, así se puede re-firmar un PDF ya firmado (co-firma).
    field_name = f"Firma{len(writer.prev.embedded_signatures) + 1}"

    # Contexto de validación usado AL FIRMAR: pyHanko construye la cadena,
    # descarga las CRL (del CDP de cada certificado) y las embebe en el DSS.
    vc = ValidationContext(
        trust_roots=[app.state.root],
        allow_fetching=True,
        revocation_mode="hard-fail",
    )
    meta = signers.PdfSignatureMetadata(
        field_name=field_name,
        reason=reason,
        location=location,
        md_algorithm="sha256",
        subfilter=fields.SigSeedSubFilter.PADES,  # ETSI.CAdES.detached
        embed_validation_info=True,  # => DSS con certs + CRLs  => B-LT
        use_pades_lta=lta,  # => + DocTimeStamp          => B-LTA
        validation_context=vc,
    )
    try:
        out = await signers.async_sign_pdf(
            writer,
            meta,
            signer=app.state.signer,
            timestamper=HTTPTimeStamper(f"{base}/tsa"),  # sello de tiempo de firma => B-T
        )
    except Exception as e:  # noqa: BLE001 - PoC: devolver el motivo al cliente
        raise HTTPException(422, f"No se pudo firmar: {type(e).__name__}: {e}") from e

    name = (pdf.filename or "documento.pdf").removesuffix(".pdf")
    return Response(
        out.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{name}-pades-lt.pdf"'},
    )


# --------------------------------------------------------------------------- Verificación
@app.post("/verify")
async def verify(pdf: UploadFile = File(...)) -> dict:
    reader = PdfFileReader(BytesIO(await pdf.read()))
    if not reader.embedded_signatures:
        raise HTTPException(422, "El PDF no tiene firmas")

    has_dss = "/DSS" in reader.root
    # Validación OFFLINE: sin fetching, con revocación obligatoria. Sólo pasa si
    # todo lo necesario (certs + CRLs) está dentro del PDF -> prueba de B-LT.
    vc_kwargs = dict(trust_roots=[app.state.root], allow_fetching=False, revocation_mode="hard-fail")
    vc = (
        DocumentSecurityStore.read_dss(reader).as_validation_context(vc_kwargs)
        if has_dss
        else ValidationContext(**vc_kwargs)
    )

    results = []
    for sig in reader.embedded_signatures:
        if sig.sig_object.get("/Type") == "/DocTimeStamp":
            results.append({"field": sig.field_name, "type": "DocTimeStamp"})
            continue
        status = await async_validate_pdf_signature(sig, signer_validation_context=vc, ts_validation_context=vc)
        results.append(
            {
                "field": sig.field_name,
                "type": "Signature",
                "subfilter": str(sig.sig_object.get("/SubFilter")),
                "signer": status.signing_cert.subject.human_friendly,
                "bottom_line": status.bottom_line,
                "intact": status.intact,
                "valid": status.valid,
                "trusted": status.trusted,
                "coverage": status.coverage.name,
                "signature_timestamp": (
                    {
                        "time": status.timestamp_validity.timestamp.isoformat(),
                        "tsa": status.timestamp_validity.signing_cert.subject.human_friendly,
                        "valid": status.timestamp_validity.valid,
                        "trusted": status.timestamp_validity.trusted,
                    }
                    if status.timestamp_validity
                    else None
                ),
                "details": status.pretty_print_details(),
            }
        )

    has_doc_ts = any(r["type"] == "DocTimeStamp" for r in results)
    sig_ok = [r for r in results if r["type"] == "Signature"]
    level = "PAdES B-B"
    if sig_ok and all(r["signature_timestamp"] for r in sig_ok):
        level = "PAdES B-T"
        if has_dss and all(r["bottom_line"] for r in sig_ok):
            level = "PAdES B-LTA" if has_doc_ts else "PAdES B-LT"
    dss = (
        {k: len(reader.root["/DSS"].get(f"/{k}", [])) for k in ("Certs", "OCSPs", "CRLs")}
        if has_dss
        else None
    )
    return {"pades_level": level, "dss": dss, "signatures": results}


# --------------------------------------------------------------------------- Certificados
def _check_integrity(
    signed_data: cms.SignedData, covered_digest: Callable[[str], bytes]
) -> tuple[bool, bool, str | None]:
    """(intact, valid, error) sólo criptográfico: no mira confianza ni revocación.

    `covered_digest(md)` devuelve el hash, con el algoritmo `md`, de lo que la
    firma dice cubrir: el ByteRange del PDF, o el valor de la firma que sella la TSA.
    """
    signer_info = signed_data["signer_infos"][0]
    eci = signed_data["encap_content_info"]
    content_type = eci["content_type"].native
    md = signer_info["digest_algorithm"]["algorithm"].native
    try:
        cert = extract_certs_for_validation(signed_data).signer_cert
        if content_type == "tst_info":
            # Sello de tiempo: los atributos firmados cubren el TSTInfo, y es su
            # messageImprint el que tiene que coincidir con lo sellado.
            tst_digest = hashlib.new(md, eci["content"].contents).digest()
            intact, valid = validate_sig_integrity(signer_info, cert, content_type, tst_digest)
            imprint = eci["content"].parsed["message_imprint"]
            imprint_md = imprint["hash_algorithm"]["algorithm"].native
            intact = intact and imprint["hashed_message"].native == covered_digest(imprint_md)
        else:
            intact, valid = validate_sig_integrity(signer_info, cert, content_type, covered_digest(md))
    except SignatureValidationError as e:
        return False, False, str(e)
    return intact, valid, None


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """True si `issuer` firmó `cert` (nombre del emisor + firma verificada)."""
    try:
        cert.verify_directly_issued_by(issuer)
    except ValueError as e:
        # cryptography rechaza algoritmos débiles como SHA-1, que siguen usando
        # PKIs reales (p. ej. la AC Raíz de Argentina firmando a sus CAs). Acá
        # sólo armamos la cadena, no evaluamos política: se verifica a mano.
        return "Unsupported signature algorithm" in str(e) and _verify_legacy(cert, issuer)
    except (TypeError, InvalidSignature):
        return False
    return True


def _verify_legacy(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    if cert.issuer != issuer.subject or cert.signature_hash_algorithm is None:
        return False
    key = issuer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        else:
            return False
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


AIA_TIMEOUT = 5  # segundos por descarga


def _http_get(url: str) -> bytes:
    r = requests.get(url, timeout=AIA_TIMEOUT)
    r.raise_for_status()
    return r.content


def _parse_certs(data: bytes) -> list[x509.Certificate]:
    """Los `.crt`/`.p7c` publicados en AIA pueden venir en DER, PEM o PKCS#7."""
    loaders = (
        lambda d: [x509.load_der_x509_certificate(d)],
        x509.load_pem_x509_certificates,
        pkcs7.load_der_pkcs7_certificates,
        pkcs7.load_pem_pkcs7_certificates,
    )
    for load in loaders:
        try:
            return load(data)
        except ValueError:
            continue
    raise ValueError("no es un certificado DER, PEM ni PKCS#7")


class _AiaFetcher:
    """Descarga emisores desde AIA caIssuers, con caché por request (firma y sello suelen compartir CA)."""

    def __init__(self) -> None:
        self._cache: dict[str, list[x509.Certificate] | str] = {}

    def issuers(self, cert: x509.Certificate) -> tuple[list[x509.Certificate], list[str]]:
        try:
            aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        except x509.ExtensionNotFound:
            return [], [f"{cert.subject.rfc4514_string()}: no tiene AIA caIssuers"]
        urls = [
            d.access_location.value
            for d in aia
            if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS
            and isinstance(d.access_location, x509.UniformResourceIdentifier)
            and d.access_location.value.lower().startswith(("http://", "https://"))
        ]
        certs: list[x509.Certificate] = []
        errors: list[str] = []
        for url in urls:
            if url not in self._cache:
                try:
                    self._cache[url] = _parse_certs(_http_get(url))
                except (requests.RequestException, ValueError) as e:
                    self._cache[url] = f"{url}: {e}"
            got = self._cache[url]
            if isinstance(got, str):
                errors.append(got)
            else:
                certs.extend(got)
        if not urls:
            errors.append(f"{cert.subject.rfc4514_string()}: no tiene AIA caIssuers por HTTP")
        return certs, errors


def _build_chain(
    leaf: x509.Certificate, pool: dict[x509.Certificate, str], fetcher: _AiaFetcher | None
) -> tuple[list[tuple[x509.Certificate, str]], list[str]]:
    """Sube desde `leaf` buscando al emisor de cada eslabón, hasta un autofirmado.

    Primero en `pool` (cert -> origen) y, si no está y hay `fetcher`, en las URLs
    AIA caIssuers del eslabón. Devuelve la cadena como (cert, origen) y los errores de AIA.
    """
    chain = [(leaf, pool[leaf])]
    errors: list[str] = []
    while not _issued_by(chain[-1][0], chain[-1][0]):
        current, used = chain[-1][0], [c for c, _ in chain]
        candidates = [(c, src) for c, src in pool.items() if c not in used]
        issuer = next(((c, s) for c, s in candidates if _issued_by(current, c)), None)
        if issuer is None and fetcher is not None:
            fetched, errs = fetcher.issuers(current)
            issuer = next(((c, "aia") for c in fetched if c not in used and _issued_by(current, c)), None)
            if issuer is None:
                errors.extend(errs or [f"{current.subject.rfc4514_string()}: AIA no trae a su emisor"])
        if issuer is None:
            break
        chain.append(issuer)
    return chain, errors


def _describe(cert: x509.Certificate, position: int, source: str) -> dict:
    self_signed = _issued_by(cert, cert)
    der = cert.public_bytes(serialization.Encoding.DER)
    return {
        "type": "end_entity" if position == 0 else "root" if self_signed else "intermediate",
        "source": source,
        "self_signed": self_signed,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "der_b64": base64.b64encode(der).decode(),
    }


def _extract_chain(
    signed_data: cms.SignedData,
    covered_digest: Callable[[str], bytes],
    extra_certs: list[tuple[asn1_x509.Certificate, str]],
    altered_msg: str,
    fetcher: _AiaFetcher | None = None,
) -> dict:
    """Chequeo criptográfico + cadena del firmante de `signed_data`.

    `extra_certs` son (cert, origen) que no vienen en `signed_data` pero sirven
    para completar la cadena; con `fetcher` se completa además por AIA.
    """
    intact, valid, error = _check_integrity(signed_data, covered_digest)
    out = {"crypto_valid": intact and valid, "intact": intact, "valid": valid}
    if not out["crypto_valid"]:
        out["error"] = error or (altered_msg if not intact else "firma inválida")
        out["certificates"] = None
        return out

    # Firmante primero, sin duplicados (el mismo cert suele estar en el CMS y en el
    # DSS: gana el primer origen).
    cms_certs = extract_certs_for_validation(signed_data)
    by_der: dict[bytes, str] = {}
    for c, src in [(cms_certs.signer_cert, "cms"), *((c, "cms") for c in cms_certs.other_certs), *extra_certs]:
        by_der.setdefault(c.dump(), src)
    pool = {x509.load_der_x509_certificate(der): src for der, src in by_der.items()}
    chain, aia_errors = _build_chain(next(iter(pool)), pool, fetcher)
    out["chain_complete"] = _issued_by(chain[-1][0], chain[-1][0])
    out["certificates"] = [_describe(c, i, src) for i, (c, src) in enumerate(chain)]
    if aia_errors:
        out["aia_errors"] = aia_errors
    return out


def _signature_timestamp(
    sig: EmbeddedPdfSignature, dss_certs: list[asn1_x509.Certificate], fetcher: _AiaFetcher | None
) -> dict | None:
    """Cadena de la TSA del sello de tiempo de la firma (atributo no firmado), o None si no tiene."""
    token = next(extract_tst_data_iter(sig.signer_info, signed=False), None)
    if token is None:
        return None
    # La TSA sella el valor de la firma. Sus certificados vienen en el token, y los
    # del CMS de la firma y del DSS sirven para completar la cadena.
    extra = [*((c, "cms") for c in sig.other_embedded_certs), *((c, "dss") for c in dss_certs)]
    out = _extract_chain(
        token, message_imprint_checker(sig.signer_info), extra, "el sello no corresponde a esta firma", fetcher
    )
    gen_time = token["encap_content_info"]["content"].parsed["gen_time"].native
    return {"time": gen_time.isoformat(), **out}


def _extract_all(data: bytes, fetch_missing: bool) -> dict:
    reader = PdfFileReader(BytesIO(data))
    if not reader.embedded_signatures:
        raise HTTPException(422, "El PDF no tiene firmas")

    dss_certs: list[asn1_x509.Certificate] = (
        list(DocumentSecurityStore.read_dss(reader).load_certs()) if "/DSS" in reader.root else []
    )
    dss_extra = [(c, "dss") for c in dss_certs]
    fetcher = _AiaFetcher() if fetch_missing else None

    results = []
    for sig in reader.embedded_signatures:
        is_doc_ts = sig.sig_object_type == "/DocTimeStamp"
        entry = {
            "field": sig.field_name,
            "type": "DocTimeStamp" if is_doc_ts else "Signature",
            **_extract_chain(sig.signed_data, sig.compute_digest, dss_extra, "el documento fue alterado", fetcher),
        }
        if not is_doc_ts:
            entry["signature_timestamp"] = (
                _signature_timestamp(sig, dss_certs, fetcher) if entry["crypto_valid"] else None
            )
        results.append(entry)

    return {"signatures": results}


@app.post("/certificates")
async def certificates(pdf: UploadFile = File(...), fetch_missing: bool = Form(True)) -> dict:
    """Cadena de certificados (hoja -> raíz) de cada firma criptográficamente válida.

    No exige confianza: la cadena se arma con los certificados que trae el propio
    PDF (CMS de la firma + DSS), verificando que cada uno haya firmado al anterior.
    Si falta algún emisor y `fetch_missing` es true, se descarga desde la URL AIA
    caIssuers del certificado (cada cert indica su origen en `source`).
    """
    data = await pdf.read()
    # Las descargas AIA son bloqueantes: fuera del event loop.
    return await run_in_threadpool(_extract_all, data, fetch_missing)


def main() -> None:
    import uvicorn

    uvicorn.run("pades_lt_poc.app:app", host="127.0.0.1", port=8000)
