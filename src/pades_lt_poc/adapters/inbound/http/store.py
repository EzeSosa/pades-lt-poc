import base64
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, File, Form, HTTPException, Response, UploadFile
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

from ....domain.certificates import CaKind
from ....domain.errors import CertificateNotFound, DuplicateCertificate
from ....domain.source import EntryChanges, Origin, StoredCertificate
from .dependencies import CertificateSourceDep, ClockDep

router = APIRouter(prefix="/store", tags=["Fuente de certificados"])


class CertificateUpdate(BaseModel):
    enabled: bool | None = None
    trusted: bool | None = None
    notes: str | None = None


def present(entry: StoredCertificate, now: datetime) -> dict:
    """Una entrada de la fuente como la devuelve la API."""
    cert = entry.certificate
    return {
        "id": entry.id,
        "sha256": cert.sha256,
        "kind": entry.kind.value,
        "trusted": entry.trusted,
        "enabled": entry.enabled,
        "origin": entry.origin.value,
        "notes": entry.notes,
        "subject": cert.subject,
        "issuer": cert.issuer,
        "not_before": cert.not_before.isoformat(),
        "not_after": cert.not_after.isoformat(),
        "validity_status": cert.validity_status(now).value,
        "created_at": entry.created_at.isoformat(),
        "updated_at": entry.updated_at.isoformat(),
        "der_b64": base64.b64encode(cert.der).decode(),
    }


def _not_found(cert_id: int) -> HTTPException:
    return HTTPException(404, f"No hay un certificado con id {cert_id} en la fuente")


@router.get("/certificates")
def list_certificates(
    source: CertificateSourceDep, clock: ClockDep, kind: Literal["root", "intermediate"] | None = None
) -> dict:
    """Raíces e intermedios de la fuente, con un resumen de lo que usa el validador."""
    summary = source.summary()
    now = clock.now()
    return {
        "summary": {
            "total": summary.total,
            "trusted_roots": summary.trusted_roots,
            "intermediates": summary.intermediates,
            "disabled": summary.disabled,
        },
        "certificates": [present(e, now) for e in source.list(CaKind(kind) if kind else None)],
    }


@router.post("/certificates", status_code=201)
async def add_certificates(
    source: CertificateSourceDep,
    clock: ClockDep,
    crt: UploadFile | None = File(None, description="Archivo .crt/.cer/.pem/.p7c: DER, PEM o PKCS#7."),
    b64: str | None = Form(None, description="Alternativa al archivo: el base64 de un DER, o un PEM."),
    trusted: bool = Form(False, description="Si es una raíz, si queda como ancla de confianza. Un intermedio nunca lo es."),
    notes: str = Form(""),
    origin: Literal["manual", "pdf"] = Form("manual", description="De dónde salió: cargado a mano o desde un PDF."),
) -> dict:
    """Agrega una CA (o todas las de un PKCS#7). Rechaza lo que no sea CA; si ya estaban todas, 409."""
    if (crt is None) == (b64 is None):
        raise HTTPException(422, "Mandá un archivo `crt` o un `b64`, uno solo de los dos")
    data = await crt.read() if crt is not None else b64.encode()
    try:
        # Bloquea (SQLite, lock y re-parseo de la fuente): fuera del event loop.
        result = await run_in_threadpool(source.add, data, trusted=trusted, notes=notes, origin=Origin(origin))
    except DuplicateCertificate as e:
        raise HTTPException(409, f"Ya está en la fuente (id {', '.join(map(str, e.args[0]))})") from None
    now = clock.now()
    return {
        "added": [present(e, now) for e in result.added],
        "already_present": [present(e, now) for e in result.already_present],
    }


@router.post("/certificates/seed")
def restore_seed(source: CertificateSourceDep, clock: ClockDep) -> dict:
    """Vuelve a agregar los certificados de la carga inicial que se hayan borrado."""
    now = clock.now()
    return {"added": [present(e, now) for e in source.restore_seed()]}


@router.get("/certificates/{cert_id}")
def get_certificate(source: CertificateSourceDep, clock: ClockDep, cert_id: int) -> dict:
    try:
        return present(source.get(cert_id), clock.now())
    except CertificateNotFound:
        raise _not_found(cert_id) from None


@router.patch("/certificates/{cert_id}")
def update_certificate(source: CertificateSourceDep, clock: ClockDep, cert_id: int, changes: CertificateUpdate) -> dict:
    """Habilita o deshabilita, marca una raíz como confiable o no, o cambia las notas."""
    try:
        return present(source.update(cert_id, EntryChanges(**changes.model_dump())), clock.now())
    except CertificateNotFound:
        raise _not_found(cert_id) from None


@router.delete("/certificates/{cert_id}", status_code=204)
def delete_certificate(source: CertificateSourceDep, cert_id: int) -> Response:
    try:
        source.delete(cert_id)
    except CertificateNotFound:
        raise _not_found(cert_id) from None
    return Response(status_code=204)
