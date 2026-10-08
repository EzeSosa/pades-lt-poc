from typing import Literal

from fastapi import APIRouter, File, Form, HTTPException, Response, UploadFile
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

from ..dependencies import CertificateStoreDep
from ..services.store import CertificateNotFound, DuplicateCertificate

router = APIRouter(prefix="/store", tags=["Fuente de certificados"])


class CertificateUpdate(BaseModel):
    enabled: bool | None = None
    trusted: bool | None = None
    notes: str | None = None


def _not_found(cert_id: int) -> HTTPException:
    return HTTPException(404, f"No hay un certificado con id {cert_id} en la fuente")


@router.get("/certificates")
def list_certificates(store: CertificateStoreDep, kind: Literal["root", "intermediate"] | None = None) -> dict:
    """Raíces e intermedios de la fuente, con un resumen de lo que usa el validador."""
    certs = store.list()
    snapshot = store.snapshot()
    return {
        "summary": {
            "total": len(certs),
            "trusted_roots": len(snapshot.trusted_roots),
            "intermediates": len(snapshot.intermediates),
            "disabled": sum(not c["enabled"] for c in certs),
        },
        "certificates": [c for c in certs if kind is None or c["kind"] == kind],
    }


@router.post("/certificates", status_code=201)
async def add_certificates(
    store: CertificateStoreDep,
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
        # store.add bloquea (lock, SQLite y re-parseo de la fuente): fuera del event loop.
        return await run_in_threadpool(store.add, data, trusted=trusted, notes=notes, origin=origin)
    except DuplicateCertificate as e:
        raise HTTPException(409, f"Ya está en la fuente (id {', '.join(map(str, e.args[0]))})") from None


@router.post("/certificates/seed")
def restore_seed(store: CertificateStoreDep) -> dict:
    """Vuelve a agregar los certificados de la carga inicial que se hayan borrado."""
    return {"added": store.restore_seed()}


@router.get("/certificates/{cert_id}")
def get_certificate(store: CertificateStoreDep, cert_id: int) -> dict:
    try:
        return store.get(cert_id)
    except CertificateNotFound:
        raise _not_found(cert_id) from None


@router.patch("/certificates/{cert_id}")
def update_certificate(store: CertificateStoreDep, cert_id: int, changes: CertificateUpdate) -> dict:
    """Habilita o deshabilita, marca una raíz como confiable o no, o cambia las notas."""
    try:
        return store.update(cert_id, **changes.model_dump())
    except CertificateNotFound:
        raise _not_found(cert_id) from None


@router.delete("/certificates/{cert_id}", status_code=204)
def delete_certificate(store: CertificateStoreDep, cert_id: int) -> Response:
    try:
        store.delete(cert_id)
    except CertificateNotFound:
        raise _not_found(cert_id) from None
    return Response(status_code=204)
