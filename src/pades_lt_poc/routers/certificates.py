from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool

from ..dependencies import CertificateExtractorDep, CertificateInspectorDep

router = APIRouter(tags=["Certificados"])


@router.post("/certificates")
async def certificates(
    extractor: CertificateExtractorDep, pdf: UploadFile = File(...), fetch_missing: bool = Form(True)
) -> dict:
    """Cadena de certificados (hoja -> raíz) de cada firma criptográficamente válida.

    No exige confianza: la cadena se arma con los certificados que trae el propio
    PDF (CMS de la firma + DSS), verificando que cada uno haya firmado al anterior.
    Si falta algún emisor y `fetch_missing` es true, se descarga desde la URL AIA
    caIssuers del certificado (cada cert indica su origen en `source`).
    """
    data = await pdf.read()
    # Las descargas AIA son bloqueantes: fuera del event loop.
    return await run_in_threadpool(extractor.extract, data, fetch_missing)


@router.post("/certificates/inspect")
async def inspect_certificate(
    inspector: CertificateInspectorDep,
    crt: UploadFile | None = File(None, description="Archivo .crt/.cer/.pem/.p7c: DER, PEM o PKCS#7."),
    b64: str | None = Form(None, description="Alternativa al archivo: el base64 de un DER (p. ej. un der_b64)."),
) -> dict:
    """Detalle de cada certificado recibido: sujeto, emisor, vigencia, clave, huellas y extensiones.

    Un PKCS#7 puede traer varios certificados: se devuelven todos, en el orden en que vienen.
    """
    if (crt is None) == (b64 is None):
        raise HTTPException(422, "Mandá un archivo `crt` o un `b64`, uno solo de los dos")
    data = await crt.read() if crt is not None else b64.encode()
    return inspector.inspect(data)
