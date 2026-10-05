from fastapi import APIRouter, File, Form, UploadFile
from fastapi.concurrency import run_in_threadpool

from ..dependencies import CertificateExtractorDep

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
