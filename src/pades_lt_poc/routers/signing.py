import re
from urllib.parse import quote

from fastapi import APIRouter, File, Form, Request, Response, UploadFile

from ..dependencies import SignPdfDep
from ..domain.signing import SignRequest

router = APIRouter(tags=["Firma"])


@router.post("/sign")
async def sign(
    request: Request,
    sign_pdf: SignPdfDep,
    pdf: UploadFile = File(...),
    reason: str = Form("Conformidad"),
    location: str = Form("Buenos Aires, AR"),
    lta: bool = Form(False, description="Agregar además un Document TimeStamp (B-LTA)"),
) -> Response:
    """Sube un PDF y devuelve el PDF firmado PAdES B-LT (o B-LTA)."""
    # La TSA es la de esta misma app: la firma la consume por HTTP como si fuera externa.
    tsa_url = f"{str(request.base_url).rstrip('/')}/tsa"
    signed = await sign_pdf.sign(await pdf.read(), SignRequest(reason, location, lta), tsa_url)
    return Response(
        signed,
        media_type="application/pdf",
        headers={"Content-Disposition": content_disposition(pdf.filename)},
    )


def content_disposition(uploaded: str | None) -> str:
    """`attachment` con el nombre subido más `-pades-lt.pdf` (RFC 6266).

    Los headers HTTP son Latin-1: el nombre completo va en `filename*` (UTF-8, codificado) y
    `filename` lleva una versión ASCII para clientes viejos, sin comillas ni barras.
    """
    stem = re.sub(r"\.pdf$", "", uploaded or "", flags=re.IGNORECASE) or "documento"
    name = f"{stem}-pades-lt.pdf"
    fallback = re.sub(r'[^\x20-\x7e]|["\\]', "_", name)
    return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(name, safe='')}"
