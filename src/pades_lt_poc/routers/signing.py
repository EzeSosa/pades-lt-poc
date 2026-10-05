from fastapi import APIRouter, File, Form, Request, Response, UploadFile

from ..dependencies import SignerDep

router = APIRouter(tags=["Firma"])


@router.post("/sign")
async def sign(
    request: Request,
    signer: SignerDep,
    pdf: UploadFile = File(...),
    reason: str = Form("Conformidad"),
    location: str = Form("Buenos Aires, AR"),
    lta: bool = Form(False, description="Agregar además un Document TimeStamp (B-LTA)"),
) -> Response:
    """Sube un PDF y devuelve el PDF firmado PAdES B-LT (o B-LTA)."""
    # La TSA es la de esta misma app: la firma la consume por HTTP como si fuera externa.
    tsa_url = f"{str(request.base_url).rstrip('/')}/tsa"
    signed = await signer.sign(await pdf.read(), reason=reason, location=location, lta=lta, tsa_url=tsa_url)

    name = (pdf.filename or "documento.pdf").removesuffix(".pdf")
    return Response(
        signed,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{name}-pades-lt.pdf"'},
    )
