from fastapi import APIRouter, File, Form, UploadFile

from ..dependencies import VerifierDep
from ..services.verification import DiffPolicyName, RevocationMode, ValidationTime

router = APIRouter(tags=["Verificación"])


@router.post("/verify")
async def verify(
    verifier: VerifierDep,
    pdf: UploadFile = File(...),
    validation_time: ValidationTime = Form(
        "now",
        description=(
            "now: valida a la hora actual (por defecto). claimed_signing_time: valida cada firma "
            "a la hora que ella misma declara; sirve para firmas sin sello de tiempo cuya "
            "revocación embebida ya venció, pero esa hora no está probada."
        ),
    ),
    diff_policy: DiffPolicyName = Form(
        "default",
        description=(
            "Análisis de las modificaciones posteriores a cada firma. default: el de pyHanko. "
            "allow_unallocated_free_entries: además acepta entradas libres de objetos que nunca existieron."
        ),
    ),
    revocation: RevocationMode = Form(
        "offline",
        description=(
            "offline: sólo la revocación que trae el PDF (por defecto). online: además descarga CRL, "
            "OCSP y emisores faltantes de las URLs de cada certificado; sólo con validation_time=now, "
            "y el nivel alcanzado no pasa de B-T."
        ),
    ),
) -> dict:
    """Valida las firmas con el material del PDF y la fuente de certificados; con conexión, si se pide."""
    return await verifier.verify(await pdf.read(), validation_time, diff_policy, revocation)
