"""Caso de uso: firmar un PDF en PAdES B-LT (o B-LTA)."""

from __future__ import annotations

from ...domain.signing import SignRequest, check_signable, spec_for
from ..ports import PdfSigningEngine


class SignPdf:
    """Firma con la identidad del motor y el sello de tiempo de la TSA indicada (reglas S-01 a S-04).

    Async: el motor pide el sello y la revocación de la cadena por HTTP.
    """

    def __init__(self, engine: PdfSigningEngine) -> None:
        self.engine = engine

    async def sign(self, pdf: bytes, request: SignRequest, tsa_url: str) -> bytes:
        """El PDF firmado. Lanza `UnprocessablePdf` si no se puede leer, está cifrado o no se pudo firmar."""
        document = self.engine.open(pdf)
        check_signable(document.encrypted)  # S-01
        return await document.sign(spec_for(request, document.field_names), tsa_url)  # S-02, S-04
