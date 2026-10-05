"""Lógica de cada operación, sin dependencias de HTTP. Los routers sólo traducen request/response."""

from io import BytesIO

from pyhanko.pdf_utils.reader import PdfFileReader


class UnprocessablePdf(Exception):
    """El PDF no se puede procesar (sin firmas, no se pudo firmar, etc.). La API lo devuelve como 422."""


def read_signed_pdf(data: bytes) -> PdfFileReader:
    reader = PdfFileReader(BytesIO(data), strict=False)
    if not reader.embedded_signatures:
        raise UnprocessablePdf("El PDF no tiene firmas")
    return reader
