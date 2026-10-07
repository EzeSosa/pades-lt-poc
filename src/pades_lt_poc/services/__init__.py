"""Lógica de cada operación, sin dependencias de HTTP. Los routers sólo traducen request/response."""

from io import BytesIO

from pyhanko.pdf_utils.reader import PdfFileReader


class UnprocessableInput(Exception):
    """La entrada no se puede procesar. La API lo devuelve como 422."""


class UnprocessablePdf(UnprocessableInput):
    """El PDF no se puede procesar (sin firmas, no se pudo firmar, etc.)."""


class UnprocessableCertificate(UnprocessableInput):
    """Lo recibido no es un certificado en un formato conocido."""


def read_signed_pdf(data: bytes) -> PdfFileReader:
    reader = PdfFileReader(BytesIO(data), strict=False)
    if not reader.embedded_signatures:
        raise UnprocessablePdf("El PDF no tiene firmas")
    return reader
