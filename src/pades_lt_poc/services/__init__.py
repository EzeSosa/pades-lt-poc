"""Lógica de cada operación que todavía no se migró a casos de uso y adaptadores, sin dependencias de HTTP.

Los errores de negocio están en `domain.errors`.
"""

from io import BytesIO

from pyhanko.pdf_utils.reader import PdfFileReader

from ..domain.errors import UnprocessablePdf


def read_signed_pdf(data: bytes) -> PdfFileReader:
    reader = PdfFileReader(BytesIO(data), strict=False)
    if not reader.embedded_signatures:
        raise UnprocessablePdf("El PDF no tiene firmas")
    return reader
