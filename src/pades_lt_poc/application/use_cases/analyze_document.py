"""Caso de uso: el análisis de un PDF más allá de sus firmas (protección, formulario, revisiones, contenido activo y estructura)."""

from __future__ import annotations

from ...domain.document import DocumentAnalysis, analyze
from ..ports import PdfInspector


class AnalyzeDocument:
    """Lee los hechos del PDF con el `PdfInspector` y los interpreta con el dominio (reglas D-01 a D-10).

    No valida firmas: sirve para cualquier PDF, firmado o no. Un PDF que no se puede abrir (dañado o
    con contraseña) es un `UnprocessablePdf` (D-03); una sección que no se puede leer, un hallazgo (D-10).
    """

    def __init__(self, inspector: PdfInspector) -> None:
        self.inspector = inspector

    def analyze(self, pdf: bytes) -> DocumentAnalysis:
        return analyze(self.inspector.inspect(pdf))
