"""Caso de uso `AnalyzeDocument` con un inspector falso: lee los hechos y los interpreta con el dominio."""

import pytest

from fakes import FixedPdfInspector
from pades_lt_poc.application.use_cases.analyze_document import AnalyzeDocument
from pades_lt_poc.domain.document import DocumentFacts, Severity
from pades_lt_poc.domain.errors import UnprocessablePdf


def test_analyzes_the_facts_of_the_inspector():
    inspector = FixedPdfInspector(DocumentFacts(None, None, None, None, (), (), unreadable=(("todo", "roto"),)))
    analysis = AnalyzeDocument(inspector).analyze(b"pdf")
    assert inspector.inspected == [b"pdf"]
    assert [(f.code, f.severity) for f in analysis.findings] == [("unreadable", Severity.WARNING)]


def test_d03_a_pdf_that_does_not_open_is_rejected():
    inspector = FixedPdfInspector(error=UnprocessablePdf("El PDF está cifrado con contraseña de apertura"))
    with pytest.raises(UnprocessablePdf, match="contraseña"):
        AnalyzeDocument(inspector).analyze(b"pdf")
