"""Reglas de la firma (domain/signing.py) y el caso de uso `SignPdf` con un motor falso. Sin pyHanko ni PKI."""

import asyncio

import pytest

from pades_lt_poc.application.use_cases.sign_pdf import SignPdf
from pades_lt_poc.domain.errors import UnprocessablePdf
from pades_lt_poc.domain.signing import ENCRYPTED, SignatureSpec, SignRequest, check_signable, free_field_name, spec_for


# --------------------------------------------------------------------------- S-02
@pytest.mark.parametrize(
    ("taken", "name"),
    [
        (set(), "Firma1"),
        ({"Firma1"}, "Firma2"),
        ({"Firma2"}, "Firma1"),  # contar firmas daría Firma2
        ({"Firma1", "Firma2", "Firma4"}, "Firma3"),  # el menor libre
        ({"Grupo.Firma1", "firma1", "Firma 1"}, "Firma1"),  # nombre completo y exacto
    ],
)
def test_s02_first_free_field_name(taken, name):
    assert free_field_name(taken) == name


# --------------------------------------------------------------------------- S-01
def test_s01_encrypted_is_rejected():
    check_signable(encrypted=False)
    with pytest.raises(UnprocessablePdf, match="protegido con contraseña"):
        check_signable(encrypted=True)


# --------------------------------------------------------------------------- S-04
def test_s04_fixed_profile():
    spec = spec_for(SignRequest("Conformidad", "Córdoba", lta=True), {"Firma1"})
    assert spec == SignatureSpec("Firma2", "Conformidad", "Córdoba", True)
    assert (spec.digest_algorithm, spec.subfilter) == ("sha256", "ETSI.CAdES.detached")


# --------------------------------------------------------------------------- caso de uso
class FakeDocument:
    def __init__(self, encrypted=False, names=frozenset()):
        self.encrypted = encrypted
        self._names = names
        self.read_names = False
        self.signed_with = None

    @property
    def field_names(self):
        self.read_names = True
        return self._names

    async def sign(self, spec, tsa_url):
        self.signed_with = (spec, tsa_url)
        return b"firmado"


class FakeEngine:
    def __init__(self, document):
        self.document = document

    def open(self, pdf):
        return self.document


def test_sign_pdf_chooses_the_field_and_passes_the_tsa():
    doc = FakeDocument(names=frozenset({"Firma1"}))
    out = asyncio.run(SignPdf(FakeEngine(doc)).sign(b"pdf", SignRequest("r", "l", False), "http://tsa"))
    assert out == b"firmado"
    assert doc.signed_with == (SignatureSpec("Firma2", "r", "l", False), "http://tsa")


def test_sign_pdf_rejects_encrypted_before_reading_the_form():
    """En un PDF cifrado leer el formulario puede fallar: el rechazo va antes."""
    doc = FakeDocument(encrypted=True)
    with pytest.raises(UnprocessablePdf) as e:
        asyncio.run(SignPdf(FakeEngine(doc)).sign(b"pdf", SignRequest("r", "l", False), "http://tsa"))
    assert str(e.value) == ENCRYPTED
    assert not doc.read_names and doc.signed_with is None
