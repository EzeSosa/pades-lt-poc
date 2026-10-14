"""Tests de POST /sign: entradas inválidas, PDFs cifrados, nombres de campo y de descarga.

Firman contra `pki_server` (la app escuchando en un puerto real): /sign pide el sello de
tiempo a la TSA de la propia app por HTTP.
"""

from io import BytesIO

import pytest
import requests
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import copy_into_new_writer
from pyhanko.sign import fields

from conftest import load_signer, sign
from pades_lt_poc.routers.signing import content_disposition
from pades_lt_poc.services.signing import _free_field_name


def post_sign(base_url: str, pdf: bytes, filename: str = "doc.pdf") -> requests.Response:
    return requests.post(f"{base_url}/sign", files={"pdf": (filename, pdf, "application/pdf")}, timeout=60)


def encrypted(pdf: bytes) -> bytes:
    w = copy_into_new_writer(PdfFileReader(BytesIO(pdf)))
    w.encrypt("propietario", "")  # abre sin clave, pero está cifrado (AES-256)
    out = BytesIO()
    w.write(out)
    return out.getvalue()


def field_names(pdf: bytes) -> list[str]:
    return [s.field_name for s in PdfFileReader(BytesIO(pdf)).embedded_signatures]


# --------------------------------------------------------------------------- entradas
@pytest.mark.parametrize("data", [b"", b"\x89PNG\r\n\x1a\n", b"%PDF-1.7\n1 0 obj\n<<"], ids=["vacio", "png", "truncado"])
def test_invalid_pdf_is_422(pki_server, data):
    r = post_sign(pki_server, data)
    assert r.status_code == 422
    assert "No es un PDF válido" in r.json()["detail"]


def test_encrypted_pdf_is_rejected_and_signer_keeps_working(pki_server, pdf):
    """Un PDF cifrado dejaba al Signer compartido a medio configurar: después no firmaba nada."""
    r = post_sign(pki_server, encrypted(pdf))
    assert r.status_code == 422
    assert "protegido" in r.json()["detail"]
    assert post_sign(pki_server, pdf).status_code == 200


# --------------------------------------------------------------------------- nombre de campo
def test_cosign_when_existing_signature_field_is_firma2(pki_server, pdf):
    """Una sola firma, en un campo `Firma2`: contar firmas elegía `Firma2` otra vez."""
    signed = sign(pdf, load_signer())  # campo Firma1
    w = IncrementalPdfFileWriter(BytesIO(signed))
    fields.append_signature_field(w, fields.SigFieldSpec("Firma2"))
    out = BytesIO()
    w.write(out)
    renamed = sign(out.getvalue(), load_signer())  # firma el campo vacío Firma2

    r = post_sign(pki_server, renamed)
    assert r.status_code == 200, r.text
    assert field_names(r.content) == ["Firma1", "Firma2", "Firma3"]


def test_free_field_name_skips_non_signature_fields():
    pdf = (
        b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [3 0 R 4 0 R] >> >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
        b"3 0 obj\n<< /FT /Tx /T (Firma1) >>\nendobj\n"
        b"4 0 obj\n<< /T (Grupo) /Kids [5 0 R] >>\nendobj\n"
        b"5 0 obj\n<< /FT /Sig /T (Firma2) /Parent 4 0 R >>\nendobj\n"
    )
    offsets = [pdf.index(b"%d 0 obj" % i) for i in range(1, 6)]
    xref = len(pdf)
    pdf += b"xref\n0 6\n0000000000 65535 f \n" + b"".join(b"%010d 00000 n \n" % o for o in offsets)
    pdf += b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % xref
    # `Firma1` es de texto; `Grupo.Firma2` no choca con `Firma2`.
    assert _free_field_name(PdfFileReader(BytesIO(pdf))) == "Firma2"


# --------------------------------------------------------------------------- nombre de descarga
def test_non_ascii_filename(pki_server, pdf):
    r = post_sign(pki_server, pdf, "Resolución Nº 123 – año 2026 ✓.pdf")
    assert r.status_code == 200
    assert r.headers["content-disposition"] == (
        'attachment; filename="Resoluci_n N_ 123 _ a_o 2026 _-pades-lt.pdf"; '
        "filename*=UTF-8''Resoluci%C3%B3n%20N%C2%BA%20123%20%E2%80%93%20a%C3%B1o%202026%20%E2%9C%93-pades-lt.pdf"
    )


@pytest.mark.parametrize(
    ("uploaded", "fallback"),
    [
        ("Nota.PDF", "Nota-pades-lt.pdf"),
        ('a "b".pdf', "a _b_-pades-lt.pdf"),
        (None, "documento-pades-lt.pdf"),
        (".pdf", "documento-pades-lt.pdf"),
    ],
)
def test_content_disposition(uploaded, fallback):
    assert content_disposition(uploaded).startswith(f'attachment; filename="{fallback}"; filename*=UTF-8\'\'')
