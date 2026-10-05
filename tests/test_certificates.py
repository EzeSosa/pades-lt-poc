"""Tests de POST /certificates."""

import base64
import datetime as dt
from collections import Counter
from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from conftest import doc_timestamp, load_signer, sign
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID
from pyhanko.keys import (
    load_cert_from_pemder,
    load_certs_from_pemder_data,
    load_private_key_from_pemder_data,
)
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.validation import DocumentSecurityStore
from pyhanko.sign.validation.generic_cms import extract_tst_data_iter
from pyhanko_certvalidator.registry import SimpleCertificateStore

from pades_lt_poc import pki
from pades_lt_poc.services import certificates as certificates_service
from pades_lt_poc.services.certificates import _extract_chain, _issued_by, _parse_certs
from pades_lt_poc.services.verification import TRUST_DIR

DATA = Path(__file__).parent / "data"


def extract(client, pdf: bytes, **form) -> list[dict]:
    r = client.post("/certificates", files={"pdf": ("doc.pdf", pdf, "application/pdf")}, data=form)
    assert r.status_code == 200, r.text
    return r.json()["signatures"]


def der_b64(name: str) -> str:
    """El certificado de la PKI de prueba tal como lo debería devolver el endpoint."""
    return base64.b64encode(pki.entity(name).cert().public_bytes(serialization.Encoding.DER)).decode()


def assert_chain(entry: dict, names: list[str], sources: list[str] | None = None) -> None:
    """La cadena es exactamente `names` (hoja -> raíz) y cada cert está bien clasificado."""
    assert entry["crypto_valid"] is True
    assert entry["chain_complete"] is (names[-1] == pki.ROOT)
    certs = entry["certificates"]
    assert [c["der_b64"] for c in certs] == [der_b64(n) for n in names]
    for i, (cert, name) in enumerate(zip(certs, names)):
        expected_type = "end_entity" if i == 0 else "root" if name == pki.ROOT else "intermediate"
        assert cert["type"] == expected_type
        assert cert["self_signed"] is (name == pki.ROOT)
        assert cert["subject"] == pki.entity(name).cert().subject.rfc4514_string()
    if sources is not None:
        assert [c["source"] for c in certs] == sources


def tamper(data: bytes, old: bytes, new: bytes) -> bytes:
    i = data.index(old)
    return data[:i] + new + data[i + len(old) :]


# --------------------------------------------------------------------------- casos válidos
def test_signature_returns_signer_and_tsa_chains(client, pdf, timestamper):
    [entry] = extract(client, sign(pdf, load_signer(), timestamper))

    assert entry["field"] == "Firma1"
    assert entry["type"] == "Signature"
    assert_chain(entry, [pki.SIGNER, pki.INTERMEDIATE, pki.ROOT], ["cms", "cms", "cms"])

    ts = entry["signature_timestamp"]
    assert_chain(ts, [pki.TSA, pki.INTERMEDIATE, pki.ROOT])
    sealed_at = dt.datetime.fromisoformat(ts["time"])
    assert abs(dt.datetime.now(dt.timezone.utc) - sealed_at) < dt.timedelta(minutes=5)


def test_certificate_fields(client, pdf):
    [entry] = extract(client, sign(pdf, load_signer()))
    leaf = entry["certificates"][0]
    cert = pki.entity(pki.SIGNER).cert()

    assert x509.load_der_x509_certificate(base64.b64decode(leaf["der_b64"])) == cert
    assert leaf["issuer"] == cert.issuer.rfc4514_string()
    assert leaf["serial_number"] == format(cert.serial_number, "x")
    assert leaf["not_before"] == cert.not_valid_before_utc.isoformat()
    assert leaf["not_after"] == cert.not_valid_after_utc.isoformat()
    assert leaf["sha256_fingerprint"] == cert.fingerprint(hashes.SHA256()).hex()


def test_cosignature_and_document_timestamp(client, pdf, timestamper):
    signed = sign(sign(pdf, load_signer(), timestamper), load_signer(), timestamper)
    firma1, firma2, doc_ts = extract(client, doc_timestamp(signed, timestamper))

    for entry, field in ((firma1, "Firma1"), (firma2, "Firma2")):
        assert entry["field"] == field
        assert_chain(entry, [pki.SIGNER, pki.INTERMEDIATE, pki.ROOT])
        assert_chain(entry["signature_timestamp"], [pki.TSA, pki.INTERMEDIATE, pki.ROOT])

    # El DocTimeStamp lo firma la TSA, y no lleva un sello propio.
    assert doc_ts["type"] == "DocTimeStamp"
    assert_chain(doc_ts, [pki.TSA, pki.INTERMEDIATE, pki.ROOT])
    assert "signature_timestamp" not in doc_ts


def test_signature_without_timestamp(client, pdf):
    [entry] = extract(client, sign(pdf, load_signer()))
    assert_chain(entry, [pki.SIGNER, pki.INTERMEDIATE, pki.ROOT])
    assert entry["signature_timestamp"] is None


def test_self_signed_signer_from_untrusted_pki(client, pdf):
    """No exige confianza: un firmante autofirmado ajeno a la PKI de la app también sale."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Firmante Autofirmado")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    [signing_cert] = load_certs_from_pemder_data(cert_pem)
    signer = signers.SimpleSigner(
        signing_cert=signing_cert,
        signing_key=load_private_key_from_pemder_data(key_pem, passphrase=None),
        cert_registry=SimpleCertificateStore(),
    )

    [entry] = extract(client, sign(pdf, signer))

    assert entry["crypto_valid"] is True
    assert entry["chain_complete"] is True
    [only] = entry["certificates"]
    assert only["type"] == "end_entity"  # el que firmó, aunque sea autofirmado
    assert only["self_signed"] is True
    assert only["subject"] == "CN=Firmante Autofirmado"


def test_incomplete_chain_without_fetching(client, pdf):
    """Sin la intermedia ni la raíz en el PDF y sin AIA, la cadena queda en la hoja."""
    [entry] = extract(client, sign(pdf, load_signer(chain=())), fetch_missing="false")
    assert_chain(entry, [pki.SIGNER])
    assert entry["chain_complete"] is False
    assert "aia_errors" not in entry


def test_incomplete_chain_when_aia_unreachable(client, pdf):
    [entry] = extract(client, sign(pdf, load_signer(chain=())))
    assert_chain(entry, [pki.SIGNER])
    assert entry["chain_complete"] is False
    [error] = entry["aia_errors"]
    assert pki.cert_url(pki.INTERMEDIATE) in error


@pytest.fixture
def aia_via_app(client, monkeypatch) -> Counter:
    """Las URLs AIA de la PKI de prueba se sirven con la propia app; cuenta las descargas."""
    calls: Counter = Counter()

    def get(url: str) -> bytes:
        calls[url] += 1
        r = client.get(urlsplit(url).path)
        r.raise_for_status()
        return r.content

    monkeypatch.setattr(certificates_service, "_http_get", get)
    return calls


def test_chain_completed_from_aia(client, pdf, aia_via_app):
    """Si el PDF no trae la cadena, se descarga desde AIA caIssuers, eslabón por eslabón."""
    signed = sign(sign(pdf, load_signer(chain=())), load_signer(chain=()))
    for entry in extract(client, signed):
        assert_chain(entry, [pki.SIGNER, pki.INTERMEDIATE, pki.ROOT], ["cms", "aia", "aia"])
        assert "aia_errors" not in entry
    # Con caché por request: cada URL se descarga una sola vez para las dos firmas.
    assert aia_via_app == {pki.cert_url(pki.INTERMEDIATE): 1, pki.cert_url(pki.ROOT): 1}


def test_pdf_certs_take_precedence_over_aia(client, pdf, aia_via_app):
    [entry] = extract(client, sign(pdf, load_signer()))
    assert_chain(entry, [pki.SIGNER, pki.INTERMEDIATE, pki.ROOT], ["cms", "cms", "cms"])
    assert not aia_via_app


def test_chain_completed_from_dss(client, pdf):
    """Si el CMS no trae la cadena pero el DSS sí, se completa con el DSS."""
    signed = BytesIO(sign(pdf, load_signer(chain=())))
    sig = PdfFileReader(signed).embedded_signatures[0]
    ca_certs = [load_cert_from_pemder(str(pki.entity(n).cert_path)) for n in (pki.INTERMEDIATE, pki.ROOT)]
    DocumentSecurityStore.add_dss(signed, sig.pkcs7_content, certs=ca_certs)

    [entry] = extract(client, signed.getvalue())
    assert_chain(entry, [pki.SIGNER, pki.INTERMEDIATE, pki.ROOT], ["cms", "dss", "dss"])


# --------------------------------------------------------------------------- piezas sueltas
def test_parse_certs_accepts_der_pem_and_pkcs7(client):  # client: genera la PKI
    certs = [pki.entity(n).cert() for n in (pki.INTERMEDIATE, pki.ROOT)]
    Enc = serialization.Encoding
    assert _parse_certs(certs[0].public_bytes(Enc.DER)) == certs[:1]
    assert _parse_certs(certs[0].public_bytes(Enc.PEM)) == certs[:1]
    assert set(_parse_certs(pkcs7.serialize_certificates(certs, Enc.DER))) == set(certs)  # SET: sin orden
    assert set(_parse_certs(pkcs7.serialize_certificates(certs, Enc.PEM))) == set(certs)  # SET: sin orden
    with pytest.raises(ValueError):
        _parse_certs(b"<html>404</html>")


def test_issued_by_accepts_sha1():
    """cryptography no verifica SHA-1, pero PKIs reales lo siguen usando: la AC Raíz
    de Argentina firma con SHA-1 a la CA de la ONTI (emisora de los certs de CiDi)."""
    root = x509.load_der_x509_certificate((TRUST_DIR / "ac-raiz-argentina-2007.der").read_bytes())
    onti = x509.load_der_x509_certificate((DATA / "ac-onti-firma-digital.der").read_bytes())
    assert onti.signature_hash_algorithm.name == "sha1"

    assert _issued_by(root, root)
    assert _issued_by(onti, root)
    assert not _issued_by(root, onti)
    assert not _issued_by(onti, onti)


# --------------------------------------------------------------------------- casos inválidos
def test_tampered_document(client, pdf, timestamper):
    signed = sign(pdf, load_signer(), timestamper)
    [entry] = extract(client, tamper(signed, b"Hola PAdES", b"Chau PAdES"))

    assert entry["crypto_valid"] is False
    assert entry["intact"] is False
    assert entry["error"] == "el documento fue alterado"
    assert entry["certificates"] is None
    assert entry["signature_timestamp"] is None


def test_tampered_signature_value(client, pdf):
    signed = sign(pdf, load_signer())
    signature = PdfFileReader(BytesIO(signed)).embedded_signatures[0].signer_info["signature"].native
    hex_sig = next(h for h in (signature.hex().encode(), signature.hex().upper().encode()) if h in signed)
    i = signed.index(hex_sig) + 20
    flipped = b"0" if signed[i : i + 1] != b"0" else b"1"
    [entry] = extract(client, signed[:i] + flipped + signed[i + 1 :])

    assert entry["crypto_valid"] is False
    assert entry["intact"] is True  # el ByteRange no cambió
    assert entry["valid"] is False
    assert entry["error"] == "firma inválida"
    assert entry["certificates"] is None


def test_timestamp_not_matching_signature(pdf, timestamper):
    """Un sello cuyo messageImprint no coincide con el valor de la firma se rechaza."""
    signed = sign(pdf, load_signer(), timestamper)
    sig = PdfFileReader(BytesIO(signed)).embedded_signatures[0]
    token = next(extract_tst_data_iter(sig.signer_info, signed=False))

    out = _extract_chain(token, lambda md: b"\0" * 32, [], "el sello no corresponde a esta firma")

    assert out["crypto_valid"] is False
    assert out["intact"] is False
    assert out["valid"] is True  # la firma de la TSA sobre el TSTInfo sigue siendo válida
    assert out["error"] == "el sello no corresponde a esta firma"
    assert out["certificates"] is None


def test_pdf_without_signatures(client, pdf):
    r = client.post("/certificates", files={"pdf": ("doc.pdf", pdf, "application/pdf")})
    assert r.status_code == 422
    assert r.json()["detail"] == "El PDF no tiene firmas"
