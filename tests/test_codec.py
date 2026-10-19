"""`CryptographyCertificateCodec`: el adaptador del puerto `CertificateCodec` sobre `cryptography`."""

import base64

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from conftest import pki
from pades_lt_poc.adapters.outbound.crypto.codec import CryptographyCertificateCodec, issued_by, parse_certs
from pades_lt_poc.domain.certificates import CaKind
from pades_lt_poc.domain.errors import UnprocessableCertificate
from pades_lt_poc.adapters.outbound.seed_catalog import SEED_DIR

Enc = serialization.Encoding
codec = CryptographyCertificateCodec()
AC_RAIZ_2007 = (SEED_DIR / "ac-raiz-argentina-2007.der").read_bytes()
ONTI = (SEED_DIR / "ac-onti-firma-digital.der").read_bytes()


@pytest.fixture
def poc_certs(client) -> list[x509.Certificate]:  # client: genera la PKI
    return [pki.entity(n).cert() for n in (pki.INTERMEDIATE, pki.ROOT)]


# --------------------------------------------------------------------------- parse
def test_parse_accepts_every_format(poc_certs):
    intermediate = poc_certs[0]
    der = intermediate.public_bytes(Enc.DER)
    for data in (
        der,
        intermediate.public_bytes(Enc.PEM),
        base64.b64encode(der),
        b"  " + base64.encodebytes(der) + b"\n",  # base64 pegado, con saltos de línea
    ):
        [parsed] = codec.parse(data)
        assert parsed.der == der

    bundle = codec.parse(pkcs7.serialize_certificates(poc_certs, Enc.DER))
    assert {c.der for c in bundle} == {c.public_bytes(Enc.DER) for c in poc_certs}  # SET: sin orden


@pytest.mark.parametrize("data", [b"", b"<html>404</html>", b"no es un certificado", base64.b64encode(b"basura")])
def test_parse_rejects_garbage(data):
    with pytest.raises(UnprocessableCertificate):
        codec.parse(data)


def test_parsed_fields(poc_certs):
    intermediate, root = poc_certs
    [c] = codec.parse(intermediate.public_bytes(Enc.DER))
    assert c.sha256 == intermediate.fingerprint(hashes.SHA256()).hex()
    assert c.sha1 == intermediate.fingerprint(hashes.SHA1()).hex()
    assert c.subject == "CN=PoC Intermediate CA,O=PoC PAdES,C=AR"
    assert c.issuer == root.subject.rfc4514_string()
    assert c.serial_number == intermediate.serial_number
    assert (c.not_before, c.not_after) == (intermediate.not_valid_before_utc, intermediate.not_valid_after_utc)
    assert c.not_after.tzinfo is not None
    assert (c.is_ca, c.self_signed, c.ca_kind) == (True, False, CaKind.INTERMEDIATE)

    [r] = codec.parse(root.public_bytes(Enc.DER))
    assert (r.is_ca, r.self_signed, r.ca_kind) == (True, True, CaKind.ROOT)

    [leaf] = codec.parse(pki.entity(pki.SIGNER).cert().public_bytes(Enc.DER))
    assert (leaf.is_ca, leaf.self_signed, leaf.ca_kind) == (False, False, None)


# --------------------------------------------------------------------------- issued_by
def test_issued_by_accepts_sha1():
    """cryptography no verifica SHA-1, pero PKIs reales lo siguen usando: la AC Raíz
    de Argentina firma con SHA-1 a la CA de la ONTI (emisora de los certs de CiDi)."""
    [root], [onti] = codec.parse(AC_RAIZ_2007), codec.parse(ONTI)
    assert x509.load_der_x509_certificate(ONTI).signature_hash_algorithm.name == "sha1"

    assert codec.issued_by(root, root)
    assert codec.issued_by(onti, root)
    assert not codec.issued_by(root, onti)
    assert not codec.issued_by(onti, onti)
    assert root.self_signed and not onti.self_signed


def test_issued_by_needs_the_signature_not_just_the_name(poc_certs):
    """Una CA con el mismo nombre pero otra clave no es el emisor."""
    intermediate, root = poc_certs
    impostor_key = pki.entity(pki.INTERMEDIATE).key()  # otra clave, mismo nombre que la raíz
    impostor = (
        x509.CertificateBuilder()
        .subject_name(root.subject)
        .issuer_name(root.subject)
        .public_key(impostor_key.public_key())
        .serial_number(1)
        .not_valid_before(root.not_valid_before_utc)
        .not_valid_after(root.not_valid_after_utc)
        .sign(impostor_key, hashes.SHA256())
    )
    assert issued_by(intermediate, root)
    assert not issued_by(intermediate, impostor)


# --------------------------------------------------------------------------- funciones x509 (servicios sin migrar)
def test_parse_certs_is_strict_about_base64(poc_certs):
    """`parse_certs` (lo publicado en AIA) no acepta base64: lanza ValueError, no un error de negocio."""
    der = poc_certs[0].public_bytes(Enc.DER)
    assert parse_certs(der) == poc_certs[:1]
    with pytest.raises(ValueError):
        parse_certs(base64.b64encode(der))
