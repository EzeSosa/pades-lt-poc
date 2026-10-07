"""Tests de POST /certificates/inspect."""

import base64
import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from pades_lt_poc import pki
from pades_lt_poc.services.store import SEED_DIR

Enc = serialization.Encoding


def inspect(client, crt: bytes | None = None, b64: str | None = None) -> list[dict]:
    files = {"crt": ("cert.crt", crt, "application/pkix-cert")} if crt is not None else None
    data = {"b64": b64} if b64 is not None else None
    r = client.post("/certificates/inspect", files=files, data=data)
    assert r.status_code == 200, r.text
    return r.json()["certificates"]


def extension(cert: dict, name: str) -> dict:
    return next(e for e in cert["extensions"] if e["name"] == name)


def test_signer_certificate(client):
    cert = pki.entity(pki.SIGNER).cert()
    [out] = inspect(client, crt=cert.public_bytes(Enc.DER))

    assert {"name": "commonName", "oid": "2.5.4.3", "value": "Firmante de Prueba"} in out["subject"]
    assert out["subject_rfc4514"] == cert.subject.rfc4514_string()
    assert out["issuer_rfc4514"] == pki.entity(pki.INTERMEDIATE).cert().subject.rfc4514_string()
    assert out["serial_number"] == format(cert.serial_number, "x")
    assert out["version"] == 3
    assert out["is_ca"] is False
    assert out["self_signed"] is False
    assert out["validity"]["status"] == "valid"
    assert out["validity"]["days_left"] >= 0
    assert out["fingerprints"]["sha256"] == cert.fingerprint(hashes.SHA256()).hex()
    assert base64.b64decode(out["der_b64"]) == cert.public_bytes(Enc.DER)

    assert extension(out, "keyUsage")["values"] == ["digital_signature", "content_commitment"]
    assert any(v.startswith("OCSP: http") for v in extension(out, "authorityInfoAccess")["values"])
    assert extension(out, "cRLDistributionPoints")["values"] == [pki.crl_url(pki.INTERMEDIATE)]


def test_root_is_self_signed_ca(client):
    [out] = inspect(client, crt=pki.entity(pki.ROOT).cert().public_bytes(Enc.PEM))
    assert out["is_ca"] is True
    assert out["self_signed"] is True
    basic = extension(out, "basicConstraints")
    assert basic["critical"] is True
    assert basic["values"][0].startswith("CA=sí")


def test_tsa_extended_key_usage(client):
    [out] = inspect(client, crt=pki.entity(pki.TSA).cert().public_bytes(Enc.DER))
    eku = extension(out, "extendedKeyUsage")
    assert eku["critical"] is True
    assert eku["values"] == ["timeStamping"]


def test_pkcs7_returns_every_certificate(client):
    certs = [pki.entity(n).cert() for n in (pki.INTERMEDIATE, pki.ROOT)]
    out = inspect(client, crt=pkcs7.serialize_certificates(certs, Enc.DER))
    assert {c["subject_rfc4514"] for c in out} == {c.subject.rfc4514_string() for c in certs}


def test_pasted_base64_and_pem(client):
    """El campo de texto acepta el der_b64 de /certificates (aun cortado en líneas) y un PEM."""
    cert = pki.entity(pki.SIGNER).cert()
    der_b64 = base64.b64encode(cert.public_bytes(Enc.DER)).decode()
    wrapped = "\n".join(der_b64[i : i + 64] for i in range(0, len(der_b64), 64))
    for text in (der_b64, wrapped, cert.public_bytes(Enc.PEM).decode()):
        [out] = inspect(client, b64=text)
        assert out["der_b64"] == der_b64


def test_real_certificate_with_sha1_and_policies(client):
    """La CA de la ONTI (PKI argentina): firmada con SHA-1 por la AC Raíz de 2007."""
    [out] = inspect(client, crt=(SEED_DIR / "ac-onti-firma-digital.der").read_bytes())
    assert out["signature_algorithm"] == "sha1WithRSAEncryption"
    assert out["is_ca"] is True
    assert out["self_signed"] is False
    assert {"name": "serialNumber", "oid": "2.5.4.5", "value": "CUIT 30680604572"} in out["subject"]
    assert extension(out, "certificatePolicies")["values"] == [
        "Política 2.16.32.1.1.3",
        "CPS: http://pki.jgm.gov.ar/cps/cps.pdf",  # el certificado la termina con un NUL
        "CPS: http://pkicont.jgm.gov.ar/cps/cps.pdf",
        "Aviso: Certificado emitido por un certificador licenciado en el marco de la ley 25.506",
    ]
    # Extensiones de Microsoft AD CS, que cryptography no conoce: se nombran y se decodifican.
    assert extension(out, "msCertificateTemplateName")["values"] == ["SubCA"]
    assert extension(out, "msCAVersion")["values"] == ["1"]
    assert extension(out, "msPreviousCACertHash")["values"][0].startswith("43:0b:e3")


def test_expired_ec_certificate(client):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Vencido")])
    past = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(past)
        .not_valid_after(past + dt.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    [out] = inspect(client, crt=cert.public_bytes(Enc.DER))
    assert out["validity"]["status"] == "expired"
    assert out["validity"]["days_left"] < 0
    assert out["public_key"] == {"type": "EC", "size": 256, "curve": "secp256r1"}
    assert out["extensions"] == []


@pytest.mark.parametrize(
    "files, data",
    [
        (None, None),
        ({"crt": ("a.crt", b"x", "application/octet-stream")}, {"b64": "x"}),
    ],
)
def test_requires_exactly_one_input(client, files, data):
    r = client.post("/certificates/inspect", files=files, data=data)
    assert r.status_code == 422


@pytest.mark.parametrize("payload", [b"<html>404</html>", b"bm8gZXMgdW4gY2VydGlmaWNhZG8="])
def test_garbage_is_rejected(client, payload):
    r = client.post("/certificates/inspect", files={"crt": ("a.crt", payload, "application/octet-stream")})
    assert r.status_code == 422
    assert r.json()["detail"] == "No es un certificado DER, PEM, PKCS#7 ni base64 de un DER"
