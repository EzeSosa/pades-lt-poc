"""
Mini PKI de prueba, de dos niveles:

    Root CA (autofirmada, offline en la vida real)
     │   publica: /pki/root.crl
     └── Intermediate CA
          │   publica: /pki/intermediate.crl  +  OCSP en /ocsp
          ├── Firmante        KU digitalSignature + nonRepudiation
          ├── TSA             EKU timeStamping (crítica)
          └── OCSP Responder  EKU OCSPSigning + id-pkix-ocsp-nocheck

La revocación de la intermedia se verifica por CRL de la raíz; la de las
hojas, por OCSP (y CRL de la intermedia como respaldo). Así el DSS de una
firma B-LT termina conteniendo ambos tipos de información de revocación.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

PKI_DIR = Path(os.environ.get("PKI_DIR", Path.cwd() / "pki"))
BASE_URL = os.environ.get("PUBLIC_BASE_URL", "http://127.0.0.1:8000")
OCSP_URL = f"{BASE_URL}/ocsp"

# Identidades de la PKI: nombre lógico -> (CN, emisor, perfil)
ROOT, INTERMEDIATE = "root", "intermediate"
SIGNER, TSA, OCSP_RESPONDER = "signer", "tsa", "ocsp"
CAS = (ROOT, INTERMEDIATE)
LEAVES = {
    SIGNER: "Firmante de Prueba",
    TSA: "PoC Time Stamping Authority",
    OCSP_RESPONDER: "PoC OCSP Responder",
}


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def crl_url(ca: str) -> str:
    return f"{BASE_URL}/pki/{ca}.crl"


def cert_url(ca: str) -> str:
    return f"{BASE_URL}/pki/{ca}.crt"


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PoC PAdES"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _key_usage(**enabled: bool) -> x509.KeyUsage:
    flags = dict.fromkeys(
        (
            "digital_signature",
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
            "encipher_only",
            "decipher_only",
        ),
        False,
    )
    flags.update(enabled)
    return x509.KeyUsage(**flags)


def _cdp(url: str) -> x509.CRLDistributionPoints:
    return x509.CRLDistributionPoints(
        [x509.DistributionPoint([x509.UniformResourceIdentifier(url)], None, None, None)]
    )


def _aia(issuer: str, with_ocsp: bool) -> x509.AuthorityInformationAccess:
    descs = [
        x509.AccessDescription(
            AuthorityInformationAccessOID.CA_ISSUERS,
            x509.UniformResourceIdentifier(cert_url(issuer)),
        )
    ]
    if with_ocsp:
        descs.insert(
            0,
            x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(OCSP_URL)
            ),
        )
    return x509.AuthorityInformationAccess(descs)


def _builder(subject: x509.Name, issuer: x509.Name, key, days: int) -> x509.CertificateBuilder:
    now = _now()
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )


def _build_root(key) -> x509.Certificate:
    name = _name("PoC Root CA")
    return (
        _builder(name, name, key, days=3650)
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(_key_usage(key_cert_sign=True, crl_sign=True), critical=True)
        .sign(key, hashes.SHA256())
    )


def _build_intermediate(key, root_cert, root_key) -> x509.Certificate:
    return (
        _builder(_name("PoC Intermediate CA"), root_cert.subject, key, days=1825)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_key_usage(key_cert_sign=True, crl_sign=True), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .add_extension(_cdp(crl_url(ROOT)), critical=False)
        .add_extension(_aia(ROOT, with_ocsp=False), critical=False)
        .sign(root_key, hashes.SHA256())
    )


def _build_leaf(role: str, key, ca_cert, ca_key) -> x509.Certificate:
    b = (
        _builder(_name(LEAVES[role]), ca_cert.subject, key, days=730)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    if role == SIGNER:
        b = b.add_extension(
            _key_usage(digital_signature=True, content_commitment=True), critical=True
        )
    elif role == TSA:
        # RFC 3161 §2.3: el EKU timeStamping DEBE ser el único y crítico.
        b = b.add_extension(_key_usage(digital_signature=True), critical=True).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
        )
    elif role == OCSP_RESPONDER:
        # Respondedor delegado (RFC 6960 §4.2.2.2). Con ocsp-nocheck el validador
        # no necesita verificar la revocación del propio respondedor.
        b = (
            b.add_extension(_key_usage(digital_signature=True), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False)
            .add_extension(x509.OCSPNoCheck(), critical=False)
        )
    if role != OCSP_RESPONDER:
        b = b.add_extension(_cdp(crl_url(INTERMEDIATE)), critical=False).add_extension(
            _aia(INTERMEDIATE, with_ocsp=True), critical=False
        )
    return b.sign(ca_key, hashes.SHA256())


# --------------------------------------------------------------------------- disco
@dataclass(frozen=True)
class Entity:
    name: str

    @property
    def cert_path(self) -> Path:
        return PKI_DIR / f"{self.name}.crt.pem"

    @property
    def key_path(self) -> Path:
        return PKI_DIR / f"{self.name}.key.pem"

    def cert(self) -> x509.Certificate:
        return x509.load_pem_x509_certificate(self.cert_path.read_bytes())

    def key(self):
        return serialization.load_pem_private_key(self.key_path.read_bytes(), None)

    def save(self, cert: x509.Certificate, key) -> None:
        self.cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )


def entity(name: str) -> Entity:
    return Entity(name)


# seriales revocados: {serial_hex: {"issuer": "root|intermediate", "time": iso}}
REVOKED = PKI_DIR / "revoked.json"
ISSUER_OF = {INTERMEDIATE: ROOT, SIGNER: INTERMEDIATE, TSA: INTERMEDIATE, OCSP_RESPONDER: INTERMEDIATE}


def _new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def ensure_pki() -> None:
    """Genera la PKI completa si todavía no existe en disco."""
    if entity(ROOT).cert_path.exists():
        return
    PKI_DIR.mkdir(parents=True, exist_ok=True)

    root_key = _new_key()
    root_cert = _build_root(root_key)
    entity(ROOT).save(root_cert, root_key)

    int_key = _new_key()
    int_cert = _build_intermediate(int_key, root_cert, root_key)
    entity(INTERMEDIATE).save(int_cert, int_key)

    for role in LEAVES:
        key = _new_key()
        entity(role).save(_build_leaf(role, key, int_cert, int_key), key)

    REVOKED.write_text("{}")


def _revoked() -> dict[str, dict]:
    return json.loads(REVOKED.read_text())


def revoke(name: str) -> str:
    serial = format(entity(name).cert().serial_number, "x")
    data = _revoked()
    data[serial] = {"issuer": ISSUER_OF[name], "time": _now().isoformat()}
    REVOKED.write_text(json.dumps(data, indent=2))
    return serial


def unrevoke_all() -> None:
    REVOKED.write_text("{}")


# --------------------------------------------------------------------------- CRL
def build_crl(ca: str) -> bytes:
    """CRL fresca (DER) de `ca`, válida por 1 día."""
    ca_cert, ca_key = entity(ca).cert(), entity(ca).key()
    now = _now()
    b = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now - dt.timedelta(minutes=1))
        .next_update(now + dt.timedelta(days=1))
        .add_extension(x509.CRLNumber(int(now.timestamp())), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    for serial, info in _revoked().items():
        if info["issuer"] == ca:
            b = b.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(int(serial, 16))
                .revocation_date(dt.datetime.fromisoformat(info["time"]))
                .build()
            )
    return b.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


# --------------------------------------------------------------------------- OCSP
def ocsp_respond(request_der: bytes) -> bytes:
    """Respondedor OCSP (RFC 6960) para los certificados emitidos por la intermedia."""
    try:
        req = ocsp.load_der_ocsp_request(request_der)
    except ValueError:
        return ocsp.OCSPResponseBuilder.build_unsuccessful(
            ocsp.OCSPResponseStatus.MALFORMED_REQUEST
        ).public_bytes(serialization.Encoding.DER)

    issuer_cert = entity(INTERMEDIATE).cert()
    issued = {c.serial_number: c for c in (entity(r).cert() for r in (SIGNER, TSA))}
    target = issued.get(req.serial_number)
    # issuerKeyHash = hash del BIT STRING de la clave pública del emisor (RFC 6960 §4.1.1)
    h = hashes.Hash(req.hash_algorithm)
    h.update(
        issuer_cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.PKCS1
        )
    )
    if target is None or req.issuer_key_hash != h.finalize():
        return ocsp.OCSPResponseBuilder.build_unsuccessful(
            ocsp.OCSPResponseStatus.UNAUTHORIZED
        ).public_bytes(serialization.Encoding.DER)

    now = _now()
    rev = _revoked().get(format(target.serial_number, "x"))
    responder = entity(OCSP_RESPONDER)
    b = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=target,
            issuer=issuer_cert,
            algorithm=req.hash_algorithm,
            cert_status=ocsp.OCSPCertStatus.REVOKED if rev else ocsp.OCSPCertStatus.GOOD,
            this_update=now - dt.timedelta(minutes=1),
            next_update=now + dt.timedelta(hours=12),
            revocation_time=dt.datetime.fromisoformat(rev["time"]) if rev else None,
            revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, responder.cert())
        .certificates([responder.cert()])
    )
    try:
        nonce = req.extensions.get_extension_for_class(x509.OCSPNonce).value
        b = b.add_extension(nonce, critical=False)
    except x509.ExtensionNotFound:
        pass
    return b.sign(responder.key(), hashes.SHA256()).public_bytes(serialization.Encoding.DER)
