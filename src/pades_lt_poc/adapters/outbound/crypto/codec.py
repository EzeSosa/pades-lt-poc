"""`CertificateCodec` con `cryptography`: parseo de certificados y verificación de emisor.

Además de la clase del puerto, expone las funciones sobre `cryptography.x509.Certificate`
que todavía usan los servicios que no se migraron (extracción de cadenas e inspección).
Ver docs/arquitectura/adaptadores.md.
"""

from __future__ import annotations

import base64
import binascii

from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import AuthorityInformationAccessOID

from ....domain.certificates import Certificate, CertificateDetails
from ....domain.errors import UnprocessableCertificate
from . import details


class CryptographyCertificateCodec:
    """Implementa `application.ports.CertificateCodec`."""

    def parse(self, data: bytes) -> list[Certificate]:
        return [to_domain(c) for c in load_certs(data)]

    def issued_by(self, cert: Certificate, issuer: Certificate) -> bool:
        return issued_by(_x509(cert), _x509(issuer))

    def describe(self, cert: Certificate) -> CertificateDetails:
        return details.describe(_x509(cert))


def _x509(cert: Certificate) -> x509.Certificate:
    return x509.load_der_x509_certificate(cert.der)


def to_domain(cert: x509.Certificate) -> Certificate:
    der = cert.public_bytes(serialization.Encoding.DER)
    # Los nombres para mostrar y el hash de la firma, como los da asn1crypto (lo que usa pyHanko).
    asn1 = asn1_x509.Certificate.load(der)
    return Certificate(
        der=der,
        sha256=cert.fingerprint(hashes.SHA256()).hex(),
        sha1=cert.fingerprint(hashes.SHA1()).hex(),
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial_number=cert.serial_number,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        is_ca=is_ca(cert),
        self_signed=issued_by(cert, cert),
        ca_issuer_urls=ca_issuer_urls(cert),
        display_name=asn1.subject.human_friendly,
        common_name=asn1.subject.native.get("common_name"),
        signature_hash_algorithm=_signature_hash(asn1),
    )


def _signature_hash(cert: asn1_x509.Certificate) -> str | None:
    try:
        return cert["signature_algorithm"].hash_algo
    except ValueError:  # p. ej. Ed25519, que no tiene un hash separado
        return None


# --------------------------------------------------------------------------- parseo
def parse_certs(data: bytes) -> list[x509.Certificate]:
    """Los `.crt`/`.p7c` publicados (p. ej. en AIA) pueden venir en DER, PEM o PKCS#7.

    Lanza ValueError si no es ninguno.
    """
    loaders = (
        lambda d: [x509.load_der_x509_certificate(d)],
        x509.load_pem_x509_certificates,
        pkcs7.load_der_pkcs7_certificates,
        pkcs7.load_pem_pkcs7_certificates,
    )
    for load in loaders:
        try:
            return load(data)
        except ValueError:
            continue
    raise ValueError("no es un certificado DER, PEM ni PKCS#7")


def load_certs(data: bytes) -> list[x509.Certificate]:
    """Como `parse_certs`, y además el base64 de un DER. Lanza `UnprocessableCertificate`."""
    try:
        return parse_certs(data)
    except ValueError:
        pass
    # Base64 pegado a mano (p. ej. el der_b64 de /certificates): sin encabezados ni saltos de línea fijos.
    try:
        der = base64.b64decode(b"".join(data.split()), validate=True)
        return parse_certs(der)
    except (binascii.Error, ValueError):
        raise UnprocessableCertificate("No es un certificado DER, PEM, PKCS#7 ni base64 de un DER") from None


# --------------------------------------------------------------------------- atributos
def is_ca(cert: x509.Certificate) -> bool:
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def ca_issuer_urls(cert: x509.Certificate) -> tuple[str, ...] | None:
    """Las URIs AIA caIssuers, en orden; None si no tiene la extensión AIA."""
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return None
    return tuple(
        d.access_location.value
        for d in aia
        if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS
        and isinstance(d.access_location, x509.UniformResourceIdentifier)
    )


def issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """True si `issuer` firmó `cert` (nombre del emisor + firma verificada)."""
    try:
        cert.verify_directly_issued_by(issuer)
    except ValueError as e:
        # cryptography rechaza algoritmos débiles como SHA-1, que siguen usando
        # PKIs reales (p. ej. la AC Raíz de Argentina firmando a sus CAs). Acá
        # sólo armamos la cadena, no evaluamos política: se verifica a mano.
        return "Unsupported signature algorithm" in str(e) and _verify_legacy(cert, issuer)
    except (TypeError, InvalidSignature):
        return False
    return True


def _verify_legacy(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    if cert.issuer != issuer.subject or cert.signature_hash_algorithm is None:
        return False
    key = issuer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        else:
            return False
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True
