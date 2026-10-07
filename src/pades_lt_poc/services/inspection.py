"""Detalle legible de un certificado X.509 (o de los de un PKCS#7): sujeto, vigencia, clave y extensiones."""

from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime

from asn1crypto import core as asn1_core
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from . import UnprocessableCertificate
from .certificates import _issued_by, _parse_certs


class CertificateInspector:
    """Acepta DER, PEM o PKCS#7 (como los que publica AIA), o el base64 de un DER sin encabezados."""

    def inspect(self, data: bytes) -> dict:
        certs = _load(data)
        now = datetime.now(UTC)
        return {"certificates": [_inspect(c, now) for c in certs]}


def _load(data: bytes) -> list[x509.Certificate]:
    try:
        return _parse_certs(data)
    except ValueError:
        pass
    # Base64 pegado a mano (p. ej. el der_b64 de /certificates): sin encabezados ni saltos de línea fijos.
    try:
        der = base64.b64decode(b"".join(data.split()), validate=True)
        return _parse_certs(der)
    except (binascii.Error, ValueError):
        raise UnprocessableCertificate("No es un certificado DER, PEM, PKCS#7 ni base64 de un DER") from None


def _inspect(cert: x509.Certificate, now: datetime) -> dict:
    not_before, not_after = cert.not_valid_before_utc, cert.not_valid_after_utc
    status = "not_yet_valid" if now < not_before else "expired" if now > not_after else "valid"
    der = cert.public_bytes(serialization.Encoding.DER)
    return {
        "version": cert.version.value + 1,
        "serial_number": format(cert.serial_number, "x"),
        "subject": _name(cert.subject),
        "issuer": _name(cert.issuer),
        "subject_rfc4514": cert.subject.rfc4514_string(),
        "issuer_rfc4514": cert.issuer.rfc4514_string(),
        "self_signed": _issued_by(cert, cert),
        "is_ca": _is_ca(cert),
        "validity": {
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "status": status,
            "days_left": (not_after - now).days,
        },
        "signature_algorithm": _oid_name(cert.signature_algorithm_oid),
        "public_key": _public_key(cert),
        "fingerprints": {
            "sha1": cert.fingerprint(hashes.SHA1()).hex(),
            "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        },
        "extensions": [_extension(e) for e in cert.extensions],
        "der_b64": base64.b64encode(der).decode(),
    }


# OIDs que cryptography no nombra pero aparecen en certificados reales (las CAs de
# la PKI argentina corren sobre Microsoft AD CS).
EXTRA_OID_NAMES = {
    "1.3.6.1.4.1.311.20.2": "msCertificateTemplateName",
    "1.3.6.1.4.1.311.21.1": "msCAVersion",
    "1.3.6.1.4.1.311.21.2": "msPreviousCACertHash",
    "1.3.6.1.4.1.311.21.7": "msCertificateTemplate",
    "1.3.6.1.4.1.311.21.10": "msApplicationPolicies",
}


def _oid_name(oid: x509.ObjectIdentifier) -> str:
    # cryptography sólo expone el nombre corto de los OIDs que conoce, como atributo privado.
    name = getattr(oid, "_name", None)
    if not name or name == "Unknown OID":
        return EXTRA_OID_NAMES.get(oid.dotted_string, oid.dotted_string)
    return name


def _name(name: x509.Name) -> list[dict]:
    return [
        {"oid": a.oid.dotted_string, "name": _oid_name(a.oid), "value": _text(a.value)}
        for rdn in name.rdns
        for a in rdn
    ]


def _text(value: str | bytes) -> str:
    return value if isinstance(value, str) else value.hex()


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def _public_key(cert: x509.Certificate) -> dict:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return {"type": "RSA", "size": key.key_size}
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"type": "EC", "size": key.curve.key_size, "curve": key.curve.name}
    if isinstance(key, dsa.DSAPublicKey):
        return {"type": "DSA", "size": key.key_size}
    if isinstance(key, ed25519.Ed25519PublicKey):
        return {"type": "Ed25519", "size": 256}
    if isinstance(key, ed448.Ed448PublicKey):
        return {"type": "Ed448", "size": 456}
    return {"type": type(key).__name__, "size": None}


def _extension(ext: x509.Extension) -> dict:
    return {
        "oid": ext.oid.dotted_string,
        "name": _oid_name(ext.oid),
        "critical": ext.critical,
        "values": _extension_values(ext.value),
    }


KEY_USAGES = (
    "digital_signature",
    "content_commitment",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "key_cert_sign",
    "crl_sign",
)


def _extension_values(value: x509.ExtensionType) -> list[str]:
    """La extensión como líneas de texto. Los nombres son los de RFC 5280 / cryptography, sin traducir."""
    match value:
        case x509.BasicConstraints():
            limit = "" if value.path_length is None else f", pathLen={value.path_length}"
            return [f"CA={'sí' if value.ca else 'no'}{limit}"]
        case x509.KeyUsage():
            used = [u for u in KEY_USAGES if getattr(value, u)]
            if value.key_agreement:  # sólo entonces se pueden leer
                used += [u for u in ("encipher_only", "decipher_only") if getattr(value, u)]
            return used
        case x509.ExtendedKeyUsage():
            return [_oid_name(oid) for oid in value]
        case x509.AuthorityInformationAccess() | x509.SubjectInformationAccess():
            return [f"{_oid_name(d.access_method)}: {_general_name(d.access_location)}" for d in value]
        case x509.CRLDistributionPoints() | x509.FreshestCRL():
            return [_general_name(n) for dp in value for n in dp.full_name or []]
        case x509.CertificatePolicies():
            return [line for p in value for line in _policy(p)]
        case x509.SubjectAlternativeName() | x509.IssuerAlternativeName():
            return [_general_name(n) for n in value]
        case x509.SubjectKeyIdentifier():
            return [value.digest.hex(":")]
        case x509.AuthorityKeyIdentifier():
            return [value.key_identifier.hex(":")] if value.key_identifier else []
        case x509.OCSPNoCheck():
            return ["presente: el respondedor OCSP no se valida contra revocación"]
        case x509.UnrecognizedExtension():
            return [_der_value(value.value)]
    return [str(value)]


def _der_value(der: bytes) -> str:
    """Valor de una extensión desconocida: decodificado si es un ASN.1 simple (texto, entero), si no en hex."""
    try:
        native = asn1_core.load(der).native
    except (ValueError, TypeError):
        return der.hex()
    if isinstance(native, (str, int)):
        return str(native)
    return native.hex(":") if isinstance(native, bytes) else der.hex()


def _general_name(name: x509.GeneralName) -> str:
    match name:
        case x509.DirectoryName():
            return name.value.rfc4514_string()
        case x509.OtherName():
            return f"{_oid_name(name.type_id)}: {name.value.hex()}"
        case x509.RegisteredID():
            return _oid_name(name.value)
    return str(name.value)


def _policy(policy: x509.PolicyInformation) -> list[str]:
    """Una línea por política y otra por cada calificador (CPS o aviso al usuario)."""
    lines = [f"Política {_oid_name(policy.policy_identifier)}"]
    for q in policy.policy_qualifiers or []:
        # Algunas CAs (p. ej. la ONTI) terminan las URIs del CPS con un NUL.
        if isinstance(q, str):
            lines.append(f"CPS: {q.rstrip(chr(0))}")
        elif q.explicit_text:
            lines.append(f"Aviso: {q.explicit_text.rstrip(chr(0))}")
    return lines
