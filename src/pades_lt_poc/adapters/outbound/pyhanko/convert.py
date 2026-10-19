"""Conversión entre los certificados de pyHanko (asn1crypto) y los de dominio."""

from __future__ import annotations

from collections.abc import Iterable

from asn1crypto import x509 as asn1_x509

from ....application.ports import CertificateCodec
from ....domain.certificates import Certificate


class CertificateConverter:
    """asn1crypto -> `Certificate`, una vez por certificado (el mismo suele aparecer varias veces en un PDF)."""

    def __init__(self, codec: CertificateCodec) -> None:
        self.codec = codec
        self._cache: dict[bytes, Certificate] = {}

    def __call__(self, cert: asn1_x509.Certificate) -> Certificate:
        der = cert.dump()
        if der not in self._cache:
            [self._cache[der]] = self.codec.parse(der)
        return self._cache[der]


def to_asn1(certs: Iterable[Certificate]) -> list[asn1_x509.Certificate]:
    """Certificados de dominio como los recibe pyHanko."""
    return [asn1_x509.Certificate.load(c.der) for c in certs]
