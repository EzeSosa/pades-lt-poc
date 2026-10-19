"""Caso de uso: el detalle legible de uno o varios certificados sueltos (no de un PDF)."""

from __future__ import annotations

from dataclasses import dataclass

from ...domain.certificates import Certificate, CertificateDetails
from ..ports import CertificateCodec
from .certificate_source import CertificateSource


@dataclass(frozen=True)
class InspectedCertificate:
    certificate: Certificate
    details: CertificateDetails
    in_store: bool
    """Si ya está en la fuente de certificados (habilitado o no). La UI lo usa para ofrecer agregarlo."""


class InspectCertificates:
    """Acepta DER, PEM o PKCS#7 (como los que publica AIA), o el base64 de un DER sin encabezados.

    Un PKCS#7 puede traer varios certificados: se devuelven todos, en el orden en que vienen.
    No hace E/S.
    """

    def __init__(self, codec: CertificateCodec, source: CertificateSource) -> None:
        self.codec = codec
        self.source = source

    def inspect(self, data: bytes) -> list[InspectedCertificate]:
        """Lanza `UnprocessableCertificate` si `data` no es un certificado en un formato conocido."""
        certs = self.codec.parse(data)
        snapshot = self.source.snapshot()
        return [InspectedCertificate(c, self.codec.describe(c), snapshot.contains(c)) for c in certs]
