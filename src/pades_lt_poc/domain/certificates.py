"""El certificado X.509 tal como lo ve el negocio: su DER y los datos que las reglas necesitan.

Lo construye un adaptador (`CertificateCodec`) a partir de los bytes; el dominio no parsea
ASN.1 ni verifica firmas. Ver ADR-0002.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class ValidityStatus(StrEnum):
    """Dónde cae un momento respecto de la vigencia del certificado."""

    VALID = "valid"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"


class CaKind(StrEnum):
    """Qué tipo de CA es: una raíz (autofirmada) o un intermedio. Es el `kind` de la fuente."""

    ROOT = "root"
    INTERMEDIATE = "intermediate"


@dataclass(frozen=True)
class Certificate:
    """Un certificado X.509. Dos certificados son el mismo si su DER es el mismo.

    Todos los campos salvo `der` se derivan de él (los calcula el codec al parsear), así que
    no participan de la igualdad ni del hash.
    """

    der: bytes
    sha256: str = field(compare=False)
    """Huella SHA-256 del DER, en hexadecimal en minúsculas. Es la identidad del certificado en la fuente."""
    sha1: str = field(compare=False)
    """Huella SHA-1 del DER, en hexadecimal en minúsculas. Sólo informativa."""
    subject: str = field(compare=False)
    """Sujeto en formato RFC 4514 (p. ej. `CN=PoC Root CA,O=PoC PAdES,C=AR`)."""
    issuer: str = field(compare=False)
    """Emisor en formato RFC 4514."""
    serial_number: int = field(compare=False)
    not_before: datetime = field(compare=False)
    """Inicio de la vigencia, con zona horaria (UTC)."""
    not_after: datetime = field(compare=False)
    """Fin de la vigencia, con zona horaria (UTC)."""
    is_ca: bool = field(compare=False)
    """Si `basicConstraints` dice que es una CA. Sin la extensión, no lo es."""
    self_signed: bool = field(compare=False)
    """Si su propia clave verifica su firma (no basta con que sujeto y emisor coincidan)."""
    ca_issuer_urls: tuple[str, ...] | None = field(default=None, compare=False)
    """Las URIs AIA caIssuers (dónde se publica su emisor), en orden. None si no tiene la extensión
    AIA; vacío si la tiene pero sin caIssuers. Incluye las que no son HTTP."""

    def validity_status(self, now: datetime) -> ValidityStatus:
        """La vigencia en `now`. Los dos extremos cuentan como vigentes."""
        if now < self.not_before:
            return ValidityStatus.NOT_YET_VALID
        if now > self.not_after:
            return ValidityStatus.EXPIRED
        return ValidityStatus.VALID

    def days_left(self, now: datetime) -> int:
        """Días completos desde `now` hasta el fin de la vigencia; negativo si ya venció."""
        return (self.not_after - now).days

    @property
    def ca_kind(self) -> CaKind | None:
        """Raíz si es una CA autofirmada, intermedio si es una CA emitida por otra; None si no es CA."""
        if not self.is_ca:
            return None
        return CaKind.ROOT if self.self_signed else CaKind.INTERMEDIATE


# --------------------------------------------------------------------------- detalle legible
@dataclass(frozen=True)
class NameAttribute:
    """Un atributo de un nombre X.500 (sujeto o emisor)."""

    oid: str
    name: str
    """El nombre corto del OID (`commonName`, `serialNumber`, ...) o el OID si no se conoce."""
    value: str
    """El valor como texto; los valores binarios, en hexadecimal."""


@dataclass(frozen=True)
class PublicKeyInfo:
    type: str
    """`RSA`, `EC`, `DSA`, `Ed25519`, `Ed448`, o el nombre de la clase si es otro."""
    size: int | None
    """Bits de la clave (de la curva, si es EC)."""
    curve: str | None = None
    """Sólo EC: el nombre de la curva."""


@dataclass(frozen=True)
class ExtensionInfo:
    oid: str
    name: str
    critical: bool
    values: tuple[str, ...]
    """La extensión como líneas de texto. Ver `CertificateCodec.describe`."""


@dataclass(frozen=True)
class CertificateDetails:
    """Lo que muestra la inspección de un certificado, además de lo que ya tiene `Certificate`."""

    version: int
    """1, 2 o 3."""
    subject: tuple[NameAttribute, ...]
    issuer: tuple[NameAttribute, ...]
    signature_algorithm: str
    public_key: PublicKeyInfo
    extensions: tuple[ExtensionInfo, ...]
