"""Las firmas de un PDF tal como las ve el negocio: qué tipo son, qué certificados traen y si están íntegras.

Lo arma el puerto `SignedPdfReader` (con pyHanko). Ver docs/arquitectura/dominio.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from .certificates import Certificate


class SignatureKind(StrEnum):
    SIGNATURE = "Signature"
    """Una firma de documento (`/Sig`), opcionalmente con un sello de tiempo sobre su valor."""
    DOC_TIMESTAMP = "DocTimeStamp"
    """Un sello de tiempo de documento (`/DocTimeStamp`, PAdES B-LTA)."""


@dataclass(frozen=True)
class Integrity:
    """El chequeo criptográfico de una firma CMS, sin confianza ni revocación.

    - `intact`: lo que la firma dice cubrir no cambió (el hash coincide).
    - `valid`: la firma verifica con la clave del certificado firmante.
    - `error`: el motivo, si el chequeo no se pudo hacer (p. ej. no se encontró el firmante).
    """

    intact: bool
    valid: bool
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.intact and self.valid

    def failure(self, altered: str) -> str | None:
        """Por qué falló, para mostrar: el error, o `altered` si lo cubierto cambió, o "firma inválida"."""
        if self.ok:
            return None
        return self.error or (altered if not self.intact else "firma inválida")


@dataclass(frozen=True)
class CmsSignature:
    """Una firma CMS (la de un documento, un sello de tiempo o un sello de documento)."""

    signer: Certificate | None
    """El certificado firmante; None si no se pudo identificar (y entonces `integrity` falla)."""
    other_certificates: tuple[Certificate, ...]
    """Los demás certificados que trae el CMS, en orden."""
    integrity: Integrity


@dataclass(frozen=True)
class TimestampToken:
    """Un sello de tiempo RFC 3161: una firma CMS de la TSA sobre un TSTInfo."""

    time: datetime
    """La hora sellada (`genTime`)."""
    cms: CmsSignature
    """La firma de la TSA. Su integridad incluye que el sello corresponda a lo sellado."""


@dataclass(frozen=True)
class EmbeddedSignature:
    field_name: str
    kind: SignatureKind
    cms: CmsSignature
    """La firma (para un DocTimeStamp, la de la TSA sobre el documento)."""
    timestamp: TimestampToken | None
    """El sello de tiempo de la firma (atributo no firmado), si tiene. Siempre None para un DocTimeStamp."""


@dataclass(frozen=True)
class SignedDocument:
    signatures: tuple[EmbeddedSignature, ...]
    """En el orden del documento. Nunca vacío: un PDF sin firmas no es un `SignedDocument`."""
    dss_certificates: tuple[Certificate, ...]
    """Los certificados del DSS (Document Security Store), si el PDF tiene uno."""
