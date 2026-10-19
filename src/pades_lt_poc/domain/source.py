"""La fuente de certificados: raíces e intermedios que usa el validador además de lo que trae el PDF.

Reglas (los ids son los de docs/arquitectura/invariantes.md):

- F-01  La fuente sólo guarda CAs (`new_entries`).
- F-02  Sólo una raíz puede ser ancla de confianza: al agregar, un intermedio queda como no
        confiable (`new_entries`); al cambiarlo, pedirlo es un error (`check_changes`).
- F-03  Si todos los certificados recibidos ya estaban, es un error; si estaban algunos, se
        agregan los demás (caso de uso `CertificateSource.add`).
- F-04  La carga inicial se aplica una sola vez; restaurarla sólo agrega lo que falta.
- F-05  Un cambio aplica enseguida, y una verificación ve raíces e intermedios de un mismo
        estado de la fuente (`TrustSnapshot`).
- F-06  Para saber si un certificado está en la fuente cuenta todo; para confiar y completar
        cadenas, sólo lo habilitado (`TrustSnapshot.from_entries`).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from .certificates import CaKind, Certificate
from .errors import UnprocessableCertificate, UnprocessableInput


class Origin(StrEnum):
    """De dónde salió un certificado de la fuente."""

    SEED = "seed"
    """De la carga inicial."""
    MANUAL = "manual"
    """Cargado a mano (un archivo o un base64)."""
    PDF = "pdf"
    """Tomado de un PDF firmado (desde la inspección de sus certificados)."""


@dataclass(frozen=True)
class SeedCertificate:
    """Un certificado de la carga inicial, con la nota que lo explica."""

    der: bytes
    notes: str


@dataclass(frozen=True)
class NewEntry:
    """Un certificado listo para entrar a la fuente, con las reglas ya aplicadas."""

    certificate: Certificate
    kind: CaKind
    trusted: bool
    origin: Origin
    notes: str


@dataclass(frozen=True)
class StoredCertificate:
    """Un certificado de la fuente."""

    id: int
    certificate: Certificate
    kind: CaKind
    trusted: bool
    """Si es ancla de confianza. Sólo puede serlo una raíz (F-02)."""
    enabled: bool
    """Si el validador lo usa. Uno deshabilitado sigue en la fuente, pero no confía ni completa cadenas."""
    origin: Origin
    notes: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class EntryChanges:
    """Lo que se puede cambiar de un certificado de la fuente. `None` es "no cambiar"."""

    enabled: bool | None = None
    trusted: bool | None = None
    notes: str | None = None

    def is_empty(self) -> bool:
        return self.enabled is None and self.trusted is None and self.notes is None


@dataclass(frozen=True)
class AddResult:
    added: list[StoredCertificate]
    already_present: list[StoredCertificate]


@dataclass(frozen=True)
class TrustSnapshot:
    """Lo que usa el validador de la fuente, en un instante. Inmutable: se reemplaza entero en cada cambio."""

    trusted_roots: tuple[Certificate, ...]
    """Raíces habilitadas y confiables: anclas de confianza."""
    intermediates: tuple[Certificate, ...]
    """Intermedios habilitados: completan cadenas que el PDF no trae."""
    chain_certs: tuple[Certificate, ...]
    """Raíces e intermedios habilitados, confiables o no: para armar cadenas sin exigir confianza."""
    known_sha256: frozenset[str]
    """Huella de todo lo que está en la fuente, habilitado o no: para decir si un certificado ya está."""

    @classmethod
    def from_entries(cls, entries: Iterable[StoredCertificate]) -> TrustSnapshot:
        """El snapshot de `entries`, conservando su orden en cada grupo."""
        entries = list(entries)
        enabled = [e for e in entries if e.enabled]
        return cls(
            trusted_roots=tuple(e.certificate for e in enabled if e.trusted),
            intermediates=tuple(e.certificate for e in enabled if e.kind is CaKind.INTERMEDIATE),
            chain_certs=tuple(e.certificate for e in enabled),
            known_sha256=frozenset(e.certificate.sha256 for e in entries),
        )

    def contains(self, cert: Certificate) -> bool:
        return cert.sha256 in self.known_sha256


EMPTY_SNAPSHOT = TrustSnapshot((), (), (), frozenset())


@dataclass(frozen=True)
class SourceSummary:
    total: int
    trusted_roots: int
    """Raíces que el validador usa como anclas (habilitadas y confiables)."""
    intermediates: int
    """Intermedios que el validador usa para completar cadenas (habilitados)."""
    disabled: int


def new_entries(certs: Iterable[Certificate], *, trusted: bool, notes: str, origin: Origin) -> list[NewEntry]:
    """Las entradas para agregar `certs` a la fuente.

    F-01: si alguno no es CA, no se agrega ninguno. F-02: `trusted` sólo vale para las raíces;
    un intermedio queda siempre como no confiable.
    """
    certs = list(certs)
    not_ca = [c.subject for c in certs if not c.is_ca]
    if not_ca:
        raise UnprocessableCertificate(
            f"La fuente sólo guarda raíces e intermedios (CAs), y esto no lo es: {'; '.join(not_ca)}"
        )
    return [
        NewEntry(
            certificate=c,
            kind=c.ca_kind,
            trusted=trusted and c.ca_kind is CaKind.ROOT,
            origin=origin,
            notes=notes,
        )
        for c in certs
    ]


def check_changes(entry: StoredCertificate, changes: EntryChanges) -> None:
    """F-02: marcar como confiable algo que no es raíz es un error (no se ignora en silencio)."""
    if changes.trusted and entry.kind is not CaKind.ROOT:
        raise UnprocessableInput("Sólo una raíz puede ser ancla de confianza")


def listing_order(entries: Iterable[StoredCertificate]) -> list[StoredCertificate]:
    """El orden en que se listan: primero las raíces, y cada grupo por sujeto."""
    return sorted(entries, key=lambda e: (e.kind is not CaKind.ROOT, e.certificate.subject))


def summarize(entries: Iterable[StoredCertificate], snapshot: TrustSnapshot) -> SourceSummary:
    entries = list(entries)
    return SourceSummary(
        total=len(entries),
        trusted_roots=len(snapshot.trusted_roots),
        intermediates=len(snapshot.intermediates),
        disabled=sum(not e.enabled for e in entries),
    )
