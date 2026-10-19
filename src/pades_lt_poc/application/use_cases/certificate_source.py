"""Caso de uso: administrar la fuente de certificados y darle al validador su snapshot.

La fuente vive en un `CertificateRepository`. Para no leerlo en cada verificación, el caso de
uso guarda en memoria un `TrustSnapshot` y lo reemplaza entero después de cada cambio (F-05):
un cambio del ABM aplica enseguida, sin reiniciar.

La copia en memoria es de cada proceso: con varios workers (o varias instancias sobre la misma
base), un cambio sólo llega al proceso que lo atendió hasta que los demás se reinicien. La PoC
corre con un solo worker.
"""

from __future__ import annotations

import threading

from ...domain.certificates import CaKind
from ...domain.errors import CertificateNotFound, DuplicateCertificate
from ...domain.source import (
    EMPTY_SNAPSHOT,
    AddResult,
    EntryChanges,
    NewEntry,
    Origin,
    SourceSummary,
    StoredCertificate,
    TrustSnapshot,
    check_changes,
    listing_order,
    new_entries,
    summarize,
)
from ..ports import CertificateCodec, CertificateRepository, Clock, SeedCatalog


class CertificateSource:
    """Lectura, ABM y carga inicial de la fuente. Todos los métodos bloquean (usan el repositorio)."""

    def __init__(self, repository: CertificateRepository, codec: CertificateCodec, seeds: SeedCatalog, clock: Clock) -> None:
        self.repository = repository
        self.codec = codec
        self.seeds = seeds
        self.clock = clock
        self._snapshot = EMPTY_SNAPSHOT
        self._lock = threading.Lock()

    def initialize(self) -> None:
        """Aplica la carga inicial si nunca se aplicó (F-04) y carga el snapshot. Se llama una vez, al arrancar."""
        self.repository.apply_initial_load(self._seed_entries(), self.clock.now())
        self._reload()

    # ----------------------------------------------------------------------- lectura
    def snapshot(self) -> TrustSnapshot:
        """Lo que usa el validador. No bloquea: es la copia en memoria."""
        return self._snapshot

    def list(self, kind: CaKind | None = None) -> list[StoredCertificate]:
        """Las entradas (de un tipo, o todas): primero las raíces, y cada grupo por sujeto."""
        return [e for e in listing_order(self.repository.all()) if kind is None or e.kind is kind]

    def summary(self) -> SourceSummary:
        return summarize(self.repository.all(), self._snapshot)

    def get(self, cert_id: int) -> StoredCertificate:
        entry = self.repository.get(cert_id)
        if entry is None:
            raise CertificateNotFound(cert_id)
        return entry

    # ----------------------------------------------------------------------- ABM
    def add(self, data: bytes, *, trusted: bool = False, notes: str = "", origin: Origin = Origin.MANUAL) -> AddResult:
        """Agrega los certificados de `data` (DER, PEM, PKCS#7 o base64).

        Sólo CAs (F-01); `trusted` vale sólo para las raíces (F-02). Si todos ya estaban,
        lanza `DuplicateCertificate` con sus ids (F-03).
        """
        entries = new_entries(self.codec.parse(data), trusted=trusted, notes=notes, origin=origin)
        added, present = self.repository.insert_missing(entries, self.clock.now())
        if not added:
            raise DuplicateCertificate([p.id for p in present])
        self._reload()
        return AddResult(added=added, already_present=present)

    def update(self, cert_id: int, changes: EntryChanges) -> StoredCertificate:
        """Habilita o deshabilita, confía o deja de confiar (sólo raíces, F-02) o cambia las notas."""
        check_changes(self.get(cert_id), changes)
        if changes.is_empty():
            return self.get(cert_id)
        updated = self.repository.update(cert_id, changes, self.clock.now())
        if updated is None:  # se borró entre la lectura y el cambio
            raise CertificateNotFound(cert_id)
        self._reload()
        return updated

    def delete(self, cert_id: int) -> None:
        if not self.repository.delete(cert_id):
            raise CertificateNotFound(cert_id)
        self._reload()

    def restore_seed(self) -> list[StoredCertificate]:
        """Vuelve a agregar los certificados de la carga inicial que falten; no toca los que están (F-04)."""
        added, _present = self.repository.insert_missing(self._seed_entries(), self.clock.now())
        self._reload()
        return added

    # ----------------------------------------------------------------------- internos
    def _seed_entries(self) -> list[NewEntry]:
        # Las raíces de la carga inicial son confiables; su intermedio no puede serlo (F-02).
        entries = []
        for seed in self.seeds.seeds():
            entries += new_entries(self.codec.parse(seed.der), trusted=True, notes=seed.notes, origin=Origin.SEED)
        return entries

    def _reload(self) -> None:
        # Leer y asignar bajo el mismo lock: si no, con dos cambios a la vez la copia más
        # vieja puede quedar asignada última.
        with self._lock:
            self._snapshot = TrustSnapshot.from_entries(self.repository.all())
