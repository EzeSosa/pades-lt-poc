"""Implementaciones en memoria de los puertos, para probar casos de uso sin infraestructura.

Cada fake cumple el mismo contrato que el adaptador real: los tests de contrato de cada puerto
corren contra los dos (p. ej. tests/test_certificate_repository.py).
"""

from __future__ import annotations

import threading
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from pades_lt_poc.domain.source import EntryChanges, NewEntry, SeedCertificate, StoredCertificate


class FixedClock:
    """Un reloj que no avanza solo: `advance()` lo mueve."""

    def __init__(self, moment: datetime = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)) -> None:
        self.moment = moment

    def now(self) -> datetime:
        return self.moment

    def advance(self, **delta) -> None:
        self.moment += timedelta(**delta)


class StaticSeedCatalog:
    def __init__(self, seeds: list[SeedCertificate]) -> None:
        self._seeds = list(seeds)

    def seeds(self) -> list[SeedCertificate]:
        return list(self._seeds)


class InMemoryCertificateRepository:
    """`CertificateRepository` en un dict. Atómico porque todo pasa bajo un lock y valida antes de escribir."""

    def __init__(self) -> None:
        self._entries: dict[int, StoredCertificate] = {}
        self._next_id = 1
        self._seeded = False
        self._lock = threading.Lock()
        self.reads = 0  # cuántas veces se llamó a all(), para los tests de carga

    def all(self) -> list[StoredCertificate]:
        with self._lock:
            self.reads += 1
            return list(self._entries.values())

    def get(self, cert_id: int) -> StoredCertificate | None:
        with self._lock:
            return self._entries.get(cert_id)

    def insert_missing(self, entries: Sequence[NewEntry], now: datetime):
        with self._lock:
            return self._insert_missing(entries, now)

    def apply_initial_load(self, entries: Sequence[NewEntry], now: datetime) -> bool:
        with self._lock:
            if self._seeded:
                return False
            self._insert_missing(entries, now)
            self._seeded = True
            return True

    def update(self, cert_id: int, changes: EntryChanges, now: datetime) -> StoredCertificate | None:
        with self._lock:
            entry = self._entries.get(cert_id)
            if entry is None or changes.is_empty():
                return entry
            values = {k: v for k, v in vars(changes).items() if v is not None}
            if values.get("trusted") and entry.kind.value != "root":
                raise ValueError("CHECK (kind = 'root' OR trusted = 0)")  # como la restricción de la base
            entry = replace(entry, **values, updated_at=now.replace(microsecond=0))
            self._entries[cert_id] = entry
            return entry

    def delete(self, cert_id: int) -> bool:
        with self._lock:
            return self._entries.pop(cert_id, None) is not None

    def _insert_missing(self, entries: Sequence[NewEntry], now: datetime):
        by_sha = {e.certificate.sha256: e for e in self._entries.values()}
        for entry in entries:  # validar todo antes de escribir: atómico
            if entry.trusted and entry.kind.value != "root":
                raise ValueError("CHECK (kind = 'root' OR trusted = 0)")
        added, present = [], []
        for entry in entries:
            existing = by_sha.get(entry.certificate.sha256)
            if existing is not None:
                present.append(existing)
                continue
            stored = StoredCertificate(
                id=self._next_id,
                certificate=entry.certificate,
                kind=entry.kind,
                trusted=entry.trusted,
                enabled=True,
                origin=entry.origin,
                notes=entry.notes,
                created_at=now.replace(microsecond=0),
                updated_at=now.replace(microsecond=0),
            )
            self._entries[stored.id] = stored
            by_sha[entry.certificate.sha256] = stored
            self._next_id += 1
            added.append(stored)
        return added, present
