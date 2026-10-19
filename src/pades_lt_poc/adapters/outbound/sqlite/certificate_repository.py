"""`CertificateRepository` sobre SQLite: la fuente de certificados en un archivo.

El esquema está documentado en docs/pades.md (La base SQLite). Las restricciones de la base
repiten las reglas del dominio que se pueden expresar en SQL (huella única, tipos y orígenes
válidos, sólo una raíz puede ser confiable), como segunda línea de defensa.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from ....application.ports import CertificateCodec
from ....domain.certificates import CaKind
from ....domain.source import EntryChanges, NewEntry, Origin, StoredCertificate

SCHEMA = """
CREATE TABLE IF NOT EXISTS certificates (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256      TEXT    NOT NULL UNIQUE,
    der         BLOB    NOT NULL,
    kind        TEXT    NOT NULL CHECK (kind IN ('root', 'intermediate')),
    trusted     INTEGER NOT NULL DEFAULT 0,
    enabled     INTEGER NOT NULL DEFAULT 1,
    origin      TEXT    NOT NULL CHECK (origin IN ('seed', 'manual', 'pdf')),
    notes       TEXT    NOT NULL DEFAULT '',
    subject     TEXT    NOT NULL,
    issuer      TEXT    NOT NULL,
    not_before  TEXT    NOT NULL,
    not_after   TEXT    NOT NULL,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL,
    -- Sólo una raíz puede ser ancla de confianza.
    CHECK (kind = 'root' OR trusted = 0)
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

SEEDED_KEY = "seeded_at"


def _timestamp(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds")


class SqliteCertificateRepository:
    """Implementa `application.ports.CertificateRepository`.

    FastAPI atiende en varios hilos: una sola conexión, compartida y serializada con un lock.
    Cada operación que escribe es una transacción (`with self._db`).

    `subject`, `issuer` y la vigencia se guardan como columnas para poder consultar la base
    a mano con `sqlite3`; al leer, el certificado se reconstruye desde el DER con el codec.
    """

    def __init__(self, path: Path, codec: CertificateCodec) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.codec = codec
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock, self._db:
            self._db.executescript(SCHEMA)

    def close(self) -> None:
        self._db.close()

    # ----------------------------------------------------------------------- lectura
    def all(self) -> list[StoredCertificate]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM certificates ORDER BY id").fetchall()
        return [self._entry(r) for r in rows]

    def get(self, cert_id: int) -> StoredCertificate | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM certificates WHERE id = ?", (cert_id,)).fetchone()
        return self._entry(row) if row is not None else None

    # ----------------------------------------------------------------------- escritura
    def insert_missing(
        self, entries: Sequence[NewEntry], now: datetime
    ) -> tuple[list[StoredCertificate], list[StoredCertificate]]:
        with self._lock, self._db:
            return self._insert_missing(entries, now)

    def apply_initial_load(self, entries: Sequence[NewEntry], now: datetime) -> bool:
        # La carga y su marca en la misma transacción: si el proceso muere en el medio, no
        # queda ninguna de las dos y el próximo arranque la vuelve a aplicar entera.
        with self._lock, self._db:
            if self._db.execute("SELECT 1 FROM meta WHERE key = ?", (SEEDED_KEY,)).fetchone():
                return False
            self._insert_missing(entries, now)
            self._db.execute("INSERT INTO meta (key, value) VALUES (?, ?)", (SEEDED_KEY, _timestamp(now)))
        return True

    def update(self, cert_id: int, changes: EntryChanges, now: datetime) -> StoredCertificate | None:
        values = {k: v for k, v in {"enabled": changes.enabled, "trusted": changes.trusted, "notes": changes.notes}.items() if v is not None}
        with self._lock:
            if values:
                assignments = ", ".join(f"{k} = ?" for k in values)  # claves fijas, no vienen de afuera
                with self._db:
                    self._db.execute(
                        f"UPDATE certificates SET {assignments}, updated_at = ? WHERE id = ?",
                        (*values.values(), _timestamp(now), cert_id),
                    )
            return self.get(cert_id)

    def delete(self, cert_id: int) -> bool:
        with self._lock, self._db:
            return self._db.execute("DELETE FROM certificates WHERE id = ?", (cert_id,)).rowcount > 0

    # ----------------------------------------------------------------------- internos
    def _insert_missing(self, entries: Sequence[NewEntry], now: datetime) -> tuple[list[StoredCertificate], list[StoredCertificate]]:
        """Va dentro de la transacción de quien llama."""
        added, present = [], []
        for entry in entries:
            cert = entry.certificate
            row = self._db.execute("SELECT * FROM certificates WHERE sha256 = ?", (cert.sha256,)).fetchone()
            if row is not None:
                present.append(self._entry(row))
                continue
            cursor = self._db.execute(
                """INSERT INTO certificates (sha256, der, kind, trusted, enabled, origin, notes, subject, issuer,
                                             not_before, not_after, created_at, updated_at)
                   VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    cert.sha256,
                    cert.der,
                    entry.kind.value,
                    int(entry.trusted),
                    entry.origin.value,
                    entry.notes,
                    cert.subject,
                    cert.issuer,
                    cert.not_before.isoformat(),
                    cert.not_after.isoformat(),
                    _timestamp(now),
                    _timestamp(now),
                ),
            )
            row = self._db.execute("SELECT * FROM certificates WHERE id = ?", (cursor.lastrowid,)).fetchone()
            added.append(self._entry(row))
        return added, present

    def _entry(self, row: sqlite3.Row) -> StoredCertificate:
        [cert] = self.codec.parse(row["der"])
        return StoredCertificate(
            id=row["id"],
            certificate=cert,
            kind=CaKind(row["kind"]),
            trusted=bool(row["trusted"]),
            enabled=bool(row["enabled"]),
            origin=Origin(row["origin"]),
            notes=row["notes"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )
