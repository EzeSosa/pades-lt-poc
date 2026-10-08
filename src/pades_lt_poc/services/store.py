"""Fuente de certificados: raíces e intermedios en SQLite, con su ABM.

Es lo que usa el validador además del PDF: las raíces marcadas como confiables son
las anclas de confianza de /verify, y los intermedios habilitados completan cadenas
(en /verify y en /certificates) cuando el PDF no los trae. Se carga en memoria al
arrancar y se vuelve a cargar después de cada cambio, sin reiniciar la app.

La copia en memoria es de cada proceso: con varios workers (o varias instancias sobre
la misma base), un cambio sólo llega al proceso que lo atendió hasta que los demás se
reinicien. La PoC corre con un solo worker.
"""

from __future__ import annotations

import base64
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .. import pki
from . import UnprocessableCertificate, UnprocessableInput
from .certificates import _issued_by
from .inspection import _is_ca, _load

DB_PATH = Path(os.environ.get("CERT_STORE_DB", pki.PKI_DIR.parent / "certs.db"))
SEED_DIR = Path(__file__).parent.parent / "seed"

# La carga inicial: se aplica una sola vez, al crear la base. Lo que se borre después queda borrado.
SEEDS = {
    "ac-raiz-argentina-2007.der": "AC Raíz de la Infraestructura de Firma Digital de Argentina (2007). Firma con SHA-1 a sus CAs.",
    "ac-raiz-argentina-2016.der": "AC Raíz de la Infraestructura de Firma Digital de Argentina (2016).",
    "ac-onti-firma-digital.der": "AC de Firma Digital de la ONTI, emitida por la AC Raíz 2007. Emite los certificados de CiDi.",
}

Origin = Literal["seed", "manual", "pdf"]

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


class CertificateNotFound(Exception):
    """No hay un certificado con ese id en la fuente."""


class DuplicateCertificate(Exception):
    """Todos los certificados recibidos ya estaban en la fuente."""


@dataclass(frozen=True)
class StoreSnapshot:
    """Lo que usa el validador, ya parseado. Sólo cuenta lo habilitado."""

    trusted_roots: tuple[asn1_x509.Certificate, ...]
    intermediates: tuple[asn1_x509.Certificate, ...]
    chain_certs: tuple[x509.Certificate, ...]  # raíces e intermedios, para armar cadenas en /certificates
    sha256: frozenset[str]  # todo lo que está en la fuente, habilitado o no


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _sha256(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


class CertificateStore:
    def __init__(self, path: Path = DB_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        # FastAPI atiende en varios hilos: una conexión compartida, serializada con un lock.
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock, self._db:
            self._db.executescript(SCHEMA)
            seeded = self._db.execute("SELECT 1 FROM meta WHERE key = 'seeded_at'").fetchone()
        if not seeded:
            self.restore_seed()
            with self._lock, self._db:
                self._db.execute("INSERT INTO meta (key, value) VALUES ('seeded_at', ?)", (_now(),))
        self._reload()

    def close(self) -> None:
        self._db.close()

    # ----------------------------------------------------------------------- lectura
    def snapshot(self) -> StoreSnapshot:
        return self._snapshot

    def list(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM certificates ORDER BY kind DESC, subject").fetchall()
        return [_row(r) for r in rows]

    def get(self, cert_id: int) -> dict:
        with self._lock:
            row = self._db.execute("SELECT * FROM certificates WHERE id = ?", (cert_id,)).fetchone()
        if row is None:
            raise CertificateNotFound(cert_id)
        return _row(row)

    # ----------------------------------------------------------------------- ABM
    def add(self, data: bytes, *, trusted: bool = False, notes: str = "", origin: Origin = "manual") -> dict:
        """Agrega los certificados de `data` (DER, PEM, PKCS#7 o base64).

        Sólo acepta CAs. Una raíz queda como ancla de confianza si `trusted`; un intermedio
        nunca. Devuelve los agregados y los que ya estaban; si ya estaban todos, falla.
        """
        certs = _load(data)
        not_ca = [c.subject.rfc4514_string() for c in certs if not _is_ca(c)]
        if not_ca:
            raise UnprocessableCertificate(
                f"La fuente sólo guarda raíces e intermedios (CAs), y esto no lo es: {'; '.join(not_ca)}"
            )
        added, present = [], []
        with self._lock, self._db:
            for cert in certs:
                row = self._db.execute("SELECT * FROM certificates WHERE sha256 = ?", (_sha256(cert),)).fetchone()
                if row is not None:
                    present.append(_row(row))
                    continue
                added.append(self._insert(cert, trusted=trusted, notes=notes, origin=origin))
        if not added:
            raise DuplicateCertificate([p["id"] for p in present])
        self._reload()
        return {"added": added, "already_present": present}

    def update(self, cert_id: int, *, enabled: bool | None = None, trusted: bool | None = None, notes: str | None = None) -> dict:
        current = self.get(cert_id)
        if trusted and current["kind"] != "root":
            raise UnprocessableInput("Sólo una raíz puede ser ancla de confianza")
        changes = {k: v for k, v in {"enabled": enabled, "trusted": trusted, "notes": notes}.items() if v is not None}
        if changes:
            assignments = ", ".join(f"{k} = ?" for k in changes)
            with self._lock, self._db:
                self._db.execute(
                    f"UPDATE certificates SET {assignments}, updated_at = ? WHERE id = ?",
                    (*changes.values(), _now(), cert_id),
                )
            self._reload()
        return self.get(cert_id)

    def delete(self, cert_id: int) -> None:
        with self._lock, self._db:
            deleted = self._db.execute("DELETE FROM certificates WHERE id = ?", (cert_id,)).rowcount
        if not deleted:
            raise CertificateNotFound(cert_id)
        self._reload()

    def restore_seed(self) -> list[dict]:
        """Vuelve a agregar los certificados de la carga inicial que falten (no toca los que están)."""
        added = []
        with self._lock, self._db:
            for name, notes in SEEDS.items():
                cert = x509.load_der_x509_certificate((SEED_DIR / name).read_bytes())
                exists = self._db.execute("SELECT 1 FROM certificates WHERE sha256 = ?", (_sha256(cert),)).fetchone()
                if not exists:
                    added.append(self._insert(cert, trusted=True, notes=notes, origin="seed"))
        self._reload()
        return added

    # ----------------------------------------------------------------------- internos
    def _insert(self, cert: x509.Certificate, *, trusted: bool, notes: str, origin: Origin) -> dict:
        kind = "root" if _issued_by(cert, cert) else "intermediate"
        now = _now()
        cursor = self._db.execute(
            """INSERT INTO certificates (sha256, der, kind, trusted, enabled, origin, notes, subject, issuer,
                                         not_before, not_after, created_at, updated_at)
               VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                _sha256(cert),
                cert.public_bytes(serialization.Encoding.DER),
                kind,
                int(trusted and kind == "root"),
                origin,
                notes,
                cert.subject.rfc4514_string(),
                cert.issuer.rfc4514_string(),
                cert.not_valid_before_utc.isoformat(),
                cert.not_valid_after_utc.isoformat(),
                now,
                now,
            ),
        )
        return _row(self._db.execute("SELECT * FROM certificates WHERE id = ?", (cursor.lastrowid,)).fetchone())

    def _reload(self) -> None:
        # Leer y asignar bajo el mismo lock: si no, con dos cambios a la vez la copia más
        # vieja puede quedar asignada última.
        with self._lock:
            rows = self._db.execute("SELECT sha256, der, kind, trusted, enabled FROM certificates").fetchall()
            enabled = [r for r in rows if r["enabled"]]
            self._snapshot = StoreSnapshot(
                trusted_roots=tuple(asn1_x509.Certificate.load(r["der"]) for r in enabled if r["trusted"]),
                intermediates=tuple(asn1_x509.Certificate.load(r["der"]) for r in enabled if r["kind"] == "intermediate"),
                chain_certs=tuple(x509.load_der_x509_certificate(r["der"]) for r in enabled),
                sha256=frozenset(r["sha256"] for r in rows),
            )


def _row(row: sqlite3.Row) -> dict:
    now = datetime.now(UTC)
    not_before, not_after = datetime.fromisoformat(row["not_before"]), datetime.fromisoformat(row["not_after"])
    return {
        "id": row["id"],
        "sha256": row["sha256"],
        "kind": row["kind"],
        "trusted": bool(row["trusted"]),
        "enabled": bool(row["enabled"]),
        "origin": row["origin"],
        "notes": row["notes"],
        "subject": row["subject"],
        "issuer": row["issuer"],
        "not_before": row["not_before"],
        "not_after": row["not_after"],
        "validity_status": "not_yet_valid" if now < not_before else "expired" if now > not_after else "valid",
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "der_b64": base64.b64encode(row["der"]).decode(),
    }
