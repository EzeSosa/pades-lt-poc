"""Contrato de `CertificateRepository`: los mismos tests contra SQLite y contra el fake en memoria."""

import sqlite3
from contextlib import closing
from datetime import UTC, datetime

import pytest

from fakes import InMemoryCertificateRepository
from pades_lt_poc.adapters.outbound.crypto.codec import CryptographyCertificateCodec
from pades_lt_poc.adapters.outbound.seed_catalog import SEED_DIR
from pades_lt_poc.adapters.outbound.sqlite.certificate_repository import SqliteCertificateRepository
from pades_lt_poc.domain.certificates import CaKind
from pades_lt_poc.domain.source import EntryChanges, NewEntry, Origin, new_entries

CODEC = CryptographyCertificateCodec()
T0 = datetime(2026, 10, 18, 12, 0, 0, 123456, tzinfo=UTC)
T1 = datetime(2026, 10, 19, 8, 30, 0, tzinfo=UTC)

[ROOT_2007] = CODEC.parse((SEED_DIR / "ac-raiz-argentina-2007.der").read_bytes())
[ROOT_2016] = CODEC.parse((SEED_DIR / "ac-raiz-argentina-2016.der").read_bytes())
[ONTI] = CODEC.parse((SEED_DIR / "ac-onti-firma-digital.der").read_bytes())


def entries(*certs, trusted=True, origin=Origin.MANUAL, notes=""):
    return new_entries(certs, trusted=trusted, notes=notes, origin=origin)


@pytest.fixture(params=["sqlite", "memory"])
def repo(request, tmp_path):
    if request.param == "memory":
        yield InMemoryCertificateRepository()
        return
    r = SqliteCertificateRepository(tmp_path / "certs.db", CODEC)
    yield r
    r.close()


# --------------------------------------------------------------------------- altas
def test_insert_missing_returns_added_and_present_in_order(repo):
    added, present = repo.insert_missing(entries(ROOT_2007, ONTI), T0)
    assert [e.certificate for e in added] == [ROOT_2007, ONTI]
    assert present == []

    added2, present2 = repo.insert_missing(entries(ONTI, ROOT_2016, ROOT_2007), T1)
    assert [e.certificate for e in added2] == [ROOT_2016]
    assert [e.id for e in present2] == [added[1].id, added[0].id]  # en el orden pedido; no se tocan
    assert present2[0].created_at == present2[0].updated_at == T0.replace(microsecond=0)


def test_inserted_entry_fields(repo):
    [root, onti], _ = repo.insert_missing(entries(ROOT_2007, ONTI, origin=Origin.PDF, notes="nota"), T0)
    assert (root.kind, root.trusted, root.enabled, root.origin, root.notes) == (CaKind.ROOT, True, True, Origin.PDF, "nota")
    assert (onti.kind, onti.trusted) == (CaKind.INTERMEDIATE, False)
    assert root.created_at == root.updated_at == T0.replace(microsecond=0)  # al segundo
    assert root.certificate == ROOT_2007 and root.certificate.subject == ROOT_2007.subject
    assert root.id != onti.id
    assert repo.get(root.id) == root
    assert repo.all() == [root, onti]  # en el orden en que se agregaron


def test_rejects_trusted_intermediate_atomically(repo):
    """La base no admite un intermedio confiable; si una entrada falla, no se agrega ninguna."""
    bad = NewEntry(ONTI, CaKind.INTERMEDIATE, trusted=True, origin=Origin.MANUAL, notes="")
    with pytest.raises(Exception):
        repo.insert_missing([*entries(ROOT_2007), bad], T0)
    assert repo.all() == []


# --------------------------------------------------------------------------- carga inicial
def test_initial_load_runs_once(repo):
    assert repo.apply_initial_load(entries(ROOT_2007, ONTI, origin=Origin.SEED), T0) is True
    [root, onti] = repo.all()
    repo.delete(onti.id)
    assert repo.apply_initial_load(entries(ROOT_2007, ONTI, origin=Origin.SEED), T1) is False
    assert repo.all() == [root]  # lo borrado queda borrado


def test_failed_initial_load_leaves_neither_certs_nor_mark(repo):
    """La carga y la marca van juntas: si algo falla, el próximo intento la aplica entera."""
    bad = NewEntry(ONTI, CaKind.INTERMEDIATE, trusted=True, origin=Origin.SEED, notes="")
    with pytest.raises(Exception):
        repo.apply_initial_load([*entries(ROOT_2007, origin=Origin.SEED), bad], T0)
    assert repo.all() == []
    assert repo.apply_initial_load(entries(ROOT_2007, ONTI, origin=Origin.SEED), T1) is True
    assert len(repo.all()) == 2


def test_sqlite_initial_load_survives_reopening(tmp_path):
    path = tmp_path / "certs.db"
    first = SqliteCertificateRepository(path, CODEC)
    first.apply_initial_load(entries(ROOT_2007, ONTI, origin=Origin.SEED), T0)
    first.delete(first.all()[0].id)
    first.close()

    reopened = SqliteCertificateRepository(path, CODEC)  # como al reiniciar la app
    assert reopened.apply_initial_load(entries(ROOT_2007, ONTI, origin=Origin.SEED), T1) is False
    assert [e.certificate for e in reopened.all()] == [ONTI]
    reopened.close()
    with closing(sqlite3.connect(path)) as db:
        assert db.execute("SELECT value FROM meta WHERE key = 'seeded_at'").fetchone() == ("2026-10-18T12:00:00+00:00",)


# --------------------------------------------------------------------------- cambios y bajas
def test_update_changes_only_given_fields(repo):
    [root], _ = repo.insert_missing(entries(ROOT_2007, notes="original"), T0)
    updated = repo.update(root.id, EntryChanges(enabled=False), T1)
    assert (updated.enabled, updated.trusted, updated.notes) == (False, True, "original")
    assert updated.created_at == T0.replace(microsecond=0) and updated.updated_at == T1
    updated = repo.update(root.id, EntryChanges(trusted=False, notes=""), T1)
    assert (updated.enabled, updated.trusted, updated.notes) == (False, False, "")
    assert repo.get(root.id) == updated


def test_update_without_changes_touches_nothing(repo):
    [root], _ = repo.insert_missing(entries(ROOT_2007), T0)
    assert repo.update(root.id, EntryChanges(), T1) == root


def test_update_and_delete_missing(repo):
    assert repo.update(999, EntryChanges(enabled=False), T1) is None
    assert repo.delete(999) is False
    assert repo.get(999) is None


def test_delete(repo):
    [root, onti], _ = repo.insert_missing(entries(ROOT_2007, ONTI), T0)
    assert repo.delete(root.id) is True
    assert repo.all() == [onti]
    [again], _ = repo.insert_missing(entries(ROOT_2007), T1)  # se puede volver a agregar
    assert again.id != root.id
