"""Reglas de la fuente de certificados (domain/source.py). Python puro: certificados armados a mano."""

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from pades_lt_poc.domain.certificates import CaKind, Certificate
from pades_lt_poc.domain.errors import UnprocessableCertificate, UnprocessableInput
from pades_lt_poc.domain.source import (
    EntryChanges,
    Origin,
    StoredCertificate,
    TrustSnapshot,
    check_changes,
    listing_order,
    new_entries,
    summarize,
)

T = datetime(2026, 10, 18, tzinfo=UTC)


def cert(name: str, *, is_ca: bool = True, self_signed: bool = False) -> Certificate:
    return Certificate(
        der=name.encode(),
        sha256=name.encode().hex().ljust(64, "0"),
        sha1="00" * 20,
        subject=f"CN={name}",
        issuer="CN=Emisor",
        serial_number=1,
        not_before=T,
        not_after=T,
        is_ca=is_ca,
        self_signed=self_signed,
    )


ROOT = cert("Raiz", self_signed=True)
INTERMEDIATE = cert("Intermedia")
LEAF = cert("Hoja", is_ca=False)


def stored(c: Certificate, id: int = 1, **changes) -> StoredCertificate:
    base = StoredCertificate(
        id=id,
        certificate=c,
        kind=c.ca_kind,
        trusted=False,
        enabled=True,
        origin=Origin.MANUAL,
        notes="",
        created_at=T,
        updated_at=T,
    )
    return replace(base, **changes)


# --------------------------------------------------------------------------- F-01 y F-02 al agregar
def test_f01_only_cas_and_nothing_is_added_if_one_is_not():
    with pytest.raises(UnprocessableCertificate) as e:
        new_entries([ROOT, LEAF], trusted=True, notes="", origin=Origin.MANUAL)
    assert str(e.value) == "La fuente sólo guarda raíces e intermedios (CAs), y esto no lo es: CN=Hoja"


def test_f02_trusted_applies_only_to_roots_when_adding():
    root, intermediate = new_entries([ROOT, INTERMEDIATE], trusted=True, notes="n", origin=Origin.PDF)
    assert (root.kind, root.trusted) == (CaKind.ROOT, True)
    assert (intermediate.kind, intermediate.trusted) == (CaKind.INTERMEDIATE, False)  # en silencio: no es un error
    assert {root.origin, intermediate.origin} == {Origin.PDF}
    assert {root.notes, intermediate.notes} == {"n"}

    [untrusted] = new_entries([ROOT], trusted=False, notes="", origin=Origin.MANUAL)
    assert untrusted.trusted is False


# --------------------------------------------------------------------------- F-02 al cambiar
def test_f02_trusting_an_intermediate_is_an_error():
    with pytest.raises(UnprocessableInput, match="Sólo una raíz puede ser ancla de confianza"):
        check_changes(stored(INTERMEDIATE), EntryChanges(trusted=True))


@pytest.mark.parametrize(
    ("entry", "changes"),
    [
        (stored(ROOT), EntryChanges(trusted=True)),
        (stored(INTERMEDIATE), EntryChanges(trusted=False)),  # dejar de confiar siempre se puede
        (stored(INTERMEDIATE), EntryChanges(enabled=False, notes="x")),
    ],
)
def test_f02_allowed_changes(entry, changes):
    check_changes(entry, changes)


def test_entry_changes_empty():
    assert EntryChanges().is_empty()
    assert not EntryChanges(notes="").is_empty()  # notas vacías también es un cambio


# --------------------------------------------------------------------------- F-05 y F-06: snapshot
def test_f06_snapshot_uses_only_enabled_but_knows_everything():
    entries = [
        stored(ROOT, 1, trusted=True),
        stored(cert("Raiz no confiable", self_signed=True), 2),
        stored(INTERMEDIATE, 3),
        stored(cert("Raiz deshabilitada", self_signed=True), 4, trusted=True, enabled=False),
        stored(cert("Intermedia deshabilitada"), 5, enabled=False),
    ]
    snapshot = TrustSnapshot.from_entries(entries)
    assert snapshot.trusted_roots == (ROOT,)
    assert snapshot.intermediates == (INTERMEDIATE,)
    assert [c.subject for c in snapshot.chain_certs] == ["CN=Raiz", "CN=Raiz no confiable", "CN=Intermedia"]
    assert snapshot.known_sha256 == {e.certificate.sha256 for e in entries}
    assert snapshot.contains(entries[4].certificate)


def test_snapshot_keeps_the_order_of_the_entries():
    roots = [cert(f"R{i}", self_signed=True) for i in range(3)]
    snapshot = TrustSnapshot.from_entries([stored(c, i, trusted=True) for i, c in enumerate(reversed(roots))])
    assert snapshot.trusted_roots == tuple(reversed(roots))


# --------------------------------------------------------------------------- listado y resumen
def test_listing_order_roots_first_then_by_subject():
    entries = [stored(cert("B")), stored(cert("Z", self_signed=True)), stored(cert("A")), stored(cert("M", self_signed=True))]
    assert [e.certificate.subject for e in listing_order(entries)] == ["CN=M", "CN=Z", "CN=A", "CN=B"]


def test_summary_counts_what_the_validator_uses():
    entries = [
        stored(ROOT, 1, trusted=True),
        stored(INTERMEDIATE, 2),
        stored(cert("Otra", self_signed=True), 3, trusted=True, enabled=False),
    ]
    summary = summarize(entries, TrustSnapshot.from_entries(entries))
    assert (summary.total, summary.trusted_roots, summary.intermediates, summary.disabled) == (3, 1, 1, 1)
