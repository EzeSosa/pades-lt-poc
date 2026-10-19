"""Caso de uso `CertificateSource` con el repositorio en memoria y un reloj fijo: sin PKI, sin SQLite, sin HTTP."""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import pytest

from fakes import FixedClock, InMemoryCertificateRepository, StaticSeedCatalog
from pades_lt_poc.adapters.outbound.crypto.codec import CryptographyCertificateCodec
from pades_lt_poc.adapters.outbound.seed_catalog import SEED_DIR, PackagedSeedCatalog
from pades_lt_poc.application.use_cases.certificate_source import CertificateSource
from pades_lt_poc.domain.certificates import CaKind
from pades_lt_poc.domain.errors import CertificateNotFound, DuplicateCertificate, UnprocessableCertificate, UnprocessableInput
from pades_lt_poc.domain.source import EntryChanges, Origin, SeedCertificate

CODEC = CryptographyCertificateCodec()
ROOT_2007 = (SEED_DIR / "ac-raiz-argentina-2007.der").read_bytes()
ROOT_2016 = (SEED_DIR / "ac-raiz-argentina-2016.der").read_bytes()
ONTI = (SEED_DIR / "ac-onti-firma-digital.der").read_bytes()


def leaf_der() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Hoja")])
    clock = FixedClock()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(clock.now())
        .not_valid_after(clock.now())
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def repo():
    return InMemoryCertificateRepository()


@pytest.fixture
def clock():
    return FixedClock()


@pytest.fixture
def source(repo, clock):
    s = CertificateSource(repo, CODEC, PackagedSeedCatalog(), clock)
    s.initialize()
    return s


# --------------------------------------------------------------------------- carga inicial (F-04)
def test_initial_load(source):
    entries = source.list()
    assert {e.origin for e in entries} == {Origin.SEED}
    assert [(e.kind, e.trusted) for e in entries] == [
        (CaKind.ROOT, True),
        (CaKind.ROOT, True),
        (CaKind.INTERMEDIATE, False),  # la carga dice "confiable", pero un intermedio no puede serlo
    ]
    snapshot = source.snapshot()
    assert len(snapshot.trusted_roots) == 2 and len(snapshot.intermediates) == 1


def test_initialize_reads_the_source_once(repo, clock):
    s = CertificateSource(repo, CODEC, PackagedSeedCatalog(), clock)
    assert s.snapshot().known_sha256 == frozenset()  # antes de inicializar, vacía
    s.initialize()
    assert repo.reads == 1
    assert len(s.snapshot().known_sha256) == 3


def test_initial_load_runs_once_and_restore_adds_only_missing(repo, clock, source):
    onti = next(e for e in source.list() if e.kind is CaKind.INTERMEDIATE)
    source.delete(onti.id)

    again = CertificateSource(repo, CODEC, PackagedSeedCatalog(), clock)  # como al reiniciar
    again.initialize()
    assert len(again.list()) == 2  # lo borrado queda borrado

    [restored] = again.restore_seed()
    assert restored.certificate.der == ONTI
    assert again.restore_seed() == []


def test_a_seed_that_is_not_a_ca_fails_the_initial_load(repo, clock):
    s = CertificateSource(repo, CODEC, StaticSeedCatalog([SeedCertificate(leaf_der(), "")]), clock)
    with pytest.raises(UnprocessableCertificate):
        s.initialize()


# --------------------------------------------------------------------------- altas (F-01, F-02, F-03)
def test_add_uses_the_clock_and_updates_the_snapshot(source, clock):
    for e in source.list():
        source.delete(e.id)
    clock.advance(hours=1)
    result = source.add(ONTI, notes="x", origin=Origin.PDF)
    [entry] = result.added
    assert (entry.kind, entry.trusted, entry.origin, entry.notes) == (CaKind.INTERMEDIATE, False, Origin.PDF, "x")
    assert entry.created_at == clock.now()
    assert source.snapshot().intermediates == (entry.certificate,)  # F-05: aplica enseguida


def test_add_root_trusted_only_when_asked(source):
    for e in source.list():
        source.delete(e.id)
    [untrusted] = source.add(ROOT_2016).added
    assert untrusted.trusted is False and source.snapshot().trusted_roots == ()
    source.delete(untrusted.id)
    [trusted] = source.add(ROOT_2016, trusted=True).added
    assert trusted.trusted is True and source.snapshot().trusted_roots == (trusted.certificate,)


def test_f03_duplicates(source):
    with pytest.raises(DuplicateCertificate) as e:
        source.add(ONTI)
    [onti] = [x for x in source.list() if x.kind is CaKind.INTERMEDIATE]
    assert e.value.args[0] == [onti.id]


def test_f01_rejects_end_entity(source):
    with pytest.raises(UnprocessableCertificate, match="sólo guarda raíces e intermedios"):
        source.add(leaf_der())
    with pytest.raises(UnprocessableCertificate):
        source.add(b"no es un certificado")


# --------------------------------------------------------------------------- cambios y bajas (F-02, F-05)
def test_update_applies_immediately(source, clock):
    root = next(e for e in source.list() if e.kind is CaKind.ROOT)
    clock.advance(minutes=5)
    updated = source.update(root.id, EntryChanges(enabled=False, notes="en revisión"))
    assert (updated.enabled, updated.notes, updated.updated_at) == (False, "en revisión", clock.now())
    assert root.certificate not in source.snapshot().trusted_roots
    assert source.summary().disabled == 1

    source.update(root.id, EntryChanges(enabled=True, trusted=False))
    assert root.certificate not in source.snapshot().trusted_roots
    source.update(root.id, EntryChanges(trusted=True))
    assert root.certificate in source.snapshot().trusted_roots


def test_f02_cannot_trust_an_intermediate(source):
    onti = next(e for e in source.list() if e.kind is CaKind.INTERMEDIATE)
    with pytest.raises(UnprocessableInput):
        source.update(onti.id, EntryChanges(trusted=True))
    assert source.get(onti.id).trusted is False


def test_empty_update_returns_the_entry_untouched(source, clock):
    entry = source.list()[0]
    clock.advance(days=1)
    assert source.update(entry.id, EntryChanges()) == entry


def test_not_found(source):
    with pytest.raises(CertificateNotFound):
        source.get(999)
    with pytest.raises(CertificateNotFound):
        source.update(999, EntryChanges(enabled=False))
    with pytest.raises(CertificateNotFound):
        source.delete(999)


def test_list_filters_by_kind(source):
    assert {e.kind for e in source.list(CaKind.ROOT)} == {CaKind.ROOT}
    assert [e.certificate.der for e in source.list(CaKind.INTERMEDIATE)] == [ONTI]
