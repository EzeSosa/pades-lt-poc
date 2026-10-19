"""Caso de uso `VerifySignatures` con un validador falso: qué política arma, qué pide y cómo junta el resultado."""

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import pytest

from fakes import FixedClock, InMemoryCertificateRepository, StaticSeedCatalog
from pades_lt_poc.adapters.outbound.crypto.codec import CryptographyCertificateCodec
from pades_lt_poc.adapters.outbound.seed_catalog import SEED_DIR
from pades_lt_poc.application.ports import SignatureRef
from pades_lt_poc.application.use_cases.certificate_source import CertificateSource
from pades_lt_poc.application.use_cases.verify_signatures import VerifySignatures
from pades_lt_poc.domain.errors import UnprocessableInput
from pades_lt_poc.domain.signatures import SignatureKind
from pades_lt_poc.domain.source import SeedCertificate
from pades_lt_poc.domain.verification import (
    DssSummary,
    Modifications,
    PadesLevel,
    RevocationMode,
    SignatureEvaluation,
    TimestampEvaluation,
    TrustReason,
    ValidationTimeMode,
    VerificationOptions,
)

CODEC = CryptographyCertificateCodec()
SEEDS = [SeedCertificate((SEED_DIR / f).read_bytes(), "") for f in ("ac-raiz-argentina-2007.der", "ac-raiz-argentina-2016.der", "ac-onti-firma-digital.der")]
[ROOT_2007] = CODEC.parse(SEEDS[0].der)
[ROOT_2016] = CODEC.parse(SEEDS[1].der)
[ONTI] = CODEC.parse(SEEDS[2].der)
CLOCK = FixedClock()
CLAIMED = datetime(2025, 1, 1, tzinfo=UTC)


def evaluation(*, trusted=True, path=(), ts=True) -> SignatureEvaluation:
    timestamp = TimestampEvaluation(CLOCK.now(), ONTI, True, True, None, (), ()) if ts else None
    return SignatureEvaluation(
        "/ETSI.CAdES.detached", ONTI, trusted, True, True, trusted, None if trusted else "X", (), "ENTIRE_REVISION",
        tuple(path), Modifications("NONE", True, None), "detalle", timestamp,
    )


class FakeSession:
    def __init__(self, refs, evaluations, dss=DssSummary(5, 2, 1), embedded=frozenset()):
        self.signatures = tuple(refs)
        self.dss = dss
        self.embedded_sha256 = embedded
        self._evaluations = evaluations
        self.asked_claimed = []
        self.evaluated_at = []

    def claimed_signing_time(self, ref):
        self.asked_claimed.append(ref.index)
        return CLAIMED

    async def evaluate(self, ref, at):
        self.evaluated_at.append(at)
        return self._evaluations[ref.index]

    def fetched(self):
        return None


class FakeValidator:
    def __init__(self, session):
        self.session = session
        self.policy = None
        self.opened = False

    @asynccontextmanager
    async def open(self, pdf, policy):
        self.opened, self.policy = True, policy
        yield self.session


def source(*seeds) -> CertificateSource:
    s = CertificateSource(InMemoryCertificateRepository(), CODEC, StaticSeedCatalog(list(seeds)), CLOCK)
    s.initialize()
    return s


SIG = SignatureRef(0, "Firma1", SignatureKind.SIGNATURE)
DOC_TS = SignatureRef(1, "TS", SignatureKind.DOC_TIMESTAMP)


def run(validator, src=None, options=VerificationOptions(), implicit=()):
    use_case = VerifySignatures(validator, src or source(*SEEDS), implicit, CLOCK)
    return asyncio.run(use_case.verify(b"pdf", options))


def test_policy_from_the_snapshot_and_implicit_anchors():
    validator = FakeValidator(FakeSession([SIG], [evaluation()]))
    report = run(validator, implicit=[ROOT_2016])
    policy = validator.policy
    assert policy.trust_anchors[0] == ROOT_2016  # V-01: la implícita primero
    assert set(policy.trust_anchors) == {ROOT_2016, ROOT_2007}
    assert policy.intermediates == (ONTI,)
    assert policy.legacy_sha1_roots == (ROOT_2007,)  # V-02
    assert policy.online is False
    assert (report.trust_anchors, report.intermediates) == (3, 1)  # la implícita cuenta, aunque también esté en la fuente


def test_v04_is_checked_before_opening_the_pdf():
    validator = FakeValidator(FakeSession([SIG], [evaluation()]))
    with pytest.raises(UnprocessableInput):
        run(validator, options=VerificationOptions(ValidationTimeMode.CLAIMED_SIGNING_TIME, revocation=RevocationMode.ONLINE))
    assert not validator.opened


def test_claimed_time_is_read_only_when_asked():
    session = FakeSession([SIG], [evaluation()])
    run(FakeValidator(session))
    assert session.asked_claimed == [] and session.evaluated_at[0].time == CLOCK.now()

    session = FakeSession([SIG], [evaluation()])
    report = run(FakeValidator(session), options=VerificationOptions(ValidationTimeMode.CLAIMED_SIGNING_TIME))
    assert session.asked_claimed == [0]
    assert session.evaluated_at[0].in_the_past
    assert report.signatures[0].validated_at.time == CLAIMED


def test_doc_timestamps_are_listed_not_evaluated():
    session = FakeSession([SIG, DOC_TS], [evaluation(), None])
    report = run(FakeValidator(session))
    assert [v.kind for v in report.signatures] == [SignatureKind.SIGNATURE, SignatureKind.DOC_TIMESTAMP]
    assert report.signatures[1].evaluation is None
    assert len(session.evaluated_at) == 1
    assert report.pades_level is PadesLevel.B_LTA


def test_completed_from_store_makes_the_pdf_not_self_contained():
    """V-06 y V-05: la cadena se completó con ONTI, que está en la fuente y no en el PDF."""
    session = FakeSession([SIG], [evaluation(path=[ONTI])])
    report = run(FakeValidator(session))
    assert report.signatures[0].completed_from_store == (ONTI,)
    assert report.self_contained is False and report.store_note
    assert report.pades_level is PadesLevel.B_T

    in_pdf = FakeSession([SIG], [evaluation(path=[ONTI])], embedded=frozenset({ONTI.sha256}))
    report = run(FakeValidator(in_pdf))
    assert report.signatures[0].completed_from_store == () and report.self_contained
    assert report.pades_level is PadesLevel.B_LT


def test_untrusted_signature_gets_a_trust_problem():
    report = run(FakeValidator(FakeSession([SIG], [evaluation(trusted=False)])))
    verdict = report.signatures[0]
    assert verdict.trust_problem.reason is TrustReason.NO_PATH  # sin caminos probados
    assert verdict.timestamp.trust_problem is None  # el sello sí es confiable
    assert report.pades_level is PadesLevel.B_T  # no valida: no llega a LT


def test_without_dss_no_lt():
    report = run(FakeValidator(FakeSession([SIG], [evaluation()], dss=None)))
    assert report.dss is None and report.pades_level is PadesLevel.B_T
