"""Reglas de la validación (domain/verification.py). Python puro: sin PDFs, sin pyHanko, sin PKI."""

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from pades_lt_poc.domain.certificates import Certificate
from pades_lt_poc.domain.errors import UnprocessableInput
from pades_lt_poc.domain.signatures import SignatureKind
from pades_lt_poc.domain.verification import (
    CLAIMED_TIME_WARNING,
    NO_PATH,
    ONLINE_NOTE,
    ONLINE_REASONS,
    REASONS,
    UNALLOCATED_FREES_NOTE,
    DiffPolicyMode,
    Modifications,
    PadesLevel,
    PathAttempt,
    RevocationMode,
    SignatureEvaluation,
    SignatureVerdict,
    TimestampEvaluation,
    TrustReason,
    ValidationTimeMode,
    VerificationOptions,
    completed_from_store,
    legacy_sha1_roots,
    pades_level,
    trust_anchors,
    trust_problem,
    validation_moment,
)

T = datetime(2026, 10, 18, 12, tzinfo=UTC)
CLAIMED = datetime(2025, 1, 1, tzinfo=UTC)


def cert(name: str, hash_algo: str | None = "sha256") -> Certificate:
    return Certificate(
        der=name.encode(),
        sha256=name.encode().hex().ljust(64, "0"),
        sha1="00" * 20,
        subject=f"CN={name}",
        issuer="CN=?",
        serial_number=1,
        not_before=T,
        not_after=T,
        is_ca=True,
        self_signed=False,
        signature_hash_algorithm=hash_algo,
    )


# --------------------------------------------------------------------------- V-04 y notas
def test_v04_online_only_now():
    VerificationOptions(revocation=RevocationMode.ONLINE).check()
    VerificationOptions(validation_time=ValidationTimeMode.CLAIMED_SIGNING_TIME).check()
    with pytest.raises(UnprocessableInput, match="Con conexión sólo se valida a la hora actual"):
        VerificationOptions(ValidationTimeMode.CLAIMED_SIGNING_TIME, revocation=RevocationMode.ONLINE).check()


def test_notes_depend_on_the_options():
    default = VerificationOptions()
    assert (default.warning, default.diff_policy_note, default.revocation_note) == (None, None, None)
    opts = VerificationOptions(ValidationTimeMode.CLAIMED_SIGNING_TIME, DiffPolicyMode.ALLOW_UNALLOCATED_FREE_ENTRIES)
    assert (opts.warning, opts.diff_policy_note) == (CLAIMED_TIME_WARNING, UNALLOCATED_FREES_NOTE)
    assert VerificationOptions(revocation=RevocationMode.ONLINE).revocation_note == ONLINE_NOTE


# --------------------------------------------------------------------------- V-01, V-02
def test_v01_implicit_anchors_first():
    poc, a, b = cert("poc"), cert("a"), cert("b")
    assert trust_anchors([poc], (a, b)) == (poc, a, b)


def test_v02_only_anchors_born_with_sha1():
    old, new, unknown = cert("2007", "sha1"), cert("2016", "sha512"), cert("ed", None)
    assert legacy_sha1_roots([old, new, unknown]) == (old,)


# --------------------------------------------------------------------------- V-08
def test_v08_validation_moment():
    now_mode = validation_moment(ValidationTimeMode.NOW, CLAIMED, T)
    assert (now_mode.time, now_mode.source, now_mode.in_the_past) == (T, ValidationTimeMode.NOW, False)
    claimed = validation_moment(ValidationTimeMode.CLAIMED_SIGNING_TIME, CLAIMED, T)
    assert (claimed.time, claimed.source, claimed.in_the_past) == (CLAIMED, ValidationTimeMode.CLAIMED_SIGNING_TIME, True)
    # Si la firma no declara hora, se valida a la actual y se dice.
    undeclared = validation_moment(ValidationTimeMode.CLAIMED_SIGNING_TIME, None, T)
    assert (undeclared.time, undeclared.source) == (T, ValidationTimeMode.NOW)


# --------------------------------------------------------------------------- V-09: por qué no es confiable
def attempt(reason: TrustReason | None) -> PathAttempt:
    return PathAttempt((cert("hoja"), cert("raiz")), reason, None if reason is None else "msg")


def problem(attempts=(), *, trusted=False, valid=True, validated_now=True, online=False):
    return trust_problem(
        trusted=trusted, valid=valid, indication="CHAIN_CONSTRAINTS_FAILURE", attempts=attempts,
        validated_now=validated_now, online=online,
    )


def test_v09_no_problem_if_trusted():
    assert problem([attempt(TrustReason.REVOKED)], trusted=True) is None


def test_not_evaluated_if_the_signature_does_not_verify():
    p = problem([attempt(TrustReason.REVOKED)], valid=False)
    assert (p.reason, p.paths, p.hint) == (TrustReason.NOT_EVALUATED, (), None)
    assert p.indication == "CHAIN_CONSTRAINTS_FAILURE"


def test_no_path():
    p = problem([])
    assert (p.reason, p.summary, p.hint) == (TrustReason.NO_PATH, *NO_PATH)


def test_a_path_that_validates_means_the_problem_is_elsewhere():
    p = problem([attempt(TrustReason.EXPIRED), attempt(None)])
    assert p.reason is TrustReason.OTHER and len(p.paths) == 2


def test_the_most_informative_reason_wins():
    """Una CA renovada deja un camino vencido (la versión vieja) y otro revocado: el resumen es el revocado."""
    p = problem([attempt(TrustReason.EXPIRED), attempt(TrustReason.REVOKED)])
    assert (p.reason, p.summary) == (TrustReason.REVOKED, REASONS[TrustReason.REVOKED])
    assert [a.reason for a in p.paths] == [TrustReason.EXPIRED, TrustReason.REVOKED]  # todos, en orden


@pytest.mark.parametrize(
    ("reason", "validated_now", "online", "hint"),
    [
        (TrustReason.MISSING_REVOCATION, True, False, "Probá validar con conexión, que descarga CRL y OCSP actualizadas."),
        (TrustReason.STALE_REVOCATION, True, False, "Probá validar con conexión, que descarga CRL y OCSP actualizadas o a la hora declarada por la firma."),
        (TrustReason.STALE_REVOCATION, False, False, "Probá validar con conexión, que descarga CRL y OCSP actualizadas."),
        (TrustReason.MISSING_REVOCATION, True, True, None),  # con conexión ya se intentó
        (TrustReason.EXPIRED, True, False, "Se validó a la hora actual: probá validar a la hora declarada por la firma."),
        (TrustReason.EXPIRED, False, False, None),
        (TrustReason.REVOKED, True, False, None),
    ],
)
def test_hints(reason, validated_now, online, hint):
    assert problem([attempt(reason)], validated_now=validated_now, online=online).hint == hint


def test_online_summaries_for_revocation():
    for reason in (TrustReason.STALE_REVOCATION, TrustReason.MISSING_REVOCATION):
        assert problem([attempt(reason)], online=True).summary == ONLINE_REASONS[reason]
        assert problem([attempt(reason)], online=False).summary == REASONS[reason]
    assert problem([attempt(TrustReason.REVOKED)], online=True).summary == REASONS[TrustReason.REVOKED]


# --------------------------------------------------------------------------- V-06
def test_v06_completed_from_store():
    in_pdf, from_store, downloaded = cert("pdf"), cert("fuente"), cert("aia")
    embedded = frozenset({in_pdf.sha256})
    store = frozenset({from_store.sha256, in_pdf.sha256})
    path = [in_pdf, from_store, downloaded]
    assert completed_from_store(True, path, embedded, store) == (from_store,)
    assert completed_from_store(False, path, embedded, store) == ()  # si no es confiable, no se le atribuye


# --------------------------------------------------------------------------- V-05, V-07
def evaluation(*, timestamp=True, bottom_line=True) -> SignatureEvaluation:
    ts = TimestampEvaluation(T, cert("tsa"), True, True, None, (), ()) if timestamp else None
    return SignatureEvaluation(
        "/ETSI.CAdES.detached", cert("firmante"), bottom_line, True, True, True, None, (), "ENTIRE_REVISION", (),
        Modifications(None, None, None), "", ts,
    )


def sig(**kwargs) -> SignatureVerdict:
    return SignatureVerdict("Firma", SignatureKind.SIGNATURE, evaluation(**kwargs), None, None, (), None)


DOC_TS = SignatureVerdict("TS", SignatureKind.DOC_TIMESTAMP, None, None, None, (), None)


@pytest.mark.parametrize(
    ("verdicts", "has_dss", "self_contained", "online", "level"),
    [
        ([sig(timestamp=False)], True, True, False, PadesLevel.B_B),
        ([sig(), sig(timestamp=False)], True, True, False, PadesLevel.B_B),  # todas tienen que tener sello
        ([sig()], False, True, False, PadesLevel.B_T),  # sin DSS
        ([sig(bottom_line=False)], True, True, False, PadesLevel.B_T),  # alguna no valida
        ([sig()], True, True, False, PadesLevel.B_LT),
        ([sig(), DOC_TS], True, True, False, PadesLevel.B_LTA),
        ([sig()], True, False, False, PadesLevel.B_T),  # V-05: se completó con la fuente
        ([sig(), DOC_TS], True, True, True, PadesLevel.B_T),  # V-05: con conexión
        ([DOC_TS], True, True, False, PadesLevel.B_B),  # sin firmas, sólo un sello de documento
    ],
)
def test_pades_level(verdicts, has_dss, self_contained, online, level):
    assert pades_level(verdicts, has_dss, self_contained, online) is level


def test_used_store_counts_the_timestamp_too():
    from pades_lt_poc.domain.verification import TimestampVerdict

    plain = sig()
    assert not plain.used_store
    assert replace(plain, completed_from_store=(cert("x"),)).used_store
    ts = TimestampVerdict(plain.evaluation.timestamp, None, (cert("x"),))
    assert replace(plain, timestamp=ts).used_store
