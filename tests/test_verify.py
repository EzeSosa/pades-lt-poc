"""Tests de POST /verify: anclas de confianza, hora de validación y análisis de modificaciones."""

import datetime as dt
from io import BytesIO

import pytest
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader

from conftest import load_signer, sign
from pades_lt_poc.services.store import SEED_DIR
from pades_lt_poc.services.verification import (
    CLAIMED_TIME_WARNING,
    UNALLOCATED_FREES_NOTE,
    LegacyRootsPolicy,
)

AC_RAIZ_2007 = load_cert_from_pemder(str(SEED_DIR / "ac-raiz-argentina-2007.der"))
AC_RAIZ_2016 = load_cert_from_pemder(str(SEED_DIR / "ac-raiz-argentina-2016.der"))
ONTI = load_cert_from_pemder(str(SEED_DIR / "ac-onti-firma-digital.der"))


def verify(client, pdf: bytes, **data):
    return client.post("/verify", files={"pdf": ("doc.pdf", pdf, "application/pdf")}, data=data)


# --------------------------------------------------------------------------- anclas
def test_verify_trusts_poc_root_and_both_ac_raiz(client):
    """La raíz de la PoC es implícita; las AC Raíz vienen de la carga inicial de la fuente."""
    roots = [c.dump() for c in client.app.state.verifier.trust_roots()]
    assert roots[0] == client.app.state.signer.trust_root.dump()
    assert AC_RAIZ_2007.dump() in roots
    assert AC_RAIZ_2016.dump() in roots
    assert ONTI.dump() not in roots  # un intermedio nunca es ancla de confianza


def test_sha1_exemption_only_for_roots_born_with_sha1(client):
    """La de 2007 firma con SHA-1; la de 2016, con SHA-512, no necesita la excepción."""
    legacy = client.app.state.verifier.algorithm_policy()._legacy_keys
    assert legacy == {AC_RAIZ_2007.public_key.dump()}


def test_sha1_allowed_only_for_legacy_root_key():
    """La AC Raíz firma con SHA-1 a la CA de la ONTI: se acepta para su clave y para ninguna otra."""
    policy = LegacyRootsPolicy([AC_RAIZ_2007])
    algo = ONTI["signature_algorithm"]
    assert algo.hash_algo == "sha1"

    assert policy.signature_algorithm_allowed(algo, None, AC_RAIZ_2007.public_key).allowed
    assert not policy.signature_algorithm_allowed(algo, None, AC_RAIZ_2016.public_key).allowed
    assert not policy.signature_algorithm_allowed(algo, None, ONTI.public_key).allowed
    assert not policy.signature_algorithm_allowed(algo, None, None).allowed


# --------------------------------------------------------------------------- hora de validación
def test_validates_now_by_default(client, pdf):
    before = dt.datetime.now(dt.UTC)
    r = verify(client, sign(pdf, load_signer()))
    assert r.status_code == 200
    body = r.json()

    assert body["validation_time"] == {"mode": "now", "warning": None}
    assert body["dss"] is None
    [sig] = body["signatures"]
    assert sig["trusted"] is False  # sin DSS no hay revocación: no confiable, pero sin 500
    assert sig["validated_at"]["source"] == "now"
    assert dt.datetime.fromisoformat(sig["validated_at"]["time"]) >= before


def test_claimed_signing_time_is_explicit_and_reported(client, pdf):
    signed = sign(pdf, load_signer())
    body = verify(client, signed, validation_time="claimed_signing_time").json()

    assert body["validation_time"] == {"mode": "claimed_signing_time", "warning": CLAIMED_TIME_WARNING}
    [sig] = body["signatures"]
    assert sig["validated_at"]["source"] == "claimed_signing_time"
    claimed = dt.datetime.fromisoformat(sig["validated_at"]["time"])
    assert abs(dt.datetime.now(dt.UTC) - claimed) < dt.timedelta(minutes=5)


@pytest.mark.parametrize("mode", ["signing_time", "NOW"])
def test_unknown_validation_time_is_rejected(client, pdf, mode):
    assert verify(client, sign(pdf, load_signer()), validation_time=mode).status_code == 422


# --------------------------------------------------------------------------- modificaciones
def with_free_entry(pdf: bytes, idnum: int, next_gen: int) -> bytes:
    """Agrega una revisión cuya xref sólo marca `idnum` como libre (`next_gen` f)."""
    reader = PdfFileReader(BytesIO(pdf))
    root = reader.trailer.raw_get("/Root")
    size = max(reader.trailer["/Size"], idnum + 1)
    update = b"xref\n%d 1\n0000000000 %05d f \n" % (idnum, next_gen)
    update += b"trailer\n<< /Size %d /Root %d %d R /Prev %d >>\n" % (size, root.idnum, root.generation, reader.last_startxref)
    update += b"startxref\n%d\n%%%%EOF\n" % len(pdf)
    return pdf + update


def test_unmodified_signature_reports_no_suspicious_changes(client, pdf):
    body = verify(client, sign(pdf, load_signer())).json()

    assert body["diff_policy"] == {"mode": "default", "note": None}
    [sig] = body["signatures"]
    assert sig["modifications"]["suspicious"] is None


def test_unallocated_free_entry_is_tolerated_only_when_asked(client, pdf):
    """iText marca como `65535 f` números de objeto nuevos que nunca escribe: no borra nada."""
    signed = sign(pdf, load_signer())
    size = PdfFileReader(BytesIO(signed)).trailer["/Size"]
    dead = with_free_entry(signed, idnum=size, next_gen=65535)

    [default] = verify(client, dead).json()["signatures"]
    assert "were freed" in default["modifications"]["suspicious"]

    body = verify(client, dead, diff_policy="allow_unallocated_free_entries").json()
    assert body["diff_policy"] == {"mode": "allow_unallocated_free_entries", "note": UNALLOCATED_FREES_NOTE}
    [lenient] = body["signatures"]
    assert lenient["modifications"]["suspicious"] is None
    assert lenient["modifications"]["level"] != "OTHER"


def test_freeing_an_existing_object_stays_suspicious(client, pdf):
    signed = sign(pdf, load_signer())
    freed = with_free_entry(signed, idnum=5, next_gen=1)  # 5 0 obj: la fuente de minimal_pdf

    [sig] = verify(client, freed, diff_policy="allow_unallocated_free_entries").json()["signatures"]
    assert "were freed" in sig["modifications"]["suspicious"]
    assert sig["bottom_line"] is False


def test_unknown_diff_policy_is_rejected(client, pdf):
    assert verify(client, sign(pdf, load_signer()), diff_policy="lenient").status_code == 422
