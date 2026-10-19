"""Armado de cadenas (domain/chains.py) y la integridad de una firma. Python puro: certificados armados a mano.

`issued_by` es una tabla: quién firmó a quién.
"""

from datetime import UTC, datetime

import pytest

from pades_lt_poc.domain.certificates import Certificate
from pades_lt_poc.domain.chains import (
    ALTERED_DOCUMENT,
    CertSource,
    build_chain,
    candidate_pool,
    chain_for,
    http_ca_issuer_urls,
)
from pades_lt_poc.domain.signatures import CmsSignature, Integrity

T = datetime(2026, 10, 18, tzinfo=UTC)


def cert(name: str, *, self_signed: bool = False, aia: tuple[str, ...] | None = None) -> Certificate:
    return Certificate(
        der=name.encode(),
        sha256=name.encode().hex().ljust(64, "0"),
        sha1="00" * 20,
        subject=f"CN={name}",
        issuer="CN=?",
        serial_number=1,
        not_before=T,
        not_after=T,
        is_ca=name != "hoja",
        self_signed=self_signed,
        ca_issuer_urls=aia,
    )


LEAF, INTERMEDIATE, ROOT = cert("hoja"), cert("intermedia"), cert("raiz", self_signed=True)
OTHER_ROOT = cert("otra raiz", self_signed=True)
ISSUERS = {LEAF: INTERMEDIATE, INTERMEDIATE: ROOT, ROOT: ROOT}


def issued_by(c: Certificate, issuer: Certificate) -> bool:
    return ISSUERS.get(c) == issuer


OK = Integrity(True, True)


# --------------------------------------------------------------------------- C-02: pool y precedencia
def test_pool_puts_signer_first_and_keeps_first_origin():
    cms = CmsSignature(LEAF, (INTERMEDIATE,), OK)
    pool = candidate_pool(cms, [(INTERMEDIATE, CertSource.DSS), (ROOT, CertSource.DSS), (ROOT, CertSource.STORE)])
    assert pool == [(LEAF, CertSource.CMS), (INTERMEDIATE, CertSource.CMS), (ROOT, CertSource.DSS)]


def test_build_chain_climbs_to_a_self_signed():
    chain, errors = build_chain([(LEAF, CertSource.CMS), (ROOT, CertSource.STORE), (INTERMEDIATE, CertSource.DSS)], issued_by, None)
    assert chain == [(LEAF, CertSource.CMS), (INTERMEDIATE, CertSource.DSS), (ROOT, CertSource.STORE)]
    assert errors == []


def test_build_chain_stops_when_the_issuer_is_missing():
    chain, errors = build_chain([(LEAF, CertSource.CMS), (OTHER_ROOT, CertSource.STORE)], issued_by, None)
    assert chain == [(LEAF, CertSource.CMS)]
    assert errors == []  # sin búsqueda AIA no hay errores que informar


def test_build_chain_uses_lookup_only_for_what_the_pool_lacks():
    asked = []

    def lookup(c):
        asked.append(c)
        return [OTHER_ROOT, ROOT], ["http://x: ruido"]  # el error se ignora si se encontró al emisor

    chain, errors = build_chain([(LEAF, CertSource.CMS), (INTERMEDIATE, CertSource.DSS)], issued_by, lookup)
    assert chain == [(LEAF, CertSource.CMS), (INTERMEDIATE, CertSource.DSS), (ROOT, CertSource.AIA)]
    assert asked == [INTERMEDIATE]
    assert errors == []


def test_build_chain_reports_lookup_errors_when_the_issuer_is_not_found():
    chain, errors = build_chain([(LEAF, CertSource.CMS)], issued_by, lambda c: ([], ["http://x: 404"]))
    assert chain == [(LEAF, CertSource.CMS)]
    assert errors == ["http://x: 404"]

    _, errors = build_chain([(LEAF, CertSource.CMS)], issued_by, lambda c: ([OTHER_ROOT], []))
    assert errors == ["CN=hoja: AIA no trae a su emisor"]


def test_build_chain_does_not_loop():
    """Dos certificados que se emiten mutuamente no forman una cadena infinita."""
    a, b = cert("a"), cert("b")
    chain, _ = build_chain([(a, CertSource.CMS), (b, CertSource.CMS)], lambda c, i: {a: b, b: a}.get(c) == i, None)
    assert [c for c, _ in chain] == [a, b]


# --------------------------------------------------------------------------- C-01: integridad primero
@pytest.mark.parametrize(
    ("integrity", "message"),
    [
        (Integrity(False, True), ALTERED_DOCUMENT),
        (Integrity(True, False), "firma inválida"),
        (Integrity(False, False, "signer certificate not included in signature"), "signer certificate not included in signature"),
    ],
)
def test_chain_is_not_built_if_the_signature_does_not_verify(integrity, message):
    result = chain_for(CmsSignature(LEAF, (), integrity), [], ALTERED_DOCUMENT, issued_by, None, frozenset())
    assert (result.crypto_valid, result.links, result.chain_complete) == (False, None, None)
    assert (result.intact, result.valid, result.error) == (integrity.intact, integrity.valid, message)


def test_chain_marks_in_store_and_completeness():
    cms = CmsSignature(LEAF, (INTERMEDIATE,), OK)
    result = chain_for(cms, [(ROOT, CertSource.STORE)], ALTERED_DOCUMENT, issued_by, None, frozenset({ROOT.sha256}))
    assert result.crypto_valid and result.chain_complete
    assert [(l.certificate, l.source, l.in_store) for l in result.links] == [
        (LEAF, CertSource.CMS, False),
        (INTERMEDIATE, CertSource.CMS, False),
        (ROOT, CertSource.STORE, True),
    ]

    incomplete = chain_for(cms, [], ALTERED_DOCUMENT, issued_by, None, frozenset())
    assert incomplete.chain_complete is False


# --------------------------------------------------------------------------- C-03: URLs AIA
@pytest.mark.parametrize(
    ("aia", "urls", "problem"),
    [
        (None, [], "CN=hoja: no tiene AIA caIssuers"),
        ((), [], "CN=hoja: no tiene AIA caIssuers por HTTP"),
        (("ldap://x/ca", "HTTP://a/ca.crt", "https://b/ca.p7c"), ["HTTP://a/ca.crt", "https://b/ca.p7c"], None),
        (("ldap://x/ca",), [], "CN=hoja: no tiene AIA caIssuers por HTTP"),
    ],
)
def test_only_http_ca_issuers(aia, urls, problem):
    assert http_ca_issuer_urls(cert("hoja", aia=aia)) == (urls, problem)
