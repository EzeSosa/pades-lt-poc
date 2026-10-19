"""Caso de uso `ExtractCertificateChains` con un lector de PDFs y un fetcher AIA falsos: sin PDF, sin red.

Los certificados son los de la carga inicial (AC Raíz 2007 -> AC ONTI) más uno armado acá.
"""

from datetime import UTC, datetime

import pytest

from fakes import FixedClock, InMemoryCertificateRepository, StaticSeedCatalog
from pades_lt_poc.adapters.outbound.crypto.codec import CryptographyCertificateCodec
from pades_lt_poc.adapters.outbound.seed_catalog import SEED_DIR
from pades_lt_poc.application.ports import IssuerFetchError
from pades_lt_poc.application.use_cases.certificate_chains import ExtractCertificateChains
from pades_lt_poc.application.use_cases.certificate_source import CertificateSource
from pades_lt_poc.domain.chains import CertSource
from pades_lt_poc.domain.signatures import (
    CmsSignature,
    EmbeddedSignature,
    Integrity,
    SignatureKind,
    SignedDocument,
    TimestampToken,
)
from pades_lt_poc.domain.source import SeedCertificate

CODEC = CryptographyCertificateCodec()
[ROOT] = CODEC.parse((SEED_DIR / "ac-raiz-argentina-2007.der").read_bytes())
[ONTI] = CODEC.parse((SEED_DIR / "ac-onti-firma-digital.der").read_bytes())
OK = Integrity(True, True)
T = datetime(2026, 10, 18, 12, tzinfo=UTC)


class FakeReader:
    def __init__(self, document: SignedDocument) -> None:
        self.document = document

    def read(self, pdf: bytes) -> SignedDocument:
        return self.document


class FakeFetcher:
    def __init__(self, published: dict[str, list] | None = None) -> None:
        self.published = published or {}
        self.calls: list[str] = []

    def fetch(self, url):
        self.calls.append(url)
        if url not in self.published:
            raise IssuerFetchError("404 Not Found")
        return self.published[url]


def source(*ders: bytes) -> CertificateSource:
    s = CertificateSource(
        InMemoryCertificateRepository(), CODEC, StaticSeedCatalog([SeedCertificate(d, "") for d in ders]), FixedClock()
    )
    s.initialize()
    return s


def signature(cms: CmsSignature, timestamp=None, kind=SignatureKind.SIGNATURE, field="Firma1") -> EmbeddedSignature:
    return EmbeddedSignature(field, kind, cms, timestamp)


def use_case(document, fetcher=None, store=None) -> ExtractCertificateChains:
    return ExtractCertificateChains(FakeReader(document), CODEC, store or source(), fetcher or FakeFetcher())


def test_chain_from_cms_and_dss():
    doc = SignedDocument((signature(CmsSignature(ONTI, (), OK)),), dss_certificates=(ROOT,))
    [result] = use_case(doc).extract(b"pdf", fetch_missing=False)
    assert [(l.certificate, l.source) for l in result.chain.links] == [(ONTI, CertSource.CMS), (ROOT, CertSource.DSS)]
    assert result.chain.chain_complete is True
    assert result.timestamp is None


def test_store_completes_and_marks_in_store():
    doc = SignedDocument((signature(CmsSignature(ONTI, (), OK)),), ())
    [result] = use_case(doc, store=source((SEED_DIR / "ac-raiz-argentina-2007.der").read_bytes())).extract(b"pdf", False)
    assert [(l.source, l.in_store) for l in result.chain.links] == [(CertSource.CMS, False), (CertSource.STORE, True)]


def test_aia_only_when_asked_and_cached_per_request():
    """Dos firmas de la misma CA: el emisor se descarga una sola vez."""
    [url] = ONTI.ca_issuer_urls  # la AC ONTI publica a su emisor por HTTP
    fetcher = FakeFetcher({url: [ROOT]})
    doc = SignedDocument((signature(CmsSignature(ONTI, (), OK)), signature(CmsSignature(ONTI, (), OK), field="Firma2")), ())

    without = use_case(doc, fetcher).extract(b"pdf", fetch_missing=False)
    assert [len(r.chain.links) for r in without] == [1, 1] and fetcher.calls == []

    results = use_case(doc, fetcher).extract(b"pdf", fetch_missing=True)
    for r in results:
        assert [(l.certificate, l.source) for l in r.chain.links] == [(ONTI, CertSource.CMS), (ROOT, CertSource.AIA)]
        assert r.chain.aia_errors == ()
    assert fetcher.calls == [url]


def test_aia_errors_are_reported_with_the_url():
    [url] = ONTI.ca_issuer_urls
    doc = SignedDocument((signature(CmsSignature(ONTI, (), OK)),), ())
    [result] = use_case(doc, FakeFetcher()).extract(b"pdf", fetch_missing=True)
    assert result.chain.chain_complete is False
    assert result.chain.aia_errors == (f"{url}: 404 Not Found",)


def test_timestamp_chain_uses_the_signature_cms_certs():
    """La cadena de la TSA se completa con los certificados del CMS de la firma (C-02)."""
    token = TimestampToken(T, CmsSignature(ONTI, (), OK))
    doc = SignedDocument((signature(CmsSignature(ONTI, (ROOT,), OK), token),), ())
    [result] = use_case(doc).extract(b"pdf", False)
    assert result.timestamp.time == T
    assert [(l.certificate, l.source) for l in result.timestamp.chain.links] == [(ONTI, CertSource.CMS), (ROOT, CertSource.CMS)]


def test_no_timestamp_chain_if_the_signature_does_not_verify():
    """C-01: si la firma no verifica, su sello no se analiza."""
    token = TimestampToken(T, CmsSignature(ONTI, (), OK))
    doc = SignedDocument((signature(CmsSignature(ONTI, (), Integrity(False, True)), token),), ())
    [result] = use_case(doc).extract(b"pdf", False)
    assert result.chain.crypto_valid is False and result.chain.error == "el documento fue alterado"
    assert result.timestamp is None


@pytest.mark.parametrize("kind", list(SignatureKind))
def test_kind_is_kept(kind):
    doc = SignedDocument((signature(CmsSignature(ROOT, (), OK), kind=kind),), ())
    [result] = use_case(doc).extract(b"pdf", False)
    assert result.kind is kind
