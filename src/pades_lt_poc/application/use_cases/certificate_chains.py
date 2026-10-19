"""Caso de uso: la cadena de certificados (hoja -> raíz) de cada firma de un PDF, sin exigir confianza."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ...domain.certificates import Certificate
from ...domain.chains import ALTERED_DOCUMENT, ALTERED_TIMESTAMP, CertSource, ChainResult, chain_for, http_ca_issuer_urls
from ...domain.signatures import SignatureKind
from ..ports import CertificateCodec, IssuerFetcher, IssuerFetchError, SignedPdfReader
from .certificate_source import CertificateSource


@dataclass(frozen=True)
class TimestampChain:
    time: datetime
    """La hora sellada."""
    chain: ChainResult


@dataclass(frozen=True)
class SignatureChains:
    field_name: str
    kind: SignatureKind
    chain: ChainResult
    timestamp: TimestampChain | None
    """El sello de la firma: None si no tiene, o si la firma no verifica (C-01). Siempre None para un DocTimeStamp."""


class ExtractCertificateChains:
    """Por cada firma (incluidos los DocTimeStamp), su integridad y, si verifica, la cadena del firmante.

    No exige confianza: la cadena se arma con los certificados del propio PDF (CMS + DSS),
    verificando que cada uno haya firmado al anterior. Lo que falte se busca en la fuente de
    certificados y, si tampoco está y se pide, por AIA caIssuers (reglas C-01 a C-03).

    Bloquea (descargas AIA): llamarlo fuera del event loop.
    """

    def __init__(self, reader: SignedPdfReader, codec: CertificateCodec, source: CertificateSource, fetcher: IssuerFetcher) -> None:
        self.reader = reader
        self.codec = codec
        self.source = source
        self.fetcher = fetcher

    def extract(self, pdf: bytes, fetch_missing: bool) -> list[SignatureChains]:
        document = self.reader.read(pdf)
        snapshot = self.source.snapshot()
        dss = [(c, CertSource.DSS) for c in document.dss_certificates]
        # Lo que no trae el PDF se busca en la fuente (habilitados) antes que por AIA.
        store = [(c, CertSource.STORE) for c in snapshot.chain_certs]
        lookup = _AiaLookup(self.fetcher).issuers if fetch_missing else None

        def chain(cms, extra, altered) -> ChainResult:
            return chain_for(cms, extra, altered, self.codec.issued_by, lookup, snapshot.known_sha256)

        results = []
        for sig in document.signatures:
            signature_chain = chain(sig.cms, [*dss, *store], ALTERED_DOCUMENT)
            timestamp = None
            if sig.timestamp is not None and signature_chain.crypto_valid:
                # La TSA sella el valor de la firma. Sus certificados vienen en el token, y los del
                # CMS de la firma, del DSS y de la fuente sirven para completar la cadena.
                own_cms = [(c, CertSource.CMS) for c in sig.cms.other_certificates]
                timestamp = TimestampChain(
                    sig.timestamp.time,
                    chain(sig.timestamp.cms, [*own_cms, *dss, *store], ALTERED_TIMESTAMP),
                )
            results.append(SignatureChains(sig.field_name, sig.kind, signature_chain, timestamp))
        return results


class _AiaLookup:
    """C-03: emisores por AIA caIssuers (http/https), con caché por pedido: firma y sello suelen compartir CA."""

    def __init__(self, fetcher: IssuerFetcher) -> None:
        self.fetcher = fetcher
        self._cache: dict[str, list[Certificate] | str] = {}

    def issuers(self, cert: Certificate) -> tuple[list[Certificate], list[str]]:
        urls, missing = http_ca_issuer_urls(cert)
        if missing:
            return [], [missing]
        certs: list[Certificate] = []
        errors: list[str] = []
        for url in urls:
            if url not in self._cache:
                try:
                    self._cache[url] = self.fetcher.fetch(url)
                except IssuerFetchError as e:
                    self._cache[url] = f"{url}: {e}"
            got = self._cache[url]
            if isinstance(got, str):
                errors.append(got)
            else:
                certs.extend(got)
        return certs, errors
