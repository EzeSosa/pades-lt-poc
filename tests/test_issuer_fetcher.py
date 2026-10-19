"""`HttpIssuerFetcher` (requests) contra la app de los tests escuchando en un puerto real."""

import pytest
from cryptography.hazmat.primitives import serialization

from conftest import pki
from pades_lt_poc.adapters.outbound.http.issuer_fetcher import HttpIssuerFetcher
from pades_lt_poc.application.ports import IssuerFetchError


def test_downloads_and_parses_a_published_issuer(pki_server):
    [root] = HttpIssuerFetcher().fetch(pki.cert_url(pki.ROOT))  # la app lo publica en PEM
    assert root.der == pki.entity(pki.ROOT).cert().public_bytes(serialization.Encoding.DER)
    assert root.self_signed


def test_http_errors_and_garbage_are_fetch_errors(pki_server):
    with pytest.raises(IssuerFetchError, match="404"):
        HttpIssuerFetcher().fetch(f"{pki_server}/pki/no-existe.crt")
    with pytest.raises(IssuerFetchError, match="no es un certificado"):
        HttpIssuerFetcher().fetch(f"{pki_server}/pki/root.crl")  # DER, pero una CRL


def test_unreachable_is_a_fetch_error():
    with pytest.raises(IssuerFetchError):
        HttpIssuerFetcher().fetch("http://127.0.0.1:9/ca.crt")  # puerto discard: nadie escucha
