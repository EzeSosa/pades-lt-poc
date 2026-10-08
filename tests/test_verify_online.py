"""/verify con conexión: descarga CRL, OCSP y emisores (AIA) de la PKI de prueba, servida por `pki_server`."""

import asyncio

import pytest
from cryptography.hazmat.primitives import hashes
from pyhanko_certvalidator.errors import CRLFetchError

from conftest import load_signer, sign
from pades_lt_poc import pki
from pades_lt_poc.services.fetching import CRL_CACHE, RevocationFetcherBackend


@pytest.fixture(autouse=True)
def empty_crl_cache():
    """El caché de CRLs es del proceso: cada test arranca sin nada descargado."""
    CRL_CACHE.clear()
    yield
    CRL_CACHE.clear()


def verify(client, pdf: bytes, **data) -> dict:
    r = client.post("/verify", files={"pdf": ("doc.pdf", pdf, "application/pdf")}, data=data)
    assert r.status_code == 200, r.text
    return r.json()


def test_offline_is_the_default_and_suggests_online(client, pdf):
    """Sin DSS no hay revocación: sin conexión no es confiable, y el motivo sugiere conectarse."""
    body = verify(client, sign(pdf, load_signer()))
    assert body["revocation"] == {"mode": "offline", "fetched": None, "note": None}
    [sig] = body["signatures"]
    assert sig["trusted"] is False
    assert sig["trust_problem"]["reason"] == "missing_revocation"
    assert "con conexión" in sig["trust_problem"]["hint"]


def test_online_downloads_revocation_and_trusts(client, pki_server, pdf, timestamper):
    body = verify(client, sign(pdf, load_signer(), timestamper), revocation="online")
    [sig] = body["signatures"]
    assert sig["trusted"] is True and sig["bottom_line"] is True
    assert sig["trust_problem"] is None
    assert sig["signature_timestamp"]["trusted"] is True

    revocation = body["revocation"]
    assert revocation["mode"] == "online"
    assert "descargaron" in revocation["note"]
    fetched = revocation["fetched"]
    assert fetched["crls"] or fetched["ocsps"]
    signer_serial = format(pki.entity(pki.SIGNER).cert().serial_number, "x")
    assert any(r["serial_number"] == signer_serial and r["status"] == "good" for r in fetched["ocsps"])
    # Con conexión no se puede afirmar que el PDF alcance solo.
    assert body["pades_level"] == "PAdES B-T"


def test_second_online_verification_reuses_downloaded_crls(client, pki_server, pdf):
    signed = sign(pdf, load_signer())
    first = verify(client, signed, revocation="online")["revocation"]["fetched"]["crls"]
    assert first and not any(c["from_cache"] for c in first)

    second = verify(client, signed, revocation="online")
    crls = second["revocation"]["fetched"]["crls"]
    assert crls and all(c["from_cache"] and c["fetched_at"] for c in crls)
    assert second["signatures"][0]["trusted"] is True


def test_online_detects_revoked_signer(client, pki_server, pdf):
    signed = sign(pdf, load_signer())
    client.post("/pki/revoke/signer")
    try:
        body = verify(client, signed, revocation="online")
    finally:
        client.post("/pki/unrevoke-all")
    [sig] = body["signatures"]
    assert sig["trusted"] is False
    assert sig["trust_problem"]["reason"] == "revoked"
    assert any(r["status"] == "revoked" for r in body["revocation"]["fetched"]["ocsps"])


def test_issuer_from_aia_is_not_credited_to_store(client, pki_server, pdf):
    """Sin la intermedia en el PDF ni en la fuente, con conexión se baja por AIA: no es de la fuente."""
    body = verify(client, sign(pdf, load_signer(chain=())), revocation="online")
    [sig] = body["signatures"]
    assert sig["trusted"] is True
    assert sig["completed_from_store"] == []
    assert body["certificate_store"]["self_contained"] is True
    intermediate = pki.entity(pki.INTERMEDIATE).cert().fingerprint(hashes.SHA256()).hex()
    assert intermediate in [c["sha256"] for c in body["revocation"]["fetched"]["certs"]]


def test_online_only_validates_now(client, pdf):
    r = client.post(
        "/verify",
        files={"pdf": ("doc.pdf", sign(pdf, load_signer()), "application/pdf")},
        data={"revocation": "online", "validation_time": "claimed_signing_time"},
    )
    assert r.status_code == 422
    assert "hora actual" in r.text


def test_download_timeout_is_a_fetch_error():
    """Un timeout es "no se pudo descargar" (pyHanko sigue), no una excepción que tire la verificación."""

    async def slow():
        raise TimeoutError

    async def run():
        async with RevocationFetcherBackend(crl_timeout=1) as fetchers:
            with pytest.raises(CRLFetchError, match="Se agotó el tiempo \\(1 s\\).*http://ejemplo/ca.crl"):
                await fetchers.crl_fetcher._post_fetch_task("http://ejemplo/ca.crl", slow)

    asyncio.run(run())


def test_unknown_revocation_mode_is_rejected(client, pdf):
    r = client.post(
        "/verify",
        files={"pdf": ("doc.pdf", sign(pdf, load_signer()), "application/pdf")},
        data={"revocation": "a veces"},
    )
    assert r.status_code == 422
