"""El índice de seriales de las CRL da lo mismo que la búsqueda de pyhanko-certvalidator, y el caché de CRLs."""

from datetime import timedelta

import pytest
from asn1crypto import crl as asn1_crl
from pyhanko.keys import load_cert_from_pemder
from pyhanko_certvalidator.revinfo import validate_crl

from pades_lt_poc import pki
from pades_lt_poc.services import crl_index
from pades_lt_poc.services.fetching import CrlCache


@pytest.fixture
def revoked_signer(client):
    pki.revoke(pki.SIGNER)
    yield
    pki.unrevoke_all()


def poc_cert(name: str):
    return load_cert_from_pemder(str(pki.entity(name).cert_path))


def test_verifier_installs_the_index(client):
    assert validate_crl.find_cert_in_list is crl_index.find_cert_in_list


@pytest.mark.parametrize("name", [pki.SIGNER, pki.TSA, pki.INTERMEDIATE])
def test_index_matches_pyhanko(revoked_signer, name):
    """Revocado, no revocado y de otro emisor: mismo resultado que la función original."""
    certificate_list = asn1_crl.CertificateList.load(pki.build_crl(pki.INTERMEDIATE))
    cert = poc_cert(name)
    authority = poc_cert(pki.INTERMEDIATE).subject
    args = (cert, cert.issuer, certificate_list, authority)
    assert crl_index.find_cert_in_list(*args) == crl_index._original(*args)
    date, reason = crl_index.find_cert_in_list(*args)
    assert (date is not None) == (name == pki.SIGNER)


def test_indirect_crl_falls_back_to_pyhanko():
    """Con la extensión certificateIssuer en alguna entrada, el emisor depende del orden: no se indexa."""
    assert crl_index._build_index(b"\x30\x00" + crl_index._CERTIFICATE_ISSUER_OID) is None
    assert crl_index._build_index(b"no es una CRL") is None


def test_cache_keeps_a_crl_until_next_update(client):
    cache = CrlCache(max_entries=1)
    fresh = asn1_crl.CertificateList.load(pki.build_crl(pki.INTERMEDIATE))
    next_update = fresh["tbs_cert_list"]["next_update"].native
    cache.put("http://ejemplo/a.crl", fresh)

    entry = cache.get("http://ejemplo/a.crl", now=next_update - timedelta(seconds=1))
    assert entry.crl is fresh and entry.next_update == next_update
    assert cache.get("http://ejemplo/a.crl", now=next_update) is None  # venció: se descarta
    assert cache.get("http://ejemplo/a.crl") is None

    cache.put("http://ejemplo/a.crl", fresh)
    cache.put("http://ejemplo/b.crl", fresh)  # max_entries=1: sale la más vieja
    assert cache.get("http://ejemplo/a.crl") is None
    assert cache.get("http://ejemplo/b.crl") is not None
