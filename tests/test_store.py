"""Tests de la fuente de certificados (/store) y de cómo la usan /verify y /certificates."""

import base64
from io import BytesIO

import pytest
from asn1crypto import crl as asn1_crl
from asn1crypto import ocsp as asn1_ocsp
from cryptography.x509 import ocsp as x509_ocsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import DocumentSecurityStore

from conftest import load_signer, sign
from pades_lt_poc import pki
from pades_lt_poc.services.store import SEED_DIR, SEEDS, CertificateStore

Enc = serialization.Encoding


@pytest.fixture(autouse=True)
def reset_store(client):
    """El cliente es de sesión: cada test deja la fuente como la carga inicial."""
    yield
    store = client.app.state.store
    for cert in store.list():
        store.delete(cert["id"])
    store.restore_seed()


def pem(name: str) -> str:
    return pki.entity(name).cert().public_bytes(Enc.PEM).decode()


def add(client, **data):
    return client.post("/store/certificates", data=data)


def listing(client, **params) -> dict:
    r = client.get("/store/certificates", params=params)
    assert r.status_code == 200
    return r.json()


def by_subject(client, cn: str) -> dict:
    return next(c for c in listing(client)["certificates"] if f"CN={cn}" in c["subject"])


# --------------------------------------------------------------------------- carga inicial
def test_seed(client):
    body = listing(client)
    assert body["summary"] == {"total": 3, "trusted_roots": 2, "intermediates": 1, "disabled": 0}
    certs = body["certificates"]
    assert {c["origin"] for c in certs} == {"seed"}
    roots = [c for c in certs if c["kind"] == "root"]
    assert len(roots) == 2 and all(c["trusted"] for c in roots)
    [onti] = [c for c in certs if c["kind"] == "intermediate"]
    assert onti["trusted"] is False
    assert "CN=Autoridad Certificante de Firma Digital" in onti["subject"]
    assert base64.b64decode(onti["der_b64"]) == (SEED_DIR / "ac-onti-firma-digital.der").read_bytes()


def test_seed_runs_once_and_deletions_stick(tmp_path):
    path = tmp_path / "certs.db"
    store = CertificateStore(path)
    assert len(store.list()) == len(SEEDS)
    store.delete(store.list()[0]["id"])
    store.close()

    reopened = CertificateStore(path)  # como al reiniciar la app
    assert len(reopened.list()) == len(SEEDS) - 1
    assert len(reopened.restore_seed()) == 1  # restaurar vuelve a agregar sólo lo que falta
    assert len(reopened.list()) == len(SEEDS)
    reopened.close()


def test_restore_seed_endpoint(client):
    onti = by_subject(client, "Autoridad Certificante de Firma Digital")
    assert client.delete(f"/store/certificates/{onti['id']}").status_code == 204
    r = client.post("/store/certificates/seed")
    assert [c["sha256"] for c in r.json()["added"]] == [onti["sha256"]]


# --------------------------------------------------------------------------- altas
def test_add_intermediate_is_never_trusted(client):
    r = add(client, b64=pem(pki.INTERMEDIATE), trusted="true", notes="la de la PoC")
    assert r.status_code == 201
    [added] = r.json()["added"]
    assert added["kind"] == "intermediate"
    assert added["trusted"] is False
    assert added["origin"] == "manual"
    assert added["notes"] == "la de la PoC"
    assert client.get(f"/store/certificates/{added['id']}").json()["sha256"] == added["sha256"]


def test_add_root_untrusted_by_default(client):
    r = add(client, b64=pem(pki.ROOT), origin="pdf")
    [root] = r.json()["added"]
    assert (root["kind"], root["trusted"], root["origin"]) == ("root", False, "pdf")

    client.delete(f"/store/certificates/{root['id']}")
    [root] = add(client, b64=pem(pki.ROOT), trusted="true").json()["added"]
    assert root["trusted"] is True


def test_add_pkcs7_and_duplicates(client):
    certs = [pki.entity(n).cert() for n in (pki.INTERMEDIATE, pki.ROOT)]
    bundle = pkcs7.serialize_certificates(certs, Enc.DER)
    r = client.post("/store/certificates", files={"crt": ("ca.p7c", bundle, "application/pkcs7-mime")})
    assert r.status_code == 201
    assert {c["kind"] for c in r.json()["added"]} == {"root", "intermediate"}

    # Si todo lo recibido ya estaba, no se agrega nada.
    onti = (SEED_DIR / "ac-onti-firma-digital.der").read_bytes()
    r = add(client, b64=base64.b64encode(onti).decode())
    assert r.status_code == 409  # ya estaba (carga inicial)
    assert "Ya está en la fuente" in r.json()["detail"]


def test_add_rejects_end_entity_and_garbage(client):
    r = add(client, b64=pem(pki.SIGNER))
    assert r.status_code == 422
    assert "sólo guarda raíces e intermedios" in r.json()["detail"]
    assert add(client, b64="no es un certificado").status_code == 422
    assert client.post("/store/certificates").status_code == 422  # ni archivo ni texto


# --------------------------------------------------------------------------- modificaciones y bajas
def test_disable_and_untrust_take_effect_immediately(client):
    verifier = client.app.state.verifier
    root_2016 = load_cert_from_pemder(str(SEED_DIR / "ac-raiz-argentina-2016.der"))
    entry = next(c for c in listing(client, kind="root")["certificates"] if c["sha256"] == root_2016.sha256.hex())

    r = client.patch(f"/store/certificates/{entry['id']}", json={"enabled": False, "notes": "en revisión"})
    assert (r.json()["enabled"], r.json()["notes"]) == (False, "en revisión")
    assert root_2016.dump() not in [c.dump() for c in verifier.trust_roots()]
    assert listing(client)["summary"]["disabled"] == 1

    client.patch(f"/store/certificates/{entry['id']}", json={"enabled": True, "trusted": False})
    assert root_2016.dump() not in [c.dump() for c in verifier.trust_roots()]

    client.patch(f"/store/certificates/{entry['id']}", json={"trusted": True})
    assert root_2016.dump() in [c.dump() for c in verifier.trust_roots()]


def test_only_roots_can_be_trusted(client):
    onti = by_subject(client, "Autoridad Certificante de Firma Digital")
    r = client.patch(f"/store/certificates/{onti['id']}", json={"trusted": True})
    assert r.status_code == 422
    assert r.json()["detail"] == "Sólo una raíz puede ser ancla de confianza"


def test_delete_and_not_found(client):
    onti = by_subject(client, "Autoridad Certificante de Firma Digital")
    assert client.delete(f"/store/certificates/{onti['id']}").status_code == 204
    assert client.get(f"/store/certificates/{onti['id']}").status_code == 404
    assert client.delete(f"/store/certificates/{onti['id']}").status_code == 404
    assert client.patch(f"/store/certificates/{onti['id']}", json={"enabled": True}).status_code == 404


# --------------------------------------------------------------------------- /certificates/inspect
def test_inspect_reports_in_store(client):
    """El reporte de inspección es donde se agrega a la fuente: tiene que saber si ya está."""

    def in_store(**data) -> bool:
        [cert] = client.post("/certificates/inspect", data=data).json()["certificates"]
        return cert["in_store"]

    onti = base64.b64encode((SEED_DIR / "ac-onti-firma-digital.der").read_bytes()).decode()
    assert in_store(b64=onti) is True  # carga inicial
    assert in_store(b64=pem(pki.INTERMEDIATE)) is False
    add(client, b64=pem(pki.INTERMEDIATE))
    assert in_store(b64=pem(pki.INTERMEDIATE)) is True


# --------------------------------------------------------------------------- /certificates
def extract(client, pdf: bytes) -> dict:
    r = client.post(
        "/certificates", files={"pdf": ("doc.pdf", pdf, "application/pdf")}, data={"fetch_missing": "false"}
    )
    assert r.status_code == 200, r.text
    [entry] = r.json()["signatures"]
    return entry


def test_certificates_completes_chain_from_store(client, pdf):
    """Si el PDF trae sólo al firmante, la cadena se completa con la fuente (antes que por AIA)."""
    signed = sign(pdf, load_signer(chain=()))
    entry = extract(client, signed)
    assert [c["source"] for c in entry["certificates"]] == ["cms"]

    add(client, b64=pem(pki.INTERMEDIATE))
    add(client, b64=pem(pki.ROOT))
    entry = extract(client, signed)
    assert entry["chain_complete"] is True
    assert [c["source"] for c in entry["certificates"]] == ["cms", "store", "store"]
    assert [c["in_store"] for c in entry["certificates"]] == [False, True, True]


# --------------------------------------------------------------------------- /verify
def pdf_without_intermediate(pdf: bytes) -> bytes:
    """B-B con DSS completo (raíz, OCSP del firmante y CRL de la raíz), salvo la intermedia."""
    signer, intermediate = pki.entity(pki.SIGNER).cert(), pki.entity(pki.INTERMEDIATE).cert()
    request = x509_ocsp.OCSPRequestBuilder().add_certificate(signer, intermediate, hashes.SHA1()).build()
    ocsp = asn1_ocsp.OCSPResponse.load(pki.ocsp_respond(request.public_bytes(Enc.DER)))
    crl = asn1_crl.CertificateList.load(pki.build_crl(pki.ROOT))
    root = load_cert_from_pemder(str(pki.entity(pki.ROOT).cert_path))

    out = BytesIO(sign(pdf, load_signer(chain=())))
    sig = PdfFileReader(out).embedded_signatures[0]
    DocumentSecurityStore.add_dss(out, sig.pkcs7_content, certs=[root], ocsps=[ocsp], crls=[crl])
    return out.getvalue()


def verify(client, pdf: bytes) -> dict:
    r = client.post("/verify", files={"pdf": ("doc.pdf", pdf, "application/pdf")})
    assert r.status_code == 200, r.text
    return r.json()


def test_verify_completes_from_store_and_says_so(client, pdf):
    signed = pdf_without_intermediate(pdf)

    # Sin la intermedia no hay camino hasta la raíz, y el reporte lo dice.
    body = verify(client, signed)
    [sig] = body["signatures"]
    assert sig["trusted"] is False
    assert sig["completed_from_store"] == []
    assert sig["trust_problem"]["reason"] == "no_path"
    assert "fuente" in sig["trust_problem"]["hint"]

    # Con la intermedia en la fuente valida, pero avisa que el PDF no alcanza solo.
    add(client, b64=pem(pki.INTERMEDIATE))
    body = verify(client, signed)
    [sig] = body["signatures"]
    assert sig["trusted"] is True
    assert sig["bottom_line"] is True
    assert sig["trust_problem"] is None
    intermediate = pki.entity(pki.INTERMEDIATE).cert()
    assert sig["completed_from_store"] == [
        {
            "subject": load_cert_from_pemder(str(pki.entity(pki.INTERMEDIATE).cert_path)).subject.human_friendly,
            "sha256": intermediate.fingerprint(hashes.SHA256()).hex(),
        }
    ]
    store_info = body["certificate_store"]
    assert store_info["self_contained"] is False
    assert "no es LT por sí mismo" in store_info["note"]

    # Deshabilitada, vuelve a no validar: el ABM aplica sin reiniciar.
    entry = by_subject(client, "PoC Intermediate CA")
    client.patch(f"/store/certificates/{entry['id']}", json={"enabled": False})
    assert verify(client, signed)["signatures"][0]["trusted"] is False


def test_failed_validation_does_not_credit_store(client, pdf):
    """Si la firma no valida (aquí, sin DSS no hay revocación), no se informa que la fuente completó la cadena."""
    add(client, b64=pem(pki.INTERMEDIATE))
    body = verify(client, sign(pdf, load_signer(chain=())))
    [sig] = body["signatures"]
    assert sig["trusted"] is False
    assert sig["completed_from_store"] == []
    assert body["certificate_store"]["self_contained"] is True
    assert body["certificate_store"]["note"] is None

    # El motivo: hay camino (la intermedia vino de la fuente), pero no hay revocación.
    problem = sig["trust_problem"]
    assert problem["reason"] == "missing_revocation"
    assert problem["indication"] is not None
    [path] = problem["paths"]
    intermediate = pki.entity(pki.INTERMEDIATE).cert()
    assert path["chain"][1]["subject"] == "PoC Intermediate CA"
    assert path["chain"][1]["sha256"] == intermediate.fingerprint(hashes.SHA256()).hex()
    assert path["reason"] == "missing_revocation" and path["message"]


def test_self_contained_pdf_does_not_use_store(client, pdf):
    """Un PDF que trae toda su cadena no depende de la fuente aunque la intermedia esté cargada."""
    add(client, b64=pem(pki.INTERMEDIATE))
    body = verify(client, sign(pdf, load_signer()))
    [sig] = body["signatures"]
    assert sig["completed_from_store"] == []
    assert body["certificate_store"]["self_contained"] is True
    assert body["certificate_store"]["note"] is None
