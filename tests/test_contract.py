"""Contrato de la API: la respuesta completa de cada endpoint en los casos clave, contra un golden.

Es la red de seguridad de la migración a arquitectura hexagonal (docs/adr/0001): los demás
tests miran campos sueltos; estos fijan el JSON entero, así un cambio que nadie pidió en la
forma de la respuesta (un campo que falta, un orden distinto, un mensaje reescrito) falla.

La PKI de prueba se regenera en cada corrida, así que antes de comparar se normaliza lo que
cambia: huellas, seriales, DER y key ids de sus certificados (por un nombre estable, como
`<sha256:signer>`), horas, ids de la fuente y días restantes. La vigencia de los certificados de
la carga inicial también, porque depende del calendario. Los certificados de la carga
inicial también se nombran, para que se lea qué es cada uno.

Para regenerar los goldens después de un cambio de contrato buscado:
    UPDATE_GOLDEN=1 uv run pytest tests/test_contract.py
y revisar el diff de tests/golden/ antes de commitear.
"""

from __future__ import annotations

import base64
import json
import os
import re
from io import BytesIO
from pathlib import Path

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from pyhanko.pdf_utils.reader import PdfFileReader

from conftest import doc_timestamp, load_signer, pki, sign
from pades_lt_poc.adapters.outbound.seed_catalog import SEED_DIR, SEEDS
from test_store import pdf_without_intermediate
from test_verify import with_free_entry

GOLDEN_DIR = Path(__file__).parent / "golden"
UPDATE = os.environ.get("UPDATE_GOLDEN") == "1"
PKI_NAMES = (pki.ROOT, pki.INTERMEDIATE, pki.SIGNER, pki.TSA, pki.OCSP_RESPONDER)

TIME = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
TIME_ON_DATE = re.compile(r"\d{2}:\d{2}:\d{2} on \d{4}-\d{2}-\d{2}")  # mensajes de pyhanko-certvalidator
HEX_COLON = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){7,}[0-9A-Fa-f]{2}\b")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")  # campo de un DocTimeStamp
STORE_ID = re.compile(r"\bid [\d, ]*\d")


# --------------------------------------------------------------------------- normalización
def _aliases() -> dict[str, str]:
    """Valor variable -> marcador estable, para cada certificado de la PKI y de la carga inicial."""
    certs = {name: pki.entity(name).cert() for name in PKI_NAMES}
    certs |= {f"seed-{Path(f).stem}": x509.load_der_x509_certificate((SEED_DIR / f).read_bytes()) for f in SEEDS}
    out: dict[str, str] = {pki.base_url: "<base_url>"}  # un puerto libre distinto en cada corrida
    for name, cert in certs.items():
        der = cert.public_bytes(serialization.Encoding.DER)
        out[cert.fingerprint(hashes.SHA256()).hex()] = f"<sha256:{name}>"
        out[cert.fingerprint(hashes.SHA1()).hex()] = f"<sha1:{name}>"
        out[base64.b64encode(der).decode()] = f"<der:{name}>"
        if name in PKI_NAMES:  # los seriales de la carga inicial son fijos
            out[format(cert.serial_number, "x")] = f"<serial:{name}>"
            out[str(cert.serial_number)] = f"<serial:{name}>"
            for ext in (x509.SubjectKeyIdentifier, x509.AuthorityKeyIdentifier):
                try:
                    value = cert.extensions.get_extension_for_class(ext).value
                except x509.ExtensionNotFound:
                    continue
                digest = value.digest if ext is x509.SubjectKeyIdentifier else value.key_identifier
                label = "ski" if ext is x509.SubjectKeyIdentifier else "aki"
                out[digest.hex()] = f"<{label}:{name}>"
                out[digest.hex(":").upper()] = f"<{label}:{name}>"
                out[digest.hex(":")] = f"<{label}:{name}>"
    return out


def _seed_validity(entry: dict) -> None:
    """La vigencia de los certificados de la carga inicial depende del calendario (la AC Raíz 2007 y la
    AC ONTI vencen el 2027-11-17), así que no es parte del contrato. La de la PKI de prueba sí: se
    genera en cada corrida y siempre está vigente."""
    sha256 = entry.get("sha256") or (entry.get("fingerprints") or {}).get("sha256") or ""
    if not sha256.startswith("<sha256:seed-"):
        return
    if "validity_status" in entry:
        entry["validity_status"] = "<seed-validity>"
    if isinstance(entry.get("validity"), dict):
        entry["validity"]["status"] = "<seed-validity>"


def normalize(value, aliases: dict[str, str], key: str | None = None):
    if isinstance(value, dict):
        out = {k: normalize(v, aliases, k) for k, v in value.items()}
        _seed_validity(out)
        if key == "fetched":
            # Con conexión las descargas corren en paralelo: el orden de cada lista no es parte del contrato.
            out = {k: sorted(v, key=lambda e: json.dumps(e, sort_keys=True)) for k, v in out.items()}
        return out
    if isinstance(value, list):
        return [normalize(v, aliases) for v in value]
    if key == "id" and isinstance(value, int):
        return "<id>"
    if key == "days_left" and isinstance(value, int):
        return "<days>"
    if not isinstance(value, str):
        return value
    if value in aliases:
        return aliases[value]
    # Los textos largos (detalle de pyHanko, mensajes) pueden traer valores variables adentro.
    for raw in sorted((a for a in aliases if len(a) >= 8 and a in value), key=len, reverse=True):
        value = value.replace(raw, aliases[raw])
    value = TIME_ON_DATE.sub("<time>", TIME.sub("<time>", value))
    value = UUID.sub("<uuid>", HEX_COLON.sub("<hex>", value))
    return STORE_ID.sub("id <id>", value)


@pytest.fixture
def check(client):
    """`check(nombre, status, body)`: compara contra tests/golden/<nombre>.json (o lo graba con UPDATE_GOLDEN=1)."""
    aliases = _aliases()

    def compare(name: str, status: int, body, **extra) -> None:
        actual = normalize({"status": status, **extra, "body": body}, aliases)
        path = GOLDEN_DIR / f"{name}.json"
        text = json.dumps(actual, ensure_ascii=False, indent=2) + "\n"
        if UPDATE or not path.exists():
            GOLDEN_DIR.mkdir(exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
            if not UPDATE:
                pytest.fail(f"no había golden para {name}: se grabó {path.name}, revisalo y volvé a correr")
            return
        expected = json.loads(path.read_text(encoding="utf-8"))
        assert actual == expected, f"la respuesta cambió respecto de {path.name}"

    return compare


@pytest.fixture(autouse=True)
def fresh_state(client, services):
    """La fuente queda como la carga inicial y el caché de CRLs vacío, antes y después de cada caso."""

    def reset():
        source = services.source
        for entry in source.list():
            source.delete(entry.id)
        source.restore_seed()
        services.crl_cache.clear()
        pki.unrevoke_all()

    reset()
    yield
    reset()


# --------------------------------------------------------------------------- helpers
def post_pdf(client, path: str, pdf: bytes, **data):
    r = client.post(path, files={"pdf": ("doc.pdf", pdf, "application/pdf")}, data=data)
    return r.status_code, r.json()


def sign_via_api(base_url: str, pdf: bytes, **form) -> bytes:
    r = requests.post(f"{base_url}/sign", files={"pdf": ("doc.pdf", pdf, "application/pdf")}, data=form, timeout=60)
    assert r.status_code == 200, r.text
    return r.content


def pem(name: str) -> str:
    return pki.entity(name).cert().public_bytes(serialization.Encoding.PEM).decode()


def seed_b64(file: str) -> str:
    return base64.b64encode((SEED_DIR / file).read_bytes()).decode()


# --------------------------------------------------------------------------- /sign
def test_sign_b_lt(check, pki_server, pdf):
    r = requests.post(
        f"{pki_server}/sign",
        files={"pdf": ("contrato ñandú.pdf", pdf, "application/pdf")},
        data={"reason": "Aprobación", "location": "Córdoba"},
        timeout=60,
    )
    reader = PdfFileReader(BytesIO(r.content))
    [sig] = reader.embedded_signatures
    summary = {
        "field": sig.field_name,
        "reason": str(sig.sig_object.get("/Reason")),
        "location": str(sig.sig_object.get("/Location")),
        "subfilter": str(sig.sig_object.get("/SubFilter")),
    }
    check(
        "sign_b_lt",
        r.status_code,
        summary,
        content_type=r.headers["content-type"],
        content_disposition=r.headers["content-disposition"],
    )


@pytest.mark.parametrize("data", [b"", b"%PDF-1.7\n1 0 obj\n<<"], ids=["vacio", "truncado"])
def test_sign_invalid_pdf(check, pki_server, data, request):
    r = requests.post(f"{pki_server}/sign", files={"pdf": ("doc.pdf", data, "application/pdf")}, timeout=60)
    check(f"sign_invalid_{request.node.callspec.id}", r.status_code, r.json())


# --------------------------------------------------------------------------- /verify
def test_verify_b_lt(check, client, pki_server, pdf):
    check("verify_b_lt", *post_pdf(client, "/verify", sign_via_api(pki_server, pdf)))


def test_verify_b_lta(check, client, pki_server, pdf):
    check("verify_b_lta", *post_pdf(client, "/verify", sign_via_api(pki_server, pdf, lta="true")))


def test_verify_without_dss(check, client, pdf):
    check("verify_without_dss", *post_pdf(client, "/verify", sign(pdf, load_signer())))


def test_verify_claimed_signing_time(check, client, pdf):
    signed = sign(pdf, load_signer())
    check("verify_claimed_signing_time", *post_pdf(client, "/verify", signed, validation_time="claimed_signing_time"))


def test_verify_online(check, client, pki_server, pdf, timestamper):
    signed = sign(pdf, load_signer(), timestamper)
    check("verify_online", *post_pdf(client, "/verify", signed, revocation="online"))


def test_verify_revoked_signer_online(check, client, pki_server, pdf, timestamper):
    signed = sign(pdf, load_signer(), timestamper)
    pki.revoke(pki.SIGNER)
    check("verify_revoked_signer_online", *post_pdf(client, "/verify", signed, revocation="online"))


def test_verify_completed_from_store(check, client, pdf):
    client.post("/store/certificates", data={"b64": pem(pki.INTERMEDIATE)})
    check("verify_completed_from_store", *post_pdf(client, "/verify", pdf_without_intermediate(pdf)))


def test_verify_unallocated_free_entry(check, client, pdf):
    signed = sign(pdf, load_signer())
    dead = with_free_entry(signed, idnum=PdfFileReader(BytesIO(signed)).trailer["/Size"], next_gen=65535)
    check("verify_free_entry_default", *post_pdf(client, "/verify", dead))
    check(
        "verify_free_entry_allowed",
        *post_pdf(client, "/verify", dead, diff_policy="allow_unallocated_free_entries"),
    )


def test_verify_rejections(check, client, pdf):
    check("verify_no_signatures", *post_pdf(client, "/verify", pdf))
    signed = sign(pdf, load_signer())
    check(
        "verify_online_in_the_past",
        *post_pdf(client, "/verify", signed, revocation="online", validation_time="claimed_signing_time"),
    )


# --------------------------------------------------------------------------- /certificates
def test_certificates_with_timestamp_and_doc_timestamp(check, client, pdf, timestamper):
    signed = doc_timestamp(sign(pdf, load_signer(), timestamper), timestamper)
    check("certificates_full", *post_pdf(client, "/certificates", signed))


def test_certificates_incomplete_and_from_store(check, client, pdf):
    signed = sign(pdf, load_signer(chain=()))
    check("certificates_incomplete", *post_pdf(client, "/certificates", signed))  # AIA sin red: aia_errors
    client.post("/store/certificates", data={"b64": pem(pki.INTERMEDIATE)})
    client.post("/store/certificates", data={"b64": pem(pki.ROOT)})
    check("certificates_from_store", *post_pdf(client, "/certificates", signed, fetch_missing="false"))


def test_certificates_tampered(check, client, pdf):
    signed = sign(pdf, load_signer())
    i = signed.index(b"Hola PAdES")
    tampered = signed[:i] + b"Chau PAdES" + signed[i + 10 :]
    check("certificates_tampered", *post_pdf(client, "/certificates", tampered))


# --------------------------------------------------------------------------- /certificates/inspect
def test_inspect(check, client):
    for name, data in {
        "inspect_signer": {"b64": pem(pki.SIGNER)},
        "inspect_tsa": {"b64": pem(pki.TSA)},
        "inspect_seed_onti": {"b64": seed_b64("ac-onti-firma-digital.der")},
        "inspect_garbage": {"b64": "no es un certificado"},
        "inspect_no_input": {},
    }.items():
        r = client.post("/certificates/inspect", data=data)
        check(name, r.status_code, r.json())


# --------------------------------------------------------------------------- /store
def test_store_lifecycle(check, client):
    def step(name: str, r) -> dict | None:
        body = r.json() if r.content else None
        check(f"store_{name}", r.status_code, body)
        return body

    step("list", client.get("/store/certificates"))
    step("list_intermediates", client.get("/store/certificates", params={"kind": "intermediate"}))
    added = step("add_intermediate", client.post("/store/certificates", data={"b64": pem(pki.INTERMEDIATE), "notes": "PoC"}))
    step("add_root_untrusted", client.post("/store/certificates", data={"b64": pem(pki.ROOT), "trusted": "false"}))
    step("add_duplicate", client.post("/store/certificates", data={"b64": seed_b64("ac-onti-firma-digital.der")}))
    step("add_end_entity", client.post("/store/certificates", data={"b64": pem(pki.SIGNER)}))
    step("add_no_input", client.post("/store/certificates"))

    cert_id = added["added"][0]["id"]
    step("get", client.get(f"/store/certificates/{cert_id}"))
    step("patch", client.patch(f"/store/certificates/{cert_id}", json={"enabled": False, "notes": "en revisión"}))
    step("patch_trust_intermediate", client.patch(f"/store/certificates/{cert_id}", json={"trusted": True}))
    step("delete", client.delete(f"/store/certificates/{cert_id}"))
    step("get_missing", client.get(f"/store/certificates/{cert_id}"))

    seeds = [c for c in client.get("/store/certificates").json()["certificates"] if c["origin"] == "seed"]
    client.delete(f"/store/certificates/{seeds[0]['id']}")
    step("restore_seed", client.post("/store/certificates/seed"))
