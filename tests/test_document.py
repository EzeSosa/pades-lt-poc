"""El análisis del documento (`POST /document`), con PDFs reales armados en el test.

Cubre el adaptador (`PyHankoPdfInspector`, que lee los hechos) y el presenter; las reglas en sí
se prueban sin PDF en tests/test_domain_document.py.
"""

from io import BytesIO
from pathlib import Path

import pytest
from make_pdf_suite import build_pdf, content_stream, incremental, simple_doc, stream_obj
from pyhanko.pdf_utils.crypt.permissions import StandardPermissions
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import copy_into_new_writer
from pyhanko.sign import fields, signers

from conftest import doc_timestamp, load_signer, sign
from pades_lt_poc.adapters.outbound.pyhanko import document_inspector

SUITE = Path(__file__).parent.parent / "testdata" / "pdf-suite"


def post(client, path: str, pdf: bytes, status: int = 200) -> dict:
    r = client.post(path, files={"pdf": ("doc.pdf", pdf, "application/pdf")})
    assert r.status_code == status, r.text
    return r.json()


def verify(client, pdf: bytes) -> dict:
    return post(client, "/verify", pdf)


def document(client, pdf: bytes) -> dict:
    return post(client, "/document", pdf)


def codes(doc: dict) -> list[str]:
    return [f["code"] for f in doc["findings"]]


def severities(doc: dict) -> dict[str, str]:
    return {f["code"]: f["severity"] for f in doc["findings"]}


def with_revision(pdf: bytes, objs: dict[int, bytes]) -> bytes:
    """Una revisión incremental a mano que reemplaza o agrega `objs` (como haría un editor)."""
    return incremental(pdf, objs)


def written(writer: IncrementalPdfFileWriter) -> bytes:
    out = BytesIO()
    writer.write(out)
    return out.getvalue()


# --------------------------------------------------------------------------- firma de la PoC


def test_signed_pdf_structure_revisions_and_signature_dictionary(client, pdf, timestamper):
    signed = doc_timestamp(sign(pdf, load_signer(), timestamper), timestamper)
    doc = document(client, signed)

    assert doc["structure"]["pages"] == 1 and doc["structure"]["revisions"] == 3
    assert doc["structure"]["trailing_bytes"] == 0 and doc["structure"]["hybrid_xref"] is False
    assert doc["protection"] == {"encryption": None, "certification": None, "field_locks": [], "usage_rights": False}
    assert [f["type"] for f in doc["form"]["fields"]] == ["signature", "signature"]
    assert all(f["signed"] for f in doc["form"]["fields"])

    revs = doc["revisions"]
    assert [r["signed_by"] for r in revs] == [[], ["Firma1"], [revs[2]["signed_by"][0]]]
    assert [r["after_signature"] for r in revs] == [False, False, True]
    assert revs[0]["changes"] == []
    # La firma agrega el campo, su widget en la página (/Annots), el diccionario de firma y el /AcroForm.
    kinds = {c["kind"] for c in revs[1]["changes"]}
    assert {"signature", "page", "acroform", "catalog"} <= kinds
    page = next(c for c in revs[1]["changes"] if c["kind"] == "page")
    assert page == {"object": page["object"], "kind": "page", "change": "modified", "page": 1, "subtype": None, "keys": ["/Annots"]}
    assert revs[2]["severity"] == "info"  # el sello de documento sólo agrega una firma

    sig, ts = doc["signature_dictionaries"]
    assert sig["subfilter"] == "/ETSI.CAdES.detached" and ts["type"] == "/DocTimeStamp"
    assert sig["byte_range_regular"] and sig["covers_revision"] and sig["revision"] == 2
    assert sig["byte_range"][2] + sig["byte_range"][3] == revs[1]["end_offset"]
    assert 0 < sig["contents"]["used"] < sig["contents"]["capacity"]
    assert sig["visible"] is False and sig["page"] == 1
    assert doc["findings"] == []


def test_the_last_revision_unsigned_is_reported(client, pdf, timestamper):
    """Lo que agrega el DSS (o cualquier mantenimiento) después de la última firma es informativo."""
    signed = sign(pdf, load_signer(), timestamper)
    reader = PdfFileReader(BytesIO(signed))
    info = reader.trailer.raw_get("/Info").reference.idnum
    with_info = with_revision(signed, {info: b"<< /Producer (Otro programa) >>"})
    doc = document(client, with_info)
    assert severities(doc) == {"unsigned_last_revision": "info"}
    assert doc["revisions"][-1]["changes"][0]["kind"] == "metadata"


# --------------------------------------------------------------------------- alteraciones posteriores a la firma


def test_content_changed_after_signing_is_critical(client):
    """P06 de la suite: una revisión posterior a la firma reemplaza el contenido de la página."""
    doc = document(client, (SUITE / "firmados/P06-contenido-modificado-tras-firmar.pdf").read_bytes())
    assert severities(doc)["content_changed_after_signing"] == "critical"
    last = doc["revisions"][-1]
    assert last["after_signature"] and last["severity"] == "critical" and last["signed_by"] == []
    assert [(c["kind"], c["change"], c["page"]) for c in last["changes"]] == [("page_content", "modified", 1)]


def test_annotation_added_after_signing_is_a_warning(client, pdf, timestamper):
    signed = sign(pdf, load_signer(), timestamper)
    writer = IncrementalPdfFileWriter(BytesIO(signed))
    page = writer.root["/Pages"]["/Kids"][0]
    note = generic.DictionaryObject({
        generic.NameObject("/Type"): generic.NameObject("/Annot"),
        generic.NameObject("/Subtype"): generic.NameObject("/FreeText"),
        generic.NameObject("/Rect"): generic.ArrayObject([generic.NumberObject(n) for n in (72, 500, 300, 540)]),
        generic.NameObject("/Contents"): generic.TextStringObject("APROBADO"),
        generic.NameObject("/DA"): generic.TextStringObject("/Helv 12 Tf 0 g"),
    })
    page["/Annots"].append(writer.add_object(note))
    writer.update_container(page)
    annotated = written(writer)

    doc = document(client, annotated)
    assert severities(doc) == {"annotations_or_fields_after_signing": "warning"}
    changes = {c["kind"]: c for c in doc["revisions"][-1]["changes"]}
    assert changes["annotation"]["subtype"] == "/FreeText" and changes["annotation"]["change"] == "added"
    assert changes["page"]["keys"] == ["/Annots"]


def test_trailing_bytes_after_signing(client, pdf, timestamper):
    signed = sign(pdf, load_signer(), timestamper)
    assert severities(document(client, signed + b"\n" + b"\0" * 64)) == {"trailing_padding": "info"}
    doc = document(client, signed + b"BASURA")
    assert severities(doc) == {"trailing_bytes": "warning"} and doc["structure"]["trailing_bytes"] == 6


# --------------------------------------------------------------------------- protección


def encrypted_doc(perms: StandardPermissions, user_pass: str = "") -> bytes:
    writer = copy_into_new_writer(PdfFileReader(BytesIO(simple_doc([["Documento cifrado"]]))))
    writer.encrypt("propietario", user_pass, perms=perms)
    out = BytesIO()
    writer.write(out)
    return out.getvalue()


def test_owner_password_encryption_is_read_and_the_signature_validates(client, timestamper):
    perms = StandardPermissions.ALLOW_FORM_FILLING | StandardPermissions.ALLOW_ASSISTIVE_TECHNOLOGY
    writer = IncrementalPdfFileWriter(BytesIO(encrypted_doc(perms)))
    writer.encrypt("propietario")
    meta = signers.PdfSignatureMetadata(field_name="Firma1", md_algorithm="sha256", subfilter=fields.SigSeedSubFilter.PADES)
    signed = signers.sign_pdf(writer, meta, signer=load_signer(), timestamper=timestamper).getvalue()

    body = verify(client, signed)
    assert body["signatures"][0]["intact"] and body["signatures"][0]["valid"]
    doc = document(client, signed)
    encryption = doc["protection"]["encryption"]
    assert encryption["algorithm"] == "AES-256" and encryption["key_bits"] == 256 and encryption["revision"] == 6
    permissions = encryption["permissions"]
    assert permissions["fill_forms"] and not permissions["print"] and not permissions["modify"] and not permissions["copy"]
    assert severities(doc) == {"encrypted": "info", "restricted_permissions": "info"}


@pytest.mark.parametrize("path", ["/document", "/verify"])
def test_d03_open_password_is_rejected(client, path):
    detail = post(client, path, (SUITE / "seguridad/S01-cifrado-con-clave-de-apertura.pdf").read_bytes(), 422)["detail"]
    assert "contraseña de apertura" in detail


@pytest.mark.parametrize("path", ["/document", "/verify"])
def test_not_a_pdf_is_rejected(client, path):
    assert post(client, path, b"esto no es un PDF", 422)["detail"].startswith("No es un PDF válido")


def test_unsigned_pdf_is_analyzed(client):
    """A diferencia de /verify, /document no exige firmas."""
    doc = document(client, (SUITE / "formularios/F02-need-appearances.pdf").read_bytes())
    assert severities(doc) == {"need_appearances": "warning"}
    assert doc["signature_dictionaries"] == [] and [r["after_signature"] for r in doc["revisions"]] == [False]


@pytest.mark.parametrize("case, p", [("S03-certificado-p1.pdf", 1), ("S04-certificado-p2.pdf", 2)])
def test_d04_certification(client, case, p):
    doc = document(client, (SUITE / "seguridad" / case).read_bytes())
    cert = doc["protection"]["certification"]
    assert cert["field"] == "Certificacion" and cert["permission"] == p and cert["first_signature"]
    assert "certified" in codes(doc)
    assert doc["signature_dictionaries"][0]["references"] == ["DocMDP"]


def test_field_lock(client, timestamper):
    writer = IncrementalPdfFileWriter(BytesIO(simple_doc()))
    spec = fields.SigFieldSpec("Firma1", field_mdp_spec=fields.FieldMDPSpec(fields.FieldMDPAction.INCLUDE, ["Nombre"]))
    fields.append_signature_field(writer, spec)
    meta = signers.PdfSignatureMetadata(field_name="Firma1", md_algorithm="sha256", subfilter=fields.SigSeedSubFilter.PADES)
    signed = signers.sign_pdf(writer, meta, signer=load_signer(), timestamper=timestamper).getvalue()
    doc = document(client, signed)
    assert doc["protection"]["field_locks"] == [{"field": "Firma1", "action": "Include", "fields": ["Nombre"]}]
    assert "FieldMDP" in doc["signature_dictionaries"][0]["references"]


# --------------------------------------------------------------------------- formulario y contenido activo


def active_doc() -> bytes:
    """Un formulario con NeedAppearances, JavaScript al abrir, una capa oculta y un adjunto."""
    return build_pdf([
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 8 0 R /AcroForm << /Fields [6 0 R 7 0 R] /NeedAppearances true >> "
        b"/OCProperties << /OCGs [9 0 R 10 0 R] /D << /OFF [10 0 R] >> >> /Names << /EmbeddedFiles << /Names [(datos.xml) 11 0 R] >> >> >>",
        b"<< /Type /Pages /Kids [4 0 R] /Count 1 >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> "
        b"/Contents 5 0 R /Annots [6 0 R 7 0 R] >>",
        stream_obj(content_stream(["Formulario con scripts"])),
        b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (Nombre) /V (Juana) /Ff 3 /Rect [72 650 300 670] /P 4 0 R >>",
        b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (total) /Rect [72 600 300 620] /P 4 0 R "
        b"/AA << /C << /S /JavaScript /JS (event.value = 1;) >> >> >>",
        b"<< /S /JavaScript /JS (app.alert\\('hola'\\);) >>",
        b"<< /Type /OCG /Name (Visible) >>",
        b"<< /Type /OCG /Name (Oculta) >>",
        b"<< /Type /Filespec /F (datos.xml) /UF (datos.xml) /EF << /F 12 0 R >> >>",
        stream_obj(b"<datos/>", b" /Type /EmbeddedFile /Subtype /text#2Fxml /Params << /Size 8 >>"),
    ])


def test_form_and_active_content(client, timestamper):
    doc = document(client, sign(active_doc(), load_signer(), timestamper))
    # pyHanko genera las apariencias y saca NeedAppearances al firmar: no queda.
    assert severities(doc) == {
        "executable_actions": "warning",
        "hidden_layers": "warning",
        "field_actions": "info",
        "embedded_files": "info",
    }
    form = doc["form"]
    assert not form["need_appearances"] and not form["xfa"]
    nombre, total, firma = form["fields"]
    assert (nombre["name"], nombre["value"], nombre["read_only"], nombre["required"]) == ("Nombre", "Juana", True, True)
    assert total["actions"] and firma["type"] == "signature" and firma["signed"]
    active = doc["active_content"]
    assert {"type": "JavaScript", "location": "/OpenAction"} in active["actions"]
    assert {"type": "JavaScript", "location": "campo total /AA /C"} in active["actions"]
    assert active["embedded_files"] == [{"name": "datos.xml", "size": 8, "mime_type": "text/xml"}]
    assert active["optional_content"] == {"groups": 2, "hidden": 1}


def test_need_appearances_added_after_signing(client, timestamper):
    """NeedAppearances agregado después de firmar: el visor redibuja los campos firmados."""
    signed = sign(active_doc(), load_signer(), timestamper)
    writer = IncrementalPdfFileWriter(BytesIO(signed))
    acroform = writer.root["/AcroForm"]
    acroform[generic.NameObject("/NeedAppearances")] = generic.BooleanObject(True)
    writer.update_container(acroform)
    doc = document(client, written(writer))
    assert severities(doc)["need_appearances"] == "warning"
    assert severities(doc)["annotations_or_fields_after_signing"] == "warning"
    catalog = next(c for c in doc["revisions"][-1]["changes"] if c["kind"] == "catalog")
    assert catalog["keys"] == ["/AcroForm/NeedAppearances"]  # el /AcroForm de active_doc es directo


def test_empty_signature_field(client, timestamper):
    writer = IncrementalPdfFileWriter(BytesIO((SUITE / "formularios/F03-campo-de-firma-vacio.pdf").read_bytes()))
    meta = signers.PdfSignatureMetadata(field_name="Firma2", md_algorithm="sha256", subfilter=fields.SigSeedSubFilter.PADES)
    doc = document(client, signers.sign_pdf(writer, meta, signer=load_signer(), timestamper=timestamper).getvalue())
    assert severities(doc) == {"empty_signature_fields": "info"}
    assert "Firma1" in doc["findings"][0]["message"]


# --------------------------------------------------------------------------- D-10: robustez


def test_d10_a_section_that_fails_is_a_finding(client, pdf, timestamper, monkeypatch):
    def broken(reader):
        raise KeyError("/Fields")

    monkeypatch.setattr(document_inspector, "_form", broken)
    doc = document(client, sign(pdf, load_signer(), timestamper))
    assert doc["form"] is None and doc["revisions"]  # las demás secciones se leen igual
    [finding] = doc["findings"]
    assert finding["code"] == "unreadable" and "el formulario" in finding["message"] and "KeyError" in finding["message"]
