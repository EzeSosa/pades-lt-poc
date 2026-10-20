"""Reglas del análisis del documento (domain/document.py), sin PDF: los hechos se arman a mano."""

from dataclasses import replace

import pytest

from pades_lt_poc.domain.document import (
    Action,
    ActiveContent,
    Certification,
    ChangeKind,
    ChangeType,
    DocumentFacts,
    Encryption,
    FieldKind,
    FieldLock,
    Form,
    FormField,
    ObjectChange,
    OptionalContent,
    Permissions,
    Protection,
    Revision,
    Severity,
    SignatureDictionary,
    Structure,
    analyze,
    classify_change,
    revision_severity,
    revision_verdicts,
)

STRUCTURE = Structure("1.7", None, 1, False, False, False, False, None, "pyHanko", None, 0, True, ())
NO_PROTECTION = Protection(None, None, (), False)


def facts(**kw) -> DocumentFacts:
    base = dict(structure=STRUCTURE, protection=NO_PROTECTION, form=None, active_content=None, revisions=(), signatures=())
    return DocumentFacts(**{**base, **kw})


def codes(document_facts: DocumentFacts) -> list[str]:
    return [f.code for f in analyze(document_facts).findings]


def change(kind: ChangeKind, *, added=False, freed=False, keys=(), ref="5 0") -> ObjectChange:
    type_ = ChangeType.FREED if freed else ChangeType.ADDED if added else ChangeType.MODIFIED
    return ObjectChange(ref, kind, type_, 1, tuple(keys))


def revision(number: int, *changes: ObjectChange, pages=1) -> Revision:
    return Revision(number, number * 1000, "table", len(changes), tuple(changes), pages)


def signature(field="Firma1", revision=2, *, type="/Sig", subfilter="/ETSI.CAdES.detached", byte_range=(0, 100, 300, 50), gap=True, end=350):
    return SignatureDictionary(
        field, type, "/Adobe.PPKLite", subfilter, byte_range, revision, end, gap, 99, 80,
        None, None, None, None, None, None, (), False, 1,
    )


# --------------------------------------------------------------------------- D-01, D-02: cifrado


def test_d01_permissions_from_p():
    # -4100 (0xFFFFEFFC): todo permitido; -64 (0xFFFFFFC0): apagados los bits 3 a 6.
    assert Permissions.from_flags(-4100).denied() == ()
    restricted = Permissions.from_flags(-64)
    assert restricted.denied() == ("print", "modify", "copy", "annotate")
    assert restricted.signing_allowed  # el bit 9 alcanza para firmar
    nothing = Permissions.from_flags(0)
    assert not nothing.signing_allowed and len(nothing.denied()) == 8


def encrypted(algorithm="AES-256", bits=256, p=-4100) -> Protection:
    return Protection(Encryption("/Standard", algorithm, bits, 5, 6, True, Permissions.from_flags(p)), None, (), False)


def test_d02_weak_encryption():
    assert codes(facts(protection=encrypted())) == ["encrypted"]
    assert "weak_encryption" in codes(facts(protection=encrypted("RC4", 128)))
    assert "weak_encryption" in codes(facts(protection=encrypted("AES-128", 40)))
    assert "weak_encryption" not in codes(facts(protection=encrypted("AES-128", 128)))


def test_restricted_permissions_and_signing():
    assert codes(facts(protection=encrypted(p=-64))) == ["encrypted", "restricted_permissions"]
    found = codes(facts(protection=encrypted(p=0)))
    assert found[0] == "signing_not_permitted"  # warning: va antes que los informativos
    assert set(found) == {"encrypted", "restricted_permissions", "signing_not_permitted"}


def test_pdfa_forbids_encryption():
    assert "pdfa_encrypted" in codes(facts(protection=encrypted(), structure=replace(STRUCTURE, pdfa="2B")))


# --------------------------------------------------------------------------- D-04: certificación y bloqueos


def test_d04_certification_meaning_and_position():
    first = facts(protection=Protection(None, Certification("Cert", 1, True), (), False))
    [finding] = analyze(first).findings
    assert finding.code == "certified" and "ningún cambio" in finding.message

    not_first = facts(protection=Protection(None, Certification("Cert", 2, False), (), False))
    findings = analyze(not_first).findings
    assert [f.code for f in findings] == ["certification_not_first", "certified"]
    assert findings[0].severity is Severity.CRITICAL


def test_field_locks_and_usage_rights():
    protection = Protection(None, None, (FieldLock("Firma1", "Include", ("Nombre", "DNI")),), True)
    findings = analyze(facts(protection=protection)).findings
    assert [f.code for f in findings] == ["field_lock", "usage_rights"]
    assert "Nombre, DNI" in findings[0].message


# --------------------------------------------------------------------------- D-05: revisiones


@pytest.mark.parametrize(
    "obj, severity",
    [
        (change(ChangeKind.PAGE_CONTENT), Severity.CRITICAL),
        (change(ChangeKind.RESOURCE, added=True), Severity.CRITICAL),
        (change(ChangeKind.ACTION, added=True), Severity.CRITICAL),
        (change(ChangeKind.PAGE, keys=["/Annots"]), Severity.INFO),  # una firma o anotación nueva
        (change(ChangeKind.PAGE, keys=["/Contents"]), Severity.CRITICAL),
        (change(ChangeKind.PAGE, added=True), Severity.CRITICAL),  # una página nueva
        (change(ChangeKind.CATALOG, keys=["/AcroForm", "/DSS", "/Extensions"]), Severity.INFO),
        (change(ChangeKind.CATALOG, keys=["/OpenAction"]), Severity.CRITICAL),
        (change(ChangeKind.CATALOG, keys=["/OutputIntents"]), Severity.WARNING),
        (change(ChangeKind.ACROFORM, keys=["/Fields"]), Severity.INFO),
        (change(ChangeKind.ACROFORM, keys=["/NeedAppearances"]), Severity.WARNING),
        (change(ChangeKind.CATALOG, keys=["/AcroForm/Fields", "/DSS"]), Severity.INFO),  # /AcroForm directo
        (change(ChangeKind.CATALOG, keys=["/AcroForm/NeedAppearances"]), Severity.WARNING),
        (change(ChangeKind.CATALOG, keys=["/AcroForm/Fields", "/OpenAction"]), Severity.CRITICAL),
        (change(ChangeKind.ANNOTATION, added=True), Severity.WARNING),
        (change(ChangeKind.FORM_FIELD, keys=["/V"]), Severity.WARNING),
        (change(ChangeKind.SIGNATURE, added=True), Severity.INFO),
        (change(ChangeKind.DSS, added=True), Severity.INFO),
        (change(ChangeKind.METADATA), Severity.INFO),
        (change(ChangeKind.STRUCTURE, added=True), Severity.INFO),
        (change(ChangeKind.STRUCTURE, freed=True), Severity.INFO),  # una entrada libre de un objeto que no existía
        (change(ChangeKind.PAGE_CONTENT, freed=True), Severity.CRITICAL),  # borrar el contenido de una página
        (change(ChangeKind.PAGE, freed=True, keys=["/Annots"]), Severity.CRITICAL),
    ],
)
def test_d05_classify_change(obj, severity):
    assert classify_change(obj) is severity


def test_d05_the_worst_change_wins():
    assert revision_severity([]) is Severity.INFO
    assert revision_severity([change(ChangeKind.DSS), change(ChangeKind.ANNOTATION)]) is Severity.WARNING
    assert revision_severity([change(ChangeKind.ANNOTATION), change(ChangeKind.PAGE_CONTENT)]) is Severity.CRITICAL


def test_d05_only_revisions_after_the_first_signature_are_judged():
    revs = (
        revision(1),
        revision(2, change(ChangeKind.PAGE_CONTENT), change(ChangeKind.SIGNATURE, added=True)),  # la firma la cubre
        revision(3, change(ChangeKind.DSS, added=True)),
        revision(4, change(ChangeKind.SIGNATURE, added=True)),
    )
    sigs = (signature("Firma1", 2), signature("TS", 4, type="/DocTimeStamp"))
    verdicts = revision_verdicts(revs, sigs)
    assert [v.after_signature for v in verdicts] == [False, False, True, True]
    assert [v.signed_by for v in verdicts] == [(), ("Firma1",), (), ("TS",)]
    assert all(v.severity is Severity.INFO for v in verdicts)  # lo de la rev 2 es anterior a la firma


def test_d05_a_doc_timestamp_alone_does_not_start_the_judgement():
    revs = (revision(1), revision(2, change(ChangeKind.SIGNATURE, added=True)), revision(3, change(ChangeKind.PAGE_CONTENT)))
    verdicts = revision_verdicts(revs, (signature("TS", 2, type="/DocTimeStamp"),))
    assert not any(v.after_signature for v in verdicts)


def test_d05_findings_after_signing():
    revs = (
        revision(1),
        revision(2, change(ChangeKind.SIGNATURE, added=True)),
        revision(3, change(ChangeKind.ANNOTATION, added=True), change(ChangeKind.PAGE, keys=["/Annots"])),
        revision(4, change(ChangeKind.PAGE_CONTENT)),
    )
    findings = analyze(facts(revisions=revs, signatures=(signature(),))).findings
    assert [(f.code, f.severity) for f in findings] == [
        ("content_changed_after_signing", Severity.CRITICAL),
        ("annotations_or_fields_after_signing", Severity.WARNING),
    ]
    assert "revisión 4" in findings[0].message and "contenido de página" in findings[0].message
    assert "revisión 3" in findings[1].message and "anotaciones" in findings[1].message


def test_unsigned_maintenance_revision_is_informative():
    revs = (revision(1), revision(2, change(ChangeKind.SIGNATURE, added=True)), revision(3, change(ChangeKind.DSS, added=True)))
    findings = analyze(facts(revisions=revs, signatures=(signature(),))).findings
    assert [(f.code, f.severity) for f in findings] == [("unsigned_last_revision", Severity.INFO)]


def test_page_count_changed_after_signing():
    revs = (revision(1), revision(2, change(ChangeKind.SIGNATURE, added=True)), revision(3, change(ChangeKind.PAGE, added=True), pages=2))
    assert "page_count_changed" in codes(facts(revisions=revs, signatures=(signature(),)))


# --------------------------------------------------------------------------- D-06: formulario


def field(name, kind=FieldKind.TEXT, signed=False, actions=False) -> FormField:
    return FormField(name, kind, None, False, False, signed, actions)


def test_d06_need_appearances_and_xfa():
    form = Form((field("Nombre"),), need_appearances=True, xfa=True)
    findings = analyze(facts(form=form)).findings
    assert [(f.code, f.severity) for f in findings] == [("need_appearances", Severity.WARNING), ("xfa", Severity.WARNING)]


def test_empty_signature_fields_and_field_actions():
    form = Form((field("Firma1", FieldKind.SIGNATURE), field("Firma2", FieldKind.SIGNATURE, signed=True), field("total", actions=True)), False, False)
    assert form.empty_signature_fields == ("Firma1",)
    assert codes(facts(form=form)) == ["empty_signature_fields", "field_actions"]


# --------------------------------------------------------------------------- D-07: contenido activo


def test_d07_executing_actions():
    active = ActiveContent((Action("JavaScript", "/OpenAction"), Action("URI", "página 1, anotación Link")), (), None)
    findings = analyze(facts(active_content=active)).findings
    assert [(f.code, f.severity) for f in findings] == [("executable_actions", Severity.WARNING), ("navigation_actions", Severity.INFO)]
    assert "JavaScript en /OpenAction" in findings[0].message

    launch = ActiveContent((Action("Launch", "/OpenAction"),), (), None)
    assert analyze(facts(active_content=launch)).findings[0].severity is Severity.CRITICAL


def test_d07_pdfa_forbids_javascript():
    active = ActiveContent((Action("JavaScript", "/OpenAction"),), (), None)
    assert "pdfa_actions" in codes(facts(active_content=active, structure=replace(STRUCTURE, pdfa="3A")))


def test_d07_hidden_layers_and_attachments():
    from pades_lt_poc.domain.document import EmbeddedFile

    active = ActiveContent((), (EmbeddedFile("factura.xml", 120, "text/xml"),), OptionalContent(3, 1))
    findings = analyze(facts(active_content=active)).findings
    assert [(f.code, f.severity) for f in findings] == [("hidden_layers", Severity.WARNING), ("embedded_files", Severity.INFO)]
    assert analyze(facts(active_content=ActiveContent((), (), OptionalContent(2, 0)))).findings == ()


# --------------------------------------------------------------------------- D-08: diccionario de firma


def test_d08_regular_byte_range():
    sig = signature()
    assert sig.byte_range_regular and sig.covers_revision
    assert analyze(facts(signatures=(sig,))).findings == ()


@pytest.mark.parametrize(
    "byte_range, gap",
    [((10, 100, 300, 50), True), ((0, 100, 300), True), ((0, 300, 100, 50), True), ((0, 100, 300, 50), False)],
)
def test_d08_irregular_byte_range(byte_range, gap):
    sig = signature(byte_range=byte_range, gap=gap)
    [finding] = analyze(facts(signatures=(sig,))).findings
    assert finding.code == "irregular_byte_range" and finding.severity is Severity.CRITICAL


def test_d08_byte_range_must_reach_the_end_of_its_revision():
    [finding] = analyze(facts(signatures=(signature(end=400),))).findings
    assert finding.code == "byte_range_not_revision"


def test_d08_subfilters():
    assert codes(facts(signatures=(signature(subfilter="/adbe.pkcs7.detached"),))) == ["subfilter:adbe.pkcs7.detached"]
    found = analyze(facts(signatures=(signature(subfilter="/adbe.pkcs7.sha1"),))).findings
    assert found[0].severity is Severity.WARNING
    assert codes(facts(signatures=(signature(subfilter="/ETSI.RFC3161", type="/DocTimeStamp"),))) == []
    assert codes(facts(signatures=(signature(subfilter="/raro"),))) == ["subfilter:raro"]


# --------------------------------------------------------------------------- D-09, D-10: estructura y robustez


def test_d09_trailing_bytes_and_hybrid_xref():
    assert codes(facts(structure=replace(STRUCTURE, trailing_bytes=512, trailing_padding=True))) == ["trailing_padding"]
    padded = analyze(facts(structure=replace(STRUCTURE, trailing_bytes=10, trailing_padding=False))).findings
    assert [(f.code, f.severity) for f in padded] == [("trailing_bytes", Severity.WARNING)]
    assert codes(facts(structure=replace(STRUCTURE, hybrid_xref=True))) == ["hybrid_xref"]


def test_version_is_the_highest_of_header_and_catalog():
    assert replace(STRUCTURE, catalog_version="2.0").version == "2.0"
    assert replace(STRUCTURE, header_version="2.0", catalog_version="1.7").version == "2.0"
    assert STRUCTURE.version == "1.7"


def test_d10_unreadable_sections_are_findings():
    found = analyze(DocumentFacts(None, None, None, None, (), (), unreadable=(("el formulario", "KeyError: /Fields"),))).findings
    assert [(f.code, f.severity) for f in found] == [("unreadable", Severity.WARNING)]
    assert "el formulario" in found[0].message


def test_findings_are_sorted_by_severity():
    findings = analyze(
        facts(
            protection=encrypted(),
            form=Form((), need_appearances=True, xfa=False),
            signatures=(signature(byte_range=(1, 2, 3, 4)),),
        )
    ).findings
    assert [f.severity for f in findings] == [Severity.CRITICAL, Severity.WARNING, Severity.INFO]
