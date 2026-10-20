from fastapi import APIRouter, File, UploadFile
from fastapi.concurrency import run_in_threadpool

from ....domain.document import DocumentAnalysis, FieldKind, Severity
from .dependencies import AnalyzeDocumentDep

router = APIRouter(tags=["Documento"])


@router.post("/document")
async def document(analyzer: AnalyzeDocumentDep, pdf: UploadFile = File(...)) -> dict:
    """Análisis del PDF más allá de sus firmas, firmado o no: protección (cifrado, permisos, certificación,
    bloqueos), formulario, cambios de cada revisión, contenido activo, estructura y diccionarios de firma,
    con hallazgos `info`, `warning` o `critical`. No valida firmas: eso es `/verify`.
    """
    data = await pdf.read()
    # Parsear un PDF grande bloquea: fuera del event loop.
    return present_document(await run_in_threadpool(analyzer.analyze, data))


# --------------------------------------------------------------------------- presenter
def present_document(analysis: DocumentAnalysis) -> dict:
    facts = analysis.facts
    structure, protection, form, active = facts.structure, facts.protection, facts.form, facts.active_content
    return {
        "summary": {s.value: sum(f.severity is s for f in analysis.findings) for s in Severity},
        "findings": [
            {"code": f.code, "severity": f.severity.value, "area": f.area.value, "message": f.message} for f in analysis.findings
        ],
        "structure": (
            {
                "version": structure.version,
                "header_version": structure.header_version,
                "catalog_version": structure.catalog_version,
                "pages": structure.pages,
                "revisions": len(facts.revisions),
                "hybrid_xref": structure.hybrid_xref,
                "object_streams": structure.object_streams,
                "linearized": structure.linearized,
                "tagged": structure.tagged,
                "pdfa": structure.pdfa,
                "producer": structure.producer,
                "creator": structure.creator,
                "trailing_bytes": structure.trailing_bytes,
                "extensions": list(structure.extensions),
            }
            if structure
            else None
        ),
        "protection": (
            {
                "encryption": (
                    {
                        "handler": e.handler,
                        "algorithm": e.algorithm,
                        "key_bits": e.key_bits,
                        "version": e.version,
                        "revision": e.revision,
                        "encrypt_metadata": e.encrypt_metadata,
                        "permissions": vars(e.permissions) if e.permissions else None,
                    }
                    if (e := protection.encryption)
                    else None
                ),
                "certification": (
                    {"field": c.field_name, "permission": c.permission, "meaning": c.meaning, "first_signature": c.first_signature}
                    if (c := protection.certification)
                    else None
                ),
                "field_locks": [{"field": lock.field_name, "action": lock.action, "fields": list(lock.fields)} for lock in protection.field_locks],
                "usage_rights": protection.usage_rights,
            }
            if protection
            else None
        ),
        "form": (
            {
                "need_appearances": form.need_appearances,
                "xfa": form.xfa,
                "fields": [
                    {
                        "name": f.name,
                        "type": f.kind.value,
                        "value": f.value,
                        "read_only": f.read_only,
                        "required": f.required,
                        "signed": f.signed if f.kind is FieldKind.SIGNATURE else None,
                        "actions": f.has_actions,
                    }
                    for f in form.fields
                ],
            }
            if form
            else None
        ),
        "active_content": (
            {
                "actions": [{"type": a.type, "location": a.location} for a in active.actions],
                "embedded_files": [{"name": f.name, "size": f.size, "mime_type": f.mime_type} for f in active.embedded_files],
                "optional_content": (
                    {"groups": oc.groups, "hidden": oc.hidden} if (oc := active.optional_content) else None
                ),
            }
            if active
            else None
        ),
        # Cada revisión con las firmas que la cierran y, si es posterior a la primera firma, el riesgo de lo que agrega.
        "revisions": [
            {
                "number": v.revision.number,
                "end_offset": v.revision.end_offset,
                "xref": v.revision.xref,
                "objects": v.revision.objects,
                "pages": v.revision.pages,
                "signed_by": list(v.signed_by),
                "after_signature": v.after_signature,
                "severity": v.severity.value,
                "changes": [
                    {
                        "object": c.object_ref,
                        "kind": c.kind.value,
                        "change": c.change.value,
                        "page": c.page,
                        "subtype": c.subtype,
                        "keys": list(c.keys),
                    }
                    for c in v.revision.changes
                ],
            }
            for v in analysis.revisions
        ],
        "signature_dictionaries": [
            {
                "field": s.field_name,
                "type": s.type,
                "filter": s.filter,
                "subfilter": s.subfilter,
                "byte_range": list(s.byte_range),
                "byte_range_regular": s.byte_range_regular,
                "covers_revision": s.covers_revision,
                "revision": s.revision,
                "contents": {"capacity": s.contents_capacity, "used": s.contents_used},
                "signing_time": s.signing_time,
                "name": s.name,
                "reason": s.reason,
                "location": s.location,
                "contact_info": s.contact_info,
                "application": s.application,
                "references": list(s.references),
                "visible": s.visible,
                "page": s.page,
            }
            for s in facts.signatures
        ],
    }
