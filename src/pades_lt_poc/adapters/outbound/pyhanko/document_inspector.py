"""`PdfInspector` con pyHanko: los hechos de un PDF (estructura, protección, formulario, revisiones, contenido activo y firmas).

Lee los objetos del PDF con el lector de pyHanko, sin validar nada, y los traduce a los modelos
de `domain/document.py`; ningún tipo de pyHanko sale de este módulo. Qué significan esos
hechos lo decide el dominio (`analyze`). Ver docs/arquitectura/adaptadores.md.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from typing import TypeVar

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.crypt import StandardSecurityHandler
from pyhanko.pdf_utils.reader import HistoricalResolver, PdfFileReader
from pyhanko.pdf_utils.xref import XRefSectionType

from ....domain.document import (
    Action,
    ActiveContent,
    Certification,
    ChangeKind,
    ChangeType,
    DocumentFacts,
    EmbeddedFile,
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
    SignatureDictionary,
    Structure,
)
from .signed_pdf_reader import open_pdf

T = TypeVar("T")

EOF = re.compile(rb"%%EOF[ \t\f\0]*(?:\r\n|\r|\n)?")
PDFAID = re.compile(rb"pdfaid:part\s*(?:=\s*[\"']|>)\s*(\d)[\s\S]{0,400}?pdfaid:conformance\s*(?:=\s*[\"']|>)\s*([A-Za-z])")
MAX_VALUE = 200  # largo máximo del valor de un campo que se informa


class PyHankoPdfInspector:
    """Implementa `application.ports.PdfInspector`."""

    def inspect(self, pdf: bytes) -> DocumentFacts:
        reader = open_pdf(pdf)
        unreadable: list[tuple[str, str]] = []

        def section(name: str, read: Callable[[], T], default: T) -> T:
            """D-10: una sección que falla no impide las demás ni la validación; queda como hallazgo."""
            try:
                return read()
            except Exception as e:  # noqa: BLE001 - un PDF raro no puede romper el análisis
                unreadable.append((name, f"{type(e).__name__}: {e}"))
                return default

        ends = section("las revisiones", lambda: _revision_ends(reader, pdf), [])
        return DocumentFacts(
            structure=section("la estructura", lambda: _structure(reader, pdf, ends), None),
            protection=section("la protección", lambda: _protection(reader), None),
            form=section("el formulario", lambda: _form(reader), None),
            active_content=section("el contenido activo", lambda: _active_content(reader), None),
            # Con otro lector: la vista histórica de pyHanko falla con objetos que el lector ya
            # decodificó (p. ej. el XMP que leyó la estructura).
            revisions=section("los cambios de cada revisión", lambda: _revisions(open_pdf(pdf), ends), ()),
            signatures=section("los diccionarios de firma", lambda: _signatures(reader, pdf, ends), ()),
            unreadable=tuple(unreadable),
        )


# --------------------------------------------------------------------------- utilidades


def _text(value) -> str | None:
    if value is None:
        return None
    value = value.get_object() if isinstance(value, generic.IndirectObject) else value
    if isinstance(value, generic.TextStringObject | generic.ByteStringObject):
        try:
            return str(value) if isinstance(value, generic.TextStringObject) else value.original_bytes.decode("latin-1")
        except Exception:  # noqa: BLE001
            return None
    return str(value)


def _get(d, key, default=None):
    """`d[key]` resuelto, o `default` si no está (o `d` no es un diccionario)."""
    if not isinstance(d, generic.DictionaryObject) or key not in d:
        return default
    return d[key]


def _ref_id(ref: generic.Reference) -> str:
    return f"{ref.idnum} {ref.generation}"


def _refs_in(obj, depth: int = 0) -> Iterator[generic.Reference]:
    """Las referencias indirectas dentro de un objeto directo (sin seguirlas)."""
    if isinstance(obj, generic.IndirectObject):
        yield obj.reference
    elif isinstance(obj, generic.DictionaryObject) and depth < 4:
        for key in obj:
            yield from _refs_in(obj.raw_get(key), depth + 1)
    elif isinstance(obj, generic.ArrayObject) and depth < 4:
        for i in range(len(obj)):
            yield from _refs_in(obj.raw_get(i), depth + 1)


def _pages(root) -> list[generic.DictionaryObject]:
    """Las hojas del árbol de páginas, en orden (con un tope contra árboles cíclicos)."""
    out, stack, seen = [], [root.raw_get("/Pages")], set()
    while stack and len(seen) < 100_000:
        item = stack.pop()
        ref = item.reference if isinstance(item, generic.IndirectObject) else None
        if ref is not None:
            if (ref.idnum, ref.generation) in seen:
                continue
            seen.add((ref.idnum, ref.generation))
        node = item.get_object()
        if _get(node, "/Type") == "/Pages" or "/Kids" in node:
            kids = node.raw_get("/Kids")
            kids = kids.get_object() if isinstance(kids, generic.IndirectObject) else kids
            stack.extend(reversed([kids.raw_get(i) for i in range(len(kids))]))
        else:
            out.append((ref, node))
    return out


# --------------------------------------------------------------------------- revisiones


def _revision_ends(reader: PdfFileReader, data: bytes) -> list[int]:
    """El byte siguiente al `%%EOF` de cada revisión (con su fin de línea)."""
    ends = []
    for rev in range(reader.xrefs.total_revisions):
        info = reader.xrefs.get_xref_container_info(rev)
        match = EOF.search(data, info.end_location)
        ends.append(match.end() if match else len(data))
    return ends


def _xref_kind(reader: PdfFileReader, rev: int) -> str:
    kind = reader.xrefs.get_xref_container_info(rev).xref_section_type
    return {XRefSectionType.STANDARD: "table", XRefSectionType.STREAM: "stream"}.get(kind, "hybrid")


class _Roles:
    """El rol de cada objeto en una revisión: de qué página es contenido, qué es del DSS, qué es un campo, etc."""

    def __init__(self, resolver: HistoricalResolver) -> None:
        self.kinds: dict[tuple[int, int], tuple[ChangeKind, int | None]] = {}
        root = resolver.root
        self._mark(resolver.root_ref, ChangeKind.CATALOG)
        self.pages = 0
        for number, (ref, page) in enumerate(_pages(root), start=1):
            self.pages = number
            self._mark(ref, ChangeKind.PAGE, number)
            for content in _refs_in(page.raw_get("/Contents")) if "/Contents" in page else ():
                self._mark(content, ChangeKind.PAGE_CONTENT, number)
            if "/Resources" in page:
                for res in _refs_in(page.raw_get("/Resources")):
                    self._mark(res, ChangeKind.RESOURCE, number)
            for annot in _refs_in(page.raw_get("/Annots")) if "/Annots" in page else ():
                obj = annot.get_object()
                kind = ChangeKind.ANNOTATION
                if _get(obj, "/Subtype") == "/Widget":
                    field = _get(obj, "/Parent", obj) if "/FT" not in obj else obj
                    kind = ChangeKind.SIGNATURE if _get(field, "/FT") == "/Sig" else ChangeKind.FORM_FIELD
                self._mark(annot, kind, number)
                for ap in _refs_in(obj.raw_get("/AP")) if "/AP" in obj else ():
                    self._mark(ap, kind, number)
        pages_root = root.raw_get("/Pages")
        if isinstance(pages_root, generic.IndirectObject):
            self._mark(pages_root.reference, ChangeKind.PAGE_TREE)
        for key, kind in (("/DSS", ChangeKind.DSS), ("/Metadata", ChangeKind.METADATA)):
            if key in root:
                for ref in self._walk(root.raw_get(key)):
                    self._mark(ref, kind)
        names = _get(root, "/Names")
        for key, kind in (("/EmbeddedFiles", ChangeKind.EMBEDDED_FILE), ("/JavaScript", ChangeKind.ACTION)):
            if isinstance(names, generic.DictionaryObject) and key in names:
                for ref in self._walk(names.raw_get(key)):
                    self._mark(ref, kind)
        for ref in _refs_in(root.raw_get("/OpenAction")) if "/OpenAction" in root else ():
            self._mark(ref, ChangeKind.ACTION)
        if "/AcroForm" in root:
            form = root.raw_get("/AcroForm")
            if isinstance(form, generic.IndirectObject):
                self._mark(form.reference, ChangeKind.ACROFORM)
            for field_ref in _refs_in(_get(root["/AcroForm"], "/Fields", generic.ArrayObject())):
                self._mark_field(field_ref)
        info = resolver.trailer_view.raw_get("/Info") if "/Info" in resolver.trailer_view else None
        if isinstance(info, generic.IndirectObject):
            self._mark(info.reference, ChangeKind.METADATA)

    def _mark(self, ref: generic.Reference | None, kind: ChangeKind, page: int | None = None) -> None:
        if ref is not None:
            self.kinds.setdefault((ref.idnum, ref.generation), (kind, page))

    def _mark_field(self, ref: generic.Reference, depth: int = 0) -> None:
        field = ref.get_object()
        kind = ChangeKind.SIGNATURE if _get(field, "/FT") == "/Sig" else ChangeKind.FORM_FIELD
        self._mark(ref, kind)
        if kind is ChangeKind.SIGNATURE and "/V" in field:
            for v in _refs_in(field.raw_get("/V")):
                self._mark(v, kind)
        for kid in _refs_in(field.raw_get("/Kids")) if "/Kids" in field and depth < 20 else ():
            self._mark_field(kid, depth + 1)

    def _walk(self, obj, depth: int = 0) -> Iterator[generic.Reference]:
        """Las referencias alcanzables desde `obj` (hasta 6 niveles): el DSS, el XMP, los adjuntos."""
        for ref in _refs_in(obj):
            yield ref
            if depth < 6:
                target = ref.get_object()
                if isinstance(target, generic.StreamObject):
                    continue
                yield from self._walk(target, depth + 1)


def _classify(obj, role: tuple[ChangeKind, int | None] | None) -> tuple[ChangeKind, int | None, str | None]:
    """Qué es un objeto: por su rol en el documento si lo tiene, si no por su /Type."""
    kind, page = role or (None, None)
    subtype = _text(_get(obj, "/Subtype")) if isinstance(obj, generic.DictionaryObject) else None
    if kind is None and isinstance(obj, generic.DictionaryObject):
        type_ = _get(obj, "/Type")
        if type_ in ("/Sig", "/DocTimeStamp") or _get(obj, "/FT") == "/Sig":
            kind = ChangeKind.SIGNATURE
        elif type_ in ("/ObjStm", "/XRef"):
            kind = ChangeKind.STRUCTURE
        elif type_ == "/Annot":
            kind = ChangeKind.ANNOTATION
        elif type_ in ("/XObject", "/Font", "/FontDescriptor", "/ExtGState", "/Pattern") or subtype in ("/Image", "/Form"):
            kind = ChangeKind.RESOURCE
        elif type_ == "/Action" or "/JS" in obj or _get(obj, "/S") in ("/JavaScript", "/Launch"):
            kind, subtype = ChangeKind.ACTION, _text(_get(obj, "/S"))
        elif type_ in ("/EmbeddedFile", "/Filespec"):
            kind = ChangeKind.EMBEDDED_FILE
        elif type_ == "/Metadata":
            kind = ChangeKind.METADATA
        elif type_ == "/Page":
            kind = ChangeKind.PAGE
        elif type_ == "/Pages":
            kind = ChangeKind.PAGE_TREE
        elif "/FT" in obj or "/T" in obj and "/Kids" in obj:
            kind = ChangeKind.FORM_FIELD
    return kind or ChangeKind.OTHER, page, subtype


def _changed_keys(old, new, depth: int = 0) -> tuple[str, ...]:
    """Las claves que cambiaron entre dos versiones de un diccionario. En un diccionario directo
    (p. ej. el /AcroForm dentro del catálogo) se baja un nivel: `/AcroForm/NeedAppearances`."""
    if not isinstance(old, generic.DictionaryObject) or not isinstance(new, generic.DictionaryObject):
        return ()

    def raw(d, k):
        if k not in d:
            return None
        v = d.raw_get(k)
        return ("ref", v.reference.idnum, v.reference.generation) if isinstance(v, generic.IndirectObject) else repr(v)

    out = []
    for k in sorted(set(old) | set(new)):
        if raw(old, k) == raw(new, k):
            continue
        a, b = (d.raw_get(k) if k in d else None for d in (old, new))
        nested = depth == 0 and isinstance(a, generic.DictionaryObject) and isinstance(b, generic.DictionaryObject)
        out += [f"{k}{sub}" for sub in _changed_keys(a, b, 1)] if nested else [k]
    return tuple(out)


def _revisions(reader: PdfFileReader, ends: list[int]) -> tuple[Revision, ...]:
    """D-05: los objetos escritos en cada revisión, clasificados por su rol en esa revisión."""
    xrefs = reader.xrefs
    out = []
    previous_roles = None
    for rev in range(xrefs.total_revisions):
        freed = {(r.idnum, r.generation) for r in xrefs.refs_freed_in_revision(rev)}
        refs = sorted(xrefs.explicit_refs_in_revision(rev), key=lambda r: (r.idnum, r.generation))
        refs = [r for r in refs if (r.idnum, r.generation) not in freed]
        resolver = reader.get_historical_resolver(rev)
        roles = _Roles(resolver)
        changes = []
        if rev > 0:
            previous = reader.get_historical_resolver(rev - 1)
            for ref in refs:
                obj = resolver.get_object(generic.Reference(ref.idnum, ref.generation, resolver))
                key = (ref.idnum, ref.generation)
                added = xrefs.get_introducing_revision(ref) == rev
                old = None if added else previous.get_object(generic.Reference(ref.idnum, ref.generation, previous))
                kind, page, subtype = _classify(obj, roles.kinds.get(key))
                changes.append(
                    ObjectChange(
                        object_ref=_ref_id(ref),
                        kind=kind,
                        change=ChangeType.ADDED if added else ChangeType.MODIFIED,
                        page=page,
                        keys=() if added else _changed_keys(old, obj),
                        subtype=subtype,
                    )
                )
            for idnum, generation in sorted(freed):
                # Lo que era en la revisión anterior. Si no existía (iText marca así números nuevos), es sólo estructura.
                kind, page = previous_roles.kinds.get((idnum, generation), (None, None))
                if kind is None:
                    kind = ChangeKind.OTHER if _existed(previous, idnum, generation) else ChangeKind.STRUCTURE
                changes.append(ObjectChange(f"{idnum} {generation}", kind, ChangeType.FREED, page, ()))
            for objstm in xrefs.object_streams_used_in(rev):
                changes.append(ObjectChange(_ref_id(objstm), ChangeKind.STRUCTURE, ChangeType.ADDED, None, ()))
        out.append(
            Revision(
                number=rev + 1,
                end_offset=ends[rev] if rev < len(ends) else 0,
                xref=_xref_kind(reader, rev),
                objects=len(refs),
                changes=tuple(changes),
                pages=roles.pages,
            )
        )
        previous_roles = roles
    return tuple(out)


def _existed(resolver: HistoricalResolver, idnum: int, generation: int) -> bool:
    """Si el objeto existía en `resolver`, con esa generación o con la anterior (la entrada libre la incrementa)."""
    for gen in {generation, max(generation - 1, 0)}:
        try:
            obj = resolver.get_object(generic.Reference(idnum, gen, resolver))
        except Exception:  # noqa: BLE001 - no está en la historia
            continue
        if not isinstance(obj, generic.NullObject):
            return True
    return False


# --------------------------------------------------------------------------- estructura


def _structure(reader: PdfFileReader, data: bytes, ends: list[int]) -> Structure:
    root = reader.root
    major, minor = reader.input_version
    tail = data[ends[-1]:] if ends else b""
    extensions = []
    for name, ext in (_get(root, "/Extensions") or {}).items():
        ext = ext.get_object() if isinstance(ext, generic.IndirectObject) else ext
        entries = ext if isinstance(ext, generic.ArrayObject) else [ext]
        for e in entries:
            e = e.get_object()
            extensions.append(f"{str(name).lstrip('/')} {_get(e, '/ExtensionLevel', '')}".strip())
    first = _first_object(data)
    info = _get(reader.trailer_view, "/Info") or generic.DictionaryObject()
    return Structure(
        header_version=f"{major}.{minor}",
        catalog_version=_text(_get(root, "/Version")).lstrip("/") if "/Version" in root else None,
        pages=len(_pages(root)),
        hybrid_xref=reader.xrefs.hybrid_xrefs_present,
        object_streams=any(reader.xrefs.object_streams_used_in(r) for r in range(reader.xrefs.total_revisions)),
        linearized=b"/Linearized" in first,
        tagged=bool(_get(_get(root, "/MarkInfo"), "/Marked", False)),
        pdfa=_pdfa(root),
        producer=_text(_get(info, "/Producer")),
        creator=_text(_get(info, "/Creator")),
        trailing_bytes=len(tail),
        trailing_padding=not tail.strip(b"\r\n\t\f \0"),
        extensions=tuple(extensions),
    )


def _first_object(data: bytes) -> bytes:
    """Los primeros bytes del primer objeto, donde está el diccionario de linealización si lo hay."""
    start = data.find(b" obj", 0, 2048)
    return data[start : start + 1024] if start >= 0 else b""


def _pdfa(root) -> str | None:
    metadata = _get(root, "/Metadata")
    if not isinstance(metadata, generic.StreamObject):
        return None
    match = PDFAID.search(metadata.data)
    return f"{match[1].decode()}{match[2].decode().upper()}" if match else None


# --------------------------------------------------------------------------- protección


def _encryption(reader: PdfFileReader) -> Encryption | None:
    handler = reader.security_handler
    if handler is None:
        return None
    enc = reader.trailer.raw_get("/Encrypt").get_object()
    method = None
    cf = _get(enc, "/CF")
    stmf = _get(enc, "/StmF")
    if isinstance(cf, generic.DictionaryObject) and stmf in cf:
        method = _get(cf[stmf], "/CFM")
    version = int(_get(enc, "/V", 0))
    algorithm = {"/AESV3": "AES-256", "/AESV2": "AES-128", "/V2": "RC4"}.get(method) or ("RC4" if version in (1, 2) else str(method or "?"))
    if version == 5 and algorithm == "?":
        algorithm = "AES-256"
    key_bits = int(_get(enc, "/Length", 40 if version == 1 else 0)) or None
    if algorithm == "AES-256":
        key_bits = 256
    elif algorithm == "AES-128":
        key_bits = 128
    elif key_bits is not None and key_bits <= 16:  # algunos la escriben en bytes
        key_bits *= 8
    standard = isinstance(handler, StandardSecurityHandler)
    return Encryption(
        handler=str(_get(enc, "/Filter")),
        algorithm=algorithm,
        key_bits=key_bits,
        version=version or None,
        revision=int(_get(enc, "/R")) if standard and "/R" in enc else None,
        encrypt_metadata=bool(_get(enc, "/EncryptMetadata", True)),
        permissions=Permissions.from_flags(int(_get(enc, "/P"))) if standard and "/P" in enc else None,
    )


def _protection(reader: PdfFileReader) -> Protection:
    root = reader.root
    perms = _get(root, "/Perms") or generic.DictionaryObject()
    certification = None
    docmdp = perms.raw_get("/DocMDP") if "/DocMDP" in perms else None
    sigs = reader.embedded_signatures
    if docmdp is not None:
        docmdp_ref = docmdp.reference if isinstance(docmdp, generic.IndirectObject) else None
        sig_obj = docmdp.get_object()
        level = _docmdp_p(sig_obj)
        certifier = next((i for i, s in enumerate(sigs) if docmdp_ref and _value_ref(s.sig_field) == docmdp_ref), None)
        name = sigs[certifier].field_name if certifier is not None else "(sin campo)"
        certification = Certification(name, level or 2, certifier == 0)
    locks = []
    for s in sigs:
        lock = _get(s.sig_field, "/Lock")
        if isinstance(lock, generic.DictionaryObject) and "/Action" in lock:
            fields = tuple(str(f) for f in _get(lock, "/Fields", ()))
            locks.append(FieldLock(s.field_name, str(lock["/Action"]).lstrip("/"), fields))
    return Protection(
        encryption=_encryption(reader),
        certification=certification,
        field_locks=tuple(locks),
        usage_rights="/UR3" in perms or "/UR" in perms,
    )


def _value_ref(field) -> generic.Reference | None:
    value = field.raw_get("/V") if "/V" in field else None
    return value.reference if isinstance(value, generic.IndirectObject) else None


def _docmdp_p(sig_obj) -> int | None:
    """El P de la transformación DocMDP de un diccionario de firma (por defecto 2, ISO 32000)."""
    for ref in _get(sig_obj, "/Reference", ()):
        ref = ref.get_object()
        if _get(ref, "/TransformMethod") == "/DocMDP":
            return int(_get(_get(ref, "/TransformParams"), "/P", 2))
    return None


# --------------------------------------------------------------------------- formulario


FIELD_FLAGS_READ_ONLY, FIELD_FLAGS_REQUIRED = 1, 2
BUTTON_RADIO, BUTTON_PUSH = 1 << 15, 1 << 16


def _form(reader: PdfFileReader) -> Form | None:
    acroform = _get(reader.root, "/AcroForm")
    if not isinstance(acroform, generic.DictionaryObject):
        return None
    fields: list[FormField] = []

    def walk(refs, prefix: str, inherited: dict, depth: int) -> None:
        for item in refs:
            node = item.get_object()
            name = f"{prefix}.{_text(node['/T'])}" if prefix and "/T" in node else (_text(_get(node, "/T")) or prefix)
            attrs = {**inherited, **{k: node[k] for k in ("/FT", "/Ff", "/V") if k in node}}
            kids = _get(node, "/Kids")
            named_kids = kids and any("/T" in k.get_object() for k in kids)
            if named_kids and depth < 20:
                walk(kids, name, attrs, depth + 1)
                continue
            widgets = [k.get_object() for k in kids] if kids else [node]
            fields.append(_field(name, attrs, node, widgets))

    walk(_get(acroform, "/Fields", ()), "", {}, 0)
    return Form(
        fields=tuple(fields),
        need_appearances=bool(_get(acroform, "/NeedAppearances", False)),
        xfa="/XFA" in acroform,
    )


def _field(name: str, attrs: dict, node, widgets) -> FormField:
    ft = attrs.get("/FT")
    flags = int(attrs.get("/Ff", 0))
    kind = {"/Tx": FieldKind.TEXT, "/Ch": FieldKind.CHOICE, "/Sig": FieldKind.SIGNATURE}.get(ft, FieldKind.UNKNOWN)
    if ft == "/Btn":
        kind = FieldKind.PUSHBUTTON if flags & BUTTON_PUSH else FieldKind.RADIO if flags & BUTTON_RADIO else FieldKind.CHECKBOX
    value = None
    if kind is not FieldKind.SIGNATURE and "/V" in attrs:
        raw = attrs["/V"]
        raw = raw.get_object() if isinstance(raw, generic.IndirectObject) else raw
        if isinstance(raw, generic.StreamObject):
            value = raw.data.decode("utf-8", "replace")
        elif isinstance(raw, generic.ArrayObject):
            value = ", ".join(_text(v) or "" for v in raw)
        else:
            value = _text(raw)
        value = value.lstrip("/") if isinstance(raw, generic.NameObject) else value
        if value and len(value) > MAX_VALUE:
            value = value[:MAX_VALUE] + "…"
    return FormField(
        name=name or "(sin nombre)",
        kind=kind,
        value=value,
        read_only=bool(flags & FIELD_FLAGS_READ_ONLY),
        required=bool(flags & FIELD_FLAGS_REQUIRED),
        signed=kind is FieldKind.SIGNATURE and "/V" in attrs,
        has_actions=any("/A" in w or "/AA" in w for w in (node, *widgets)),
    )


# --------------------------------------------------------------------------- contenido activo


def _action_types(action, location: str, out: list[Action], depth: int = 0) -> None:
    """La acción y las que encadena con /Next."""
    action = action.get_object() if isinstance(action, generic.IndirectObject) else action
    if isinstance(action, generic.DictionaryObject) and "/S" in action:
        out.append(Action(str(action["/S"]).lstrip("/"), location))
        if "/Next" in action and depth < 10:
            nxt = action["/Next"]
            for a in nxt if isinstance(nxt, generic.ArrayObject) else [nxt]:
                _action_types(a, location, out, depth + 1)


def _additional(aa, location: str, out: list[Action]) -> None:
    for trigger, action in (aa.items() if isinstance(aa, generic.DictionaryObject) else ()):
        _action_types(action, f"{location} /AA {trigger}", out)


def _name_tree(node, depth: int = 0) -> Iterator[tuple[str, object]]:
    node = node.get_object() if isinstance(node, generic.IndirectObject) else node
    if not isinstance(node, generic.DictionaryObject) or depth > 20:
        return
    names = _get(node, "/Names")
    if names:
        for i in range(0, len(names) - 1, 2):
            yield _text(names[i]) or "", names[i + 1]
    for kid in _get(node, "/Kids", ()):
        yield from _name_tree(kid, depth + 1)


def _active_content(reader: PdfFileReader) -> ActiveContent:
    root = reader.root
    actions: list[Action] = []
    if "/OpenAction" in root and isinstance(root["/OpenAction"], generic.DictionaryObject):
        _action_types(root["/OpenAction"], "/OpenAction", actions)
    _additional(_get(root, "/AA"), "el documento", actions)
    names = _get(root, "/Names") or generic.DictionaryObject()
    for name, js in _name_tree(_get(names, "/JavaScript")):
        _action_types(js, f"/Names /JavaScript «{name}»", actions)
    for number, (_, page) in enumerate(_pages(root), start=1):
        _additional(_get(page, "/AA"), f"página {number}", actions)
        for annot in _get(page, "/Annots", ()):
            annot = annot.get_object()
            sub = str(_get(annot, "/Subtype", "")).lstrip("/")
            where = f"página {number}, anotación {sub}"
            if "/T" in annot:
                where = f"campo {_text(annot['/T'])}"
            if "/A" in annot:
                _action_types(annot["/A"], where, actions)
            _additional(_get(annot, "/AA"), where, actions)
    acroform = _get(root, "/AcroForm")
    for ref in _get(acroform, "/Fields", ()):
        field = ref.get_object()
        if "/T" in field and "/Kids" not in field:
            continue  # campo y widget en uno: ya se recorrió como anotación
        _additional(_get(field, "/AA"), f"campo {_text(_get(field, '/T'))}", actions)

    files = []
    for name, spec in _name_tree(_get(names, "/EmbeddedFiles")):
        spec = spec.get_object()
        ef = _get(_get(spec, "/EF"), "/F") or _get(_get(spec, "/EF"), "/UF")
        params = _get(ef, "/Params") if isinstance(ef, generic.StreamObject) else None
        size = _get(params, "/Size")
        mime = _get(ef, "/Subtype") if isinstance(ef, generic.StreamObject) else None
        files.append(
            EmbeddedFile(
                name=_text(_get(spec, "/UF")) or _text(_get(spec, "/F")) or name,
                size=int(size) if size is not None else None,
                mime_type=str(mime).lstrip("/").replace("#2F", "/") if mime else None,
            )
        )

    oc = None
    ocprops = _get(root, "/OCProperties")
    if isinstance(ocprops, generic.DictionaryObject):
        groups = _get(ocprops, "/OCGs", ())
        off = _get(_get(ocprops, "/D"), "/OFF", ())
        oc = OptionalContent(groups=len(groups), hidden=len(off))
    return ActiveContent(tuple(actions), tuple(files), oc)


# --------------------------------------------------------------------------- diccionarios de firma


def _der_length(der: bytes) -> int:
    """El largo de un DER (cabecera incluida), para saber cuánto del /Contents es relleno."""
    if len(der) < 2 or der[0] != 0x30:
        return len(der.rstrip(b"\0"))
    first = der[1]
    if first < 0x80:
        return 2 + first
    n = first & 0x7F
    return 2 + n + int.from_bytes(der[2 : 2 + n], "big")


def _signatures(reader: PdfFileReader, data: bytes, ends: list[int]) -> tuple[SignatureDictionary, ...]:
    out = []
    page_refs = {(ref.idnum, ref.generation): n for n, (ref, _) in enumerate(_pages(reader.root), start=1) if ref is not None}
    for sig in reader.embedded_signatures:
        obj = sig.sig_object
        br = tuple(int(x) for x in obj.raw_get("/ByteRange"))
        gap_ok = len(br) == 4 and _is_hex_string(data, br[1], br[2])
        capacity = (br[2] - br[1] - 2) // 2 if len(br) == 4 else 0
        # El /Contents de una firma nunca se cifra (ISO 32000-2, 7.6.2): se lee crudo.
        contents = obj.raw_get("/Contents", decrypt=generic.EncryptedObjAccess.RAW)
        contents = contents.original_bytes if hasattr(contents, "original_bytes") else bytes(contents)
        field = sig.sig_field
        rect = [float(x) for x in _get(field, "/Rect", (0, 0, 0, 0))]
        page = _get(field, "/P", None)
        page_ref = field.raw_get("/P") if "/P" in field else None
        build = _get(_get(obj, "/Prop_Build"), "/App")
        refs = tuple(str(_get(r.get_object(), "/TransformMethod", "")).lstrip("/") for r in _get(obj, "/Reference", ()))
        out.append(
            SignatureDictionary(
                field_name=sig.field_name,
                type=str(sig.sig_object_type),
                filter=_text(_get(obj, "/Filter")),
                subfilter=_text(_get(obj, "/SubFilter")),
                byte_range=br,
                revision=sig.signed_revision + 1,
                revision_end=ends[sig.signed_revision] if sig.signed_revision < len(ends) else 0,
                gap_is_contents=gap_ok,
                contents_capacity=capacity,
                contents_used=_der_length(contents),
                signing_time=_text(_get(obj, "/M")),
                name=_text(_get(obj, "/Name")),
                reason=_text(_get(obj, "/Reason")),
                location=_text(_get(obj, "/Location")),
                contact_info=_text(_get(obj, "/ContactInfo")),
                application=_text(_get(build, "/Name")).lstrip("/") if build is not None and "/Name" in build else None,
                references=refs,
                visible=len(rect) == 4 and abs(rect[2] - rect[0]) > 0 and abs(rect[3] - rect[1]) > 0,
                page=page_refs.get((page_ref.reference.idnum, page_ref.reference.generation))
                if isinstance(page_ref, generic.IndirectObject) and page is not None
                else None,
            )
        )
    return tuple(out)


def _is_hex_string(data: bytes, start: int, end: int) -> bool:
    """Si `data[start:end]` es exactamente un string hexadecimal `<...>`."""
    if not (0 < start < end <= len(data)) or data[start : start + 1] != b"<" or data[end - 1 : end] != b">":
        return False
    return re.fullmatch(rb"[0-9A-Fa-f\s]*", data[start + 1 : end - 1]) is not None
