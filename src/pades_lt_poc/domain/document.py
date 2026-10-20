"""El documento PDF más allá de sus firmas: protección, formularios, revisiones, contenido activo y estructura.

El adaptador (pyHanko) lee el PDF y entrega los hechos como `DocumentFacts`, sin opinar. Lo que
se concluye de esos hechos (qué es riesgoso, qué es informativo, qué se explica) está acá, en
`analyze`. El análisis no cambia el veredicto de las firmas (`bottom_line` y el nivel PAdES los
decide la validación): lo explica y agrega lo que la validación no mira.

Reglas (los ids son los de docs/arquitectura/invariantes.md):

- D-01  Los permisos del cifrado estándar salen de los bits de `/P` (`Permissions.from_flags`).
- D-02  RC4, o una clave de menos de 128 bits, es un cifrado débil (`_protection_findings`).
- D-03  Un PDF que no abre sin contraseña no se puede analizar ni validar (contrato del puerto `PdfInspector`).
- D-04  Certificación (DocMDP): qué permite cada P, y que la certificación tiene que ser la primera firma.
- D-05  Lo agregado después de la última firma se clasifica por lo que toca (`classify_change`), y
        el riesgo es el del cambio más grave (`revision_severity`).
- D-06  Un formulario con NeedAppearances o con XFA puede mostrar algo distinto de lo firmado.
- D-07  JavaScript, acciones Launch y capas ocultas pueden cambiar lo que se ve sin tocar lo firmado.
- D-08  El diccionario de firma: ByteRange regular (empieza en 0, cuatro números, el hueco es el
        /Contents y llega al fin de su revisión) y SubFilter vigente (`_signature_findings`).
- D-09  Bytes después del último %%EOF y xref híbridas son irregularidades de estructura.
- D-10  El análisis nunca impide validar: lo que no se pudo leer es un hallazgo (`unreadable`).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum

# --------------------------------------------------------------------------- hallazgos


class Severity(StrEnum):
    INFO = "info"
    """Para saber: no cambia la confianza en lo firmado."""
    WARNING = "warning"
    """Conviene revisarlo: puede hacer que lo que se ve no sea exactamente lo firmado."""
    CRITICAL = "critical"
    """Lo que se ve, o lo que se firmó, pudo cambiar: no alcanza con que la firma sea válida."""


SEVERITY_ORDER = (Severity.CRITICAL, Severity.WARNING, Severity.INFO)


class Area(StrEnum):
    PROTECTION = "protection"
    FORM = "form"
    CONTENT = "content"
    ACTIVE_CONTENT = "active_content"
    SIGNATURE_DICTIONARY = "signature_dictionary"
    STRUCTURE = "structure"
    ANALYSIS = "analysis"


@dataclass(frozen=True)
class Finding:
    code: str
    """Estable, para que un cliente lo reconozca (p. ej. `need_appearances`)."""
    severity: Severity
    area: Area
    message: str


# --------------------------------------------------------------------------- protección


@dataclass(frozen=True)
class Permissions:
    """D-01: lo que permite el cifrado estándar, según los bits de `/P` (ISO 32000-2, tabla 22).

    Los bits se cuentan desde 1. Que un bit esté apagado prohíbe la operación, pero sólo los
    visores que respetan el estándar lo hacen cumplir: el que tiene la clave de propietario, o un
    programa que lo ignore, puede todo.
    """

    print: bool
    """Bit 3: imprimir (en baja calidad, si el bit 12 está apagado)."""
    modify: bool
    """Bit 4: modificar el contenido por otros medios que los de los bits 6, 9 y 11."""
    copy: bool
    """Bit 5: copiar o extraer texto e imágenes."""
    annotate: bool
    """Bit 6: agregar o modificar anotaciones y, con el bit 4, completar y crear campos."""
    fill_forms: bool
    """Bit 9: completar campos existentes, incluidos los de firma, aunque el bit 6 esté apagado."""
    accessibility: bool
    """Bit 10: extraer contenido para accesibilidad (obsoleto en PDF 2.0: siempre se permite)."""
    assemble: bool
    """Bit 11: insertar, rotar o borrar páginas y armar marcadores y miniaturas."""
    print_high_quality: bool
    """Bit 12: imprimir en alta calidad."""

    @classmethod
    def from_flags(cls, p: int) -> Permissions:
        def bit(n: int) -> bool:
            return bool(p & (1 << (n - 1)))

        return cls(bit(3), bit(4), bit(5), bit(6), bit(9), bit(10), bit(11), bit(12))

    @property
    def signing_allowed(self) -> bool:
        """Firmar es completar un campo de firma: hace falta el bit 9, o los bits 4 y 6."""
        return self.fill_forms or (self.modify and self.annotate)

    def denied(self) -> tuple[str, ...]:
        return tuple(name for name, allowed in vars(self).items() if not allowed)


@dataclass(frozen=True)
class Encryption:
    handler: str
    """El `/Filter` del diccionario `/Encrypt`: `/Standard` (contraseñas) o `/Adobe.PubSec` (certificados)."""
    algorithm: str
    """`RC4`, `AES-128`, `AES-256` o el nombre del método si es otro."""
    key_bits: int | None
    version: int | None
    """`/V`: la versión del algoritmo."""
    revision: int | None
    """`/R`: la revisión del handler estándar; None con certificados."""
    encrypt_metadata: bool
    permissions: Permissions | None
    """Sólo con el handler estándar; None con certificados (cada destinatario tiene los suyos)."""


DOCMDP_MEANING = {
    1: "No se permite ningún cambio: cualquier modificación, incluida otra firma, invalida la certificación.",
    2: "Se permite completar formularios, firmar campos de firma existentes y crear sellos de documento.",
    3: "Además de lo de P=2, se permite agregar, modificar y borrar anotaciones.",
}


@dataclass(frozen=True)
class Certification:
    """D-04: una firma de certificación (DocMDP), la que fija qué cambios se aceptan después."""

    field_name: str
    permission: int
    """1, 2 o 3."""
    first_signature: bool
    """Si es la primera firma del documento, como exige ISO 32000."""

    @property
    def meaning(self) -> str:
        return DOCMDP_MEANING.get(self.permission, f"P={self.permission} no está definido en ISO 32000.")


@dataclass(frozen=True)
class FieldLock:
    """Un bloqueo de campos (FieldMDP, `/Lock` del campo de firma): qué campos no pueden cambiar una vez firmado."""

    field_name: str
    action: str
    """`All` (todos los campos), `Include` (los de `fields`) o `Exclude` (todos menos los de `fields`)."""
    fields: tuple[str, ...]


@dataclass(frozen=True)
class Protection:
    encryption: Encryption | None
    certification: Certification | None
    field_locks: tuple[FieldLock, ...]
    usage_rights: bool
    """`/Perms /UR3`: derechos de uso de Adobe Reader (habilitan funciones en Reader; no son una firma de autor)."""


# --------------------------------------------------------------------------- formulario


class FieldKind(StrEnum):
    TEXT = "text"
    CHECKBOX = "checkbox"
    RADIO = "radio"
    PUSHBUTTON = "pushbutton"
    CHOICE = "choice"
    SIGNATURE = "signature"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class FormField:
    name: str
    """El nombre completo (con los de sus padres, separados por punto)."""
    kind: FieldKind
    value: str | None
    """El valor (`/V`) como texto; para una firma, None (la firma se describe aparte)."""
    read_only: bool
    required: bool
    signed: bool
    """Sólo para campos de firma: si tiene una firma (`/V`)."""
    has_actions: bool
    """Si el campo o sus widgets tienen acciones (`/A`, `/AA`): cálculos, formato, validación."""


@dataclass(frozen=True)
class Form:
    fields: tuple[FormField, ...]
    need_appearances: bool
    xfa: bool

    @property
    def empty_signature_fields(self) -> tuple[str, ...]:
        return tuple(f.name for f in self.fields if f.kind is FieldKind.SIGNATURE and not f.signed)


# --------------------------------------------------------------------------- revisiones


class ChangeKind(StrEnum):
    """Qué es un objeto escrito en una revisión, por su rol en el documento."""

    PAGE_CONTENT = "page_content"
    """Un stream de contenido de página: lo que se dibuja."""
    PAGE = "page"
    """El diccionario de una página."""
    PAGE_TREE = "page_tree"
    """Un nodo `/Pages`: qué páginas hay y en qué orden."""
    RESOURCE = "resource"
    """Fuentes, imágenes y XObjects: lo que el contenido usa para dibujar."""
    ANNOTATION = "annotation"
    """Una anotación que no es un widget de formulario (comentarios, sellos, texto libre, links)."""
    FORM_FIELD = "form_field"
    """Un campo de formulario que no es de firma, o su widget."""
    SIGNATURE = "signature"
    """Un campo de firma, su widget o su diccionario de firma o de sello de documento (`/Sig`, `/DocTimeStamp`)."""
    DSS = "dss"
    """El DSS y lo que contiene (certificados, OCSP, CRLs, VRI)."""
    ACROFORM = "acroform"
    """El diccionario `/AcroForm`."""
    CATALOG = "catalog"
    """El catálogo (`/Root`)."""
    METADATA = "metadata"
    """`/Info` o el XMP."""
    EMBEDDED_FILE = "embedded_file"
    ACTION = "action"
    """Una acción o un script (JavaScript, Launch, ...)."""
    STRUCTURE = "structure"
    """Objetos internos del archivo (object streams, xref streams)."""
    OTHER = "other"


class ChangeType(StrEnum):
    ADDED = "added"
    """El objeto no existía antes."""
    MODIFIED = "modified"
    """Reemplaza la versión de una revisión anterior."""
    FREED = "freed"
    """La xref lo marca como libre: lo borra (o, si nunca existió, no hace nada)."""


@dataclass(frozen=True)
class ObjectChange:
    """Un objeto escrito (o liberado) en una revisión."""

    object_ref: str
    """`número generación`, p. ej. `5 0`."""
    kind: ChangeKind
    """Para uno liberado, lo que era; `STRUCTURE` si nunca existió (como las entradas libres de iText)."""
    change: ChangeType
    page: int | None
    """La página a la que pertenece (desde 1), si se sabe."""
    keys: tuple[str, ...]
    """Si es un diccionario modificado: las claves que cambiaron (agregadas, quitadas o con otro valor).
    Las de un diccionario directo anidado van con su camino, p. ej. `/AcroForm/NeedAppearances`."""
    subtype: str | None = None
    """El `/Subtype` de una anotación o un XObject, o el `/S` de una acción."""


@dataclass(frozen=True)
class Revision:
    number: int
    """Desde 1, la original."""
    end_offset: int
    """El byte siguiente al `%%EOF` de la revisión."""
    xref: str
    """`table`, `stream` o `hybrid`."""
    objects: int
    """Cuántos objetos se escribieron (para la original, todos)."""
    changes: tuple[ObjectChange, ...]
    """Los objetos escritos, clasificados. Vacío para la revisión original."""
    pages: int | None
    """Cuántas páginas tiene el documento en esta revisión."""


# El catálogo cambia con cualquier firma o LTV: estas claves no tocan lo que se ve.
CATALOG_MAINTENANCE_KEYS = frozenset({"/AcroForm", "/DSS", "/Extensions", "/Perms", "/Version", "/Metadata"})
# Estas sí: qué páginas hay, qué se ejecuta al abrir y qué capas se ven.
CATALOG_CRITICAL_KEYS = frozenset({"/Pages", "/OpenAction", "/AA", "/OCProperties", "/Collection", "/NeedsRendering"})
# Al agregar una firma (visible o no) o una anotación, la página cambia sólo en /Annots: el riesgo
# es el de lo agregado, que se clasifica aparte.
PAGE_ANNOTATION_KEYS = frozenset({"/Annots"})
# Claves de /AcroForm que cambian al agregar un campo de firma.
ACROFORM_MAINTENANCE_KEYS = frozenset({"/Fields", "/SigFlags", "/DA", "/DR"})


def classify_change(change: ObjectChange) -> Severity:
    """D-05: el riesgo de un objeto escrito después de firmar.

    Crítico lo que cambia lo que se dibuja: contenido de página, recursos, páginas (salvo su lista
    de anotaciones) o el árbol de páginas, acciones, y las claves del catálogo que deciden qué se
    ve (`/Pages`, `/OpenAction`, `/OCProperties`, ...). Advertencia: anotaciones, campos de
    formulario, archivos adjuntos y otras claves del catálogo (`/Names`, `/OutputIntents`, ...),
    que un DocMDP puede permitir pero cambian lo que se ve o lo que se entrega. Informativo:
    firmas, DSS, metadatos y la estructura del archivo.
    """
    kind = change.kind
    keys = {k for k in change.keys if not k.startswith("/AcroForm/")}
    acroform_keys = {k.removeprefix("/AcroForm") for k in change.keys if k.startswith("/AcroForm/")}
    if kind is ChangeKind.CATALOG and acroform_keys:  # el /AcroForm directo, dentro del catálogo
        worst = classify_change(ObjectChange(change.object_ref, ChangeKind.ACROFORM, ChangeType.MODIFIED, None, tuple(acroform_keys)))
        rest = classify_change(ObjectChange(change.object_ref, kind, change.change, None, tuple(keys)))
        return next(s for s in SEVERITY_ORDER if s in (worst, rest))
    if kind in (ChangeKind.PAGE_CONTENT, ChangeKind.RESOURCE, ChangeKind.PAGE_TREE, ChangeKind.ACTION):
        return Severity.CRITICAL
    if kind is ChangeKind.PAGE:
        return Severity.INFO if change.change is ChangeType.MODIFIED and keys <= PAGE_ANNOTATION_KEYS else Severity.CRITICAL
    if kind is ChangeKind.CATALOG:
        if keys <= CATALOG_MAINTENANCE_KEYS:
            return Severity.INFO
        return Severity.CRITICAL if keys & CATALOG_CRITICAL_KEYS else Severity.WARNING
    if kind is ChangeKind.ACROFORM:
        return Severity.INFO if set(change.keys) <= ACROFORM_MAINTENANCE_KEYS else Severity.WARNING
    if kind in (ChangeKind.ANNOTATION, ChangeKind.FORM_FIELD, ChangeKind.EMBEDDED_FILE, ChangeKind.OTHER):
        return Severity.WARNING
    return Severity.INFO


def revision_severity(changes: Iterable[ObjectChange]) -> Severity:
    """D-05: el riesgo de una revisión es el de su cambio más grave."""
    found = {classify_change(c) for c in changes}
    return next((s for s in SEVERITY_ORDER if s in found), Severity.INFO)


# --------------------------------------------------------------------------- contenido activo


@dataclass(frozen=True)
class Action:
    type: str
    """`JavaScript`, `Launch`, `URI`, `SubmitForm`, `ImportData`, `GoToR`, `GoToE`, ..."""
    location: str
    """Dónde está, p. ej. `/OpenAction`, `/Names /JavaScript «init»`, `página 1, anotación /Link`, `campo total`."""


@dataclass(frozen=True)
class EmbeddedFile:
    name: str
    size: int | None
    mime_type: str | None


@dataclass(frozen=True)
class OptionalContent:
    groups: int
    hidden: int
    """Cuántas capas están apagadas en la configuración por defecto (`/D /OFF`)."""


@dataclass(frozen=True)
class ActiveContent:
    actions: tuple[Action, ...]
    embedded_files: tuple[EmbeddedFile, ...]
    optional_content: OptionalContent | None


# Acciones que ejecutan algo (o cambian lo que se ve) y las que sólo navegan o envían.
EXECUTING_ACTIONS = frozenset({"JavaScript", "Launch", "ImportData", "Rendition", "SetOCGState", "Hide"})


# --------------------------------------------------------------------------- diccionario de firma


SUBFILTERS = {
    "/ETSI.CAdES.detached": (Severity.INFO, None),
    "/ETSI.RFC3161": (Severity.INFO, None),
    "/adbe.pkcs7.detached": (
        Severity.INFO,
        "Firma PDF clásica (CMS detached, ISO 32000): es válida, pero no es PAdES y no puede pasar de B-B en "
        "un validador ETSI estricto.",
    ),
    "/adbe.pkcs7.sha1": (
        Severity.WARNING,
        "SubFilter obsoleto en PDF 2.0: el CMS firma un hash SHA-1 del documento, que ya no se considera seguro.",
    ),
    "/adbe.x509.rsa_sha1": (
        Severity.WARNING,
        "SubFilter obsoleto en PDF 2.0: una firma RSA desnuda (PKCS#1) sin CMS, con el certificado en /Cert.",
    ),
}


@dataclass(frozen=True)
class SignatureDictionary:
    """El diccionario de una firma (`/Sig`) o de un sello de documento (`/DocTimeStamp`), tal como está en el PDF."""

    field_name: str
    type: str
    filter: str | None
    subfilter: str | None
    byte_range: tuple[int, ...]
    revision: int
    """La revisión que firma (desde 1)."""
    revision_end: int
    """El fin de esa revisión (el byte después de su `%%EOF`)."""
    gap_is_contents: bool
    """Si el hueco del ByteRange es exactamente el string hexadecimal `/Contents` (`<...>`)."""
    contents_capacity: int
    """Bytes reservados para la firma en `/Contents`."""
    contents_used: int
    """Bytes que ocupa el CMS (el resto es relleno con ceros)."""
    signing_time: str | None
    """`/M` tal como está (fecha PDF, p. ej. `D:20261020120000+00'00'`)."""
    name: str | None
    reason: str | None
    location: str | None
    contact_info: str | None
    application: str | None
    """`/Prop_Build /App /Name`: el programa que firmó, si lo declara."""
    references: tuple[str, ...]
    """Los métodos de transformación de `/Reference` (`DocMDP`, `FieldMDP`, `UR3`)."""
    visible: bool
    """Si el widget de la firma tiene un rectángulo con área."""
    page: int | None

    @property
    def byte_range_regular(self) -> bool:
        br = self.byte_range
        return len(br) == 4 and br[0] == 0 and br[1] < br[2] and self.gap_is_contents

    @property
    def covers_revision(self) -> bool:
        """Si el ByteRange llega exactamente al fin de su revisión."""
        return len(self.byte_range) == 4 and self.byte_range[2] + self.byte_range[3] == self.revision_end


# --------------------------------------------------------------------------- estructura


@dataclass(frozen=True)
class Structure:
    header_version: str
    """La versión de la cabecera `%PDF-x.y`."""
    catalog_version: str | None
    """`/Version` del catálogo, que reemplaza a la de la cabecera si es mayor (lo usan las actualizaciones incrementales)."""
    pages: int
    hybrid_xref: bool
    object_streams: bool
    linearized: bool
    tagged: bool
    pdfa: str | None
    """La conformidad PDF/A que declara el XMP (p. ej. `2B`); None si no declara."""
    producer: str | None
    creator: str | None
    trailing_bytes: int
    """Bytes después del último `%%EOF` y su fin de línea."""
    trailing_padding: bool
    """Si esos bytes son sólo relleno (espacios, saltos de línea, ceros)."""
    extensions: tuple[str, ...]
    """Las extensiones de desarrollador del catálogo (`/Extensions`), como `ADBE 8` o `ESIC 1`."""

    @property
    def version(self) -> str:
        if self.catalog_version and _version_tuple(self.catalog_version) > _version_tuple(self.header_version):
            return self.catalog_version
        return self.header_version


def _version_tuple(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError:
        return (0,)


# --------------------------------------------------------------------------- hechos y análisis


@dataclass(frozen=True)
class SignedRevision:
    """Qué firma cubre hasta qué revisión: lo necesario para saber qué se agregó después."""

    field_name: str
    revision: int
    """Desde 1."""
    doc_timestamp: bool


@dataclass(frozen=True)
class DocumentFacts:
    """Lo que el adaptador lee del PDF. Cada sección es None si no se pudo leer (D-10)."""

    structure: Structure | None
    protection: Protection | None
    form: Form | None
    """None también si el documento no tiene formulario: ver `unreadable`."""
    active_content: ActiveContent | None
    revisions: tuple[Revision, ...]
    signatures: tuple[SignatureDictionary, ...]
    unreadable: tuple[tuple[str, str], ...] = ()
    """D-10: (sección, motivo) de lo que no se pudo leer."""


@dataclass(frozen=True)
class RevisionVerdict:
    revision: Revision
    signed_by: tuple[str, ...]
    """Las firmas (y sellos de documento) que terminan en esta revisión."""
    after_signature: bool
    """Si se escribió después de la primera firma: lo que agrega no lo cubre esa firma."""
    severity: Severity
    """El riesgo de lo que agrega, si es posterior a una firma; INFO si no."""


@dataclass(frozen=True)
class DocumentAnalysis:
    facts: DocumentFacts
    revisions: tuple[RevisionVerdict, ...]
    findings: tuple[Finding, ...]
    """Ordenados de más a menos grave."""


def revision_verdicts(revisions: Sequence[Revision], signatures: Sequence[SignatureDictionary]) -> tuple[RevisionVerdict, ...]:
    """D-05: cada revisión con las firmas que la cierran y, si es posterior a una firma, su riesgo."""
    first_signed = min((s.revision for s in signatures if s.type != "/DocTimeStamp"), default=None)
    out = []
    for rev in revisions:
        after = first_signed is not None and rev.number > first_signed
        out.append(
            RevisionVerdict(
                revision=rev,
                signed_by=tuple(s.field_name for s in signatures if s.revision == rev.number),
                after_signature=after,
                severity=revision_severity(rev.changes) if after else Severity.INFO,
            )
        )
    return tuple(out)


def analyze(facts: DocumentFacts) -> DocumentAnalysis:
    """Los hallazgos del documento, de más a menos grave (en el orden de las reglas dentro de cada severidad)."""
    revisions = revision_verdicts(facts.revisions, facts.signatures)
    findings = [
        *_protection_findings(facts.protection, facts.structure),
        *_revision_findings(revisions, facts.signatures),
        *_form_findings(facts.form),
        *_active_content_findings(facts.active_content, facts.structure),
        *_signature_findings(facts.signatures),
        *_structure_findings(facts.structure),
        *(
            Finding("unreadable", Severity.WARNING, Area.ANALYSIS, f"No se pudo analizar {section}: {reason}")
            for section, reason in facts.unreadable
        ),
    ]
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    return DocumentAnalysis(facts, revisions, tuple(findings))


def _protection_findings(protection: Protection | None, structure: Structure | None) -> list[Finding]:
    if protection is None:
        return []
    out = []
    enc = protection.encryption
    if enc:
        detail = f"{enc.algorithm}" + (f" de {enc.key_bits} bits" if enc.key_bits else "")
        out.append(
            Finding(
                "encrypted",
                Severity.INFO,
                Area.PROTECTION,
                f"El documento está cifrado ({detail}, handler {enc.handler}) y abre sin contraseña: tiene sólo "
                "contraseña de propietario. Strings y streams están cifrados; "
                "la estructura (objetos, xref, /ByteRange) no, y el /Contents de cada firma tampoco.",
            )
        )
        if enc.algorithm == "RC4" or (enc.key_bits is not None and enc.key_bits < 128):  # D-02
            out.append(
                Finding(
                    "weak_encryption",
                    Severity.WARNING,
                    Area.PROTECTION,
                    f"El cifrado ({detail}) es débil y está obsoleto en PDF 2.0: no protege el contenido.",
                )
            )
        if enc.permissions:
            denied = enc.permissions.denied()
            if denied:
                out.append(
                    Finding(
                        "restricted_permissions",
                        Severity.INFO,
                        Area.PROTECTION,
                        f"Permisos restringidos: no permite {', '.join(denied)}. Son una indicación para el visor, "
                        "no una protección: quien tiene la clave de propietario (o un programa que los ignore) puede todo.",
                    )
                )
            if not enc.permissions.signing_allowed:
                out.append(
                    Finding(
                        "signing_not_permitted",
                        Severity.WARNING,
                        Area.PROTECTION,
                        "Los permisos no admiten completar campos de firma (bit 9, ni bits 4 y 6): un visor que los "
                        "respete no deja firmarlo.",
                    )
                )
        if structure and structure.pdfa:
            out.append(
                Finding("pdfa_encrypted", Severity.WARNING, Area.PROTECTION, f"Declara PDF/A-{structure.pdfa}, que prohíbe el cifrado.")
            )
    cert = protection.certification
    if cert:  # D-04
        out.append(
            Finding(
                "certified",
                Severity.INFO,
                Area.PROTECTION,
                f"Certificado por la firma {cert.field_name} con DocMDP P={cert.permission}. {cert.meaning}",
            )
        )
        if not cert.first_signature:
            out.append(
                Finding(
                    "certification_not_first",
                    Severity.CRITICAL,
                    Area.PROTECTION,
                    f"La firma de certificación {cert.field_name} no es la primera del documento: ISO 32000 sólo "
                    "admite certificar antes de cualquier otra firma, y los validadores la desconocen.",
                )
            )
    for lock in protection.field_locks:
        which = {
            "All": "todos los campos",
            "Include": f"los campos {', '.join(lock.fields)}",
            "Exclude": f"todos los campos salvo {', '.join(lock.fields)}",
        }.get(lock.action, f"campos ({lock.action})")
        out.append(
            Finding(
                "field_lock",
                Severity.INFO,
                Area.PROTECTION,
                f"La firma {lock.field_name} bloquea {which} (FieldMDP): cambiarlos después la invalida.",
            )
        )
    if protection.usage_rights:
        out.append(
            Finding(
                "usage_rights",
                Severity.INFO,
                Area.PROTECTION,
                "Tiene derechos de uso de Adobe Reader (/Perms /UR3): habilitan funciones en Reader. No son una firma "
                "de autor, y una modificación posterior los invalida sin afectar las firmas.",
            )
        )
    return out


AFTER_SIGNATURE = {
    Severity.CRITICAL: (
        "content_changed_after_signing",
        "cambia lo que se ve: {kinds}. Las firmas anteriores siguen íntegras para su revisión, pero el documento "
        "que se muestra ya no es el firmado.",
    ),
    Severity.WARNING: (
        "annotations_or_fields_after_signing",
        "agrega o cambia {kinds}. Puede estar permitido (DocMDP, formularios), pero lo que se ve no es exactamente lo firmado.",
    ),
}
KIND_NAMES = {
    ChangeKind.PAGE_CONTENT: "contenido de página",
    ChangeKind.PAGE: "páginas",
    ChangeKind.PAGE_TREE: "el árbol de páginas",
    ChangeKind.RESOURCE: "fuentes o imágenes",
    ChangeKind.ANNOTATION: "anotaciones",
    ChangeKind.FORM_FIELD: "campos de formulario",
    ChangeKind.SIGNATURE: "firmas",
    ChangeKind.DSS: "el DSS",
    ChangeKind.ACROFORM: "el formulario",
    ChangeKind.CATALOG: "el catálogo",
    ChangeKind.METADATA: "metadatos",
    ChangeKind.EMBEDDED_FILE: "archivos adjuntos",
    ChangeKind.ACTION: "acciones",
    ChangeKind.STRUCTURE: "estructura",
    ChangeKind.OTHER: "otros objetos",
}


def _revision_findings(revisions: Sequence[RevisionVerdict], signatures: Sequence[SignatureDictionary]) -> list[Finding]:
    """D-05: lo agregado después de firmar, revisión por revisión, y la última revisión sin firmar."""
    out = []
    for verdict in revisions:
        if not verdict.after_signature or verdict.severity is Severity.INFO:
            continue
        code, text = AFTER_SIGNATURE[verdict.severity]
        risky = [c for c in verdict.revision.changes if classify_change(c) is verdict.severity]
        kinds = ", ".join(dict.fromkeys(KIND_NAMES[c.kind] for c in risky))
        out.append(Finding(code, verdict.severity, Area.CONTENT, f"La revisión {verdict.revision.number} " + text.format(kinds=kinds)))
    if revisions and signatures:
        last = revisions[-1]
        if last.after_signature and not last.signed_by and last.severity is Severity.INFO:
            out.append(
                Finding(
                    "unsigned_last_revision",
                    Severity.INFO,
                    Area.CONTENT,
                    f"La última revisión ({last.revision.number}) no está firmada: agrega sólo material de "
                    "mantenimiento (DSS, firmas, metadatos), que no cambia lo que se ve.",
                )
            )
    pages = [v.revision.pages for v in revisions if v.after_signature or v.signed_by]
    known = [p for p in pages if p is not None]
    if len(set(known)) > 1:
        out.append(
            Finding(
                "page_count_changed",
                Severity.CRITICAL,
                Area.CONTENT,
                f"La cantidad de páginas cambió después de firmar ({' → '.join(str(p) for p in dict.fromkeys(known))}).",
            )
        )
    return out


def _form_findings(form: Form | None) -> list[Finding]:
    if form is None:
        return []
    out = []
    if form.need_appearances:  # D-06
        out.append(
            Finding(
                "need_appearances",
                Severity.WARNING,
                Area.FORM,
                "El formulario tiene NeedAppearances: el visor regenera la apariencia de los campos al abrirlo, así que "
                "lo que muestra puede no ser lo que se firmó, y Acrobat lo puede marcar como modificado.",
            )
        )
    if form.xfa:  # D-06
        out.append(
            Finding(
                "xfa",
                Severity.WARNING,
                Area.FORM,
                "El formulario trae XFA: los visores que lo interpretan dibujan el formulario a partir del XML y no del "
                "contenido de las páginas. XFA está obsoleto en PDF 2.0 y no está cubierto por PAdES.",
            )
        )
    empty = form.empty_signature_fields
    if empty:
        out.append(
            Finding(
                "empty_signature_fields",
                Severity.INFO,
                Area.FORM,
                f"Campos de firma sin firmar: {', '.join(empty)}.",
            )
        )
    scripted = [f.name for f in form.fields if f.has_actions]
    if scripted:
        out.append(
            Finding(
                "field_actions",
                Severity.INFO,
                Area.FORM,
                f"Campos con acciones (cálculo, formato o validación): {', '.join(scripted)}.",
            )
        )
    return out


def _active_content_findings(active: ActiveContent | None, structure: Structure | None) -> list[Finding]:
    if active is None:
        return []
    out = []
    executing = [a for a in active.actions if a.type in EXECUTING_ACTIONS]
    if executing:  # D-07
        where = "; ".join(f"{a.type} en {a.location}" for a in executing)
        severity = Severity.CRITICAL if any(a.type == "Launch" for a in executing) else Severity.WARNING
        out.append(
            Finding(
                "executable_actions",
                severity,
                Area.ACTIVE_CONTENT,
                f"Tiene acciones que se ejecutan en el visor ({where}). Pueden cambiar lo que se muestra, o abrir "
                "programas, sin tocar los bytes firmados.",
            )
        )
        if structure and structure.pdfa:
            out.append(
                Finding("pdfa_actions", Severity.WARNING, Area.ACTIVE_CONTENT, f"Declara PDF/A-{structure.pdfa}, que prohíbe JavaScript y Launch.")
            )
    others = [a for a in active.actions if a.type not in EXECUTING_ACTIONS]
    if others:
        out.append(
            Finding(
                "navigation_actions",
                Severity.INFO,
                Area.ACTIVE_CONTENT,
                "Acciones de navegación o envío: " + "; ".join(f"{a.type} en {a.location}" for a in others) + ".",
            )
        )
    if active.embedded_files:
        names = ", ".join(f.name for f in active.embedded_files)
        out.append(
            Finding(
                "embedded_files",
                Severity.INFO,
                Area.ACTIVE_CONTENT,
                f"Archivos adjuntos: {names}. La firma cubre sus bytes, pero no lo que muestren al abrirlos aparte.",
            )
        )
    oc = active.optional_content
    if oc and oc.hidden:  # D-07
        out.append(
            Finding(
                "hidden_layers",
                Severity.WARNING,
                Area.ACTIVE_CONTENT,
                f"Tiene {oc.groups} capas (contenido opcional) y {oc.hidden} están ocultas por defecto: hay contenido "
                "firmado que no se ve, y un visor puede mostrarlo distinto.",
            )
        )
    return out


def _signature_findings(signatures: Sequence[SignatureDictionary]) -> list[Finding]:
    """D-08: el ByteRange y el SubFilter de cada firma."""
    out = []
    for sig in signatures:
        if not sig.byte_range_regular:
            out.append(
                Finding(
                    "irregular_byte_range",
                    Severity.CRITICAL,
                    Area.SIGNATURE_DICTIONARY,
                    f"El /ByteRange de {sig.field_name} ({list(sig.byte_range)}) no es regular: tiene que tener cuatro "
                    "números, empezar en 0 y dejar afuera exactamente el /Contents. Es la forma de los ataques que "
                    "esconden contenido fuera de lo firmado.",
                )
            )
        elif not sig.covers_revision:
            out.append(
                Finding(
                    "byte_range_not_revision",
                    Severity.CRITICAL,
                    Area.SIGNATURE_DICTIONARY,
                    f"El /ByteRange de {sig.field_name} no termina en el %%EOF de su revisión ({sig.revision}): firma un "
                    "bloque que no es una revisión completa.",
                )
            )
        severity, note = SUBFILTERS.get(
            sig.subfilter or "", (Severity.WARNING, f"SubFilter desconocido ({sig.subfilter}): un validador puede no saber interpretarlo.")
        )
        if note:
            out.append(Finding(f"subfilter:{(sig.subfilter or '').lstrip('/')}", severity, Area.SIGNATURE_DICTIONARY, f"{sig.field_name}: {note}"))
    return out


def _structure_findings(structure: Structure | None) -> list[Finding]:
    if structure is None:
        return []
    out = []
    if structure.trailing_bytes:  # D-09
        if structure.trailing_padding:
            out.append(
                Finding(
                    "trailing_padding",
                    Severity.INFO,
                    Area.STRUCTURE,
                    f"Hay {structure.trailing_bytes} bytes de relleno (espacios o ceros) después del último %%EOF, como "
                    "dejan algunos sistemas de correo o almacenamiento. Ninguna firma los cubre, y no son parte del documento.",
                )
            )
        else:
            out.append(
                Finding(
                    "trailing_bytes",
                    Severity.WARNING,
                    Area.STRUCTURE,
                    f"Hay {structure.trailing_bytes} bytes después del último %%EOF que no son relleno: ninguna firma los "
                    "cubre y no forman parte del documento, pero un lector tolerante podría interpretarlos.",
                )
            )
    if structure.hybrid_xref:  # D-09
        out.append(
            Finding(
                "hybrid_xref",
                Severity.WARNING,
                Area.STRUCTURE,
                "Usa referencias cruzadas híbridas (tabla y stream a la vez): un lector viejo y uno nuevo pueden ver "
                "objetos distintos.",
            )
        )
    if structure.linearized:
        out.append(
            Finding(
                "linearized",
                Severity.INFO,
                Area.STRUCTURE,
                "Está linealizado (optimizado para la web): una actualización incremental, como una firma, deja la "
                "linealización sin efecto, sin consecuencias para la validez.",
            )
        )
    return out
