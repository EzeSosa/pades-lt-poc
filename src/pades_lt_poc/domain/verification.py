"""Validación de las firmas de un PDF: opciones, anclas, nivel PAdES, uso de la fuente y por qué no es confiable.

La verificación criptográfica, la construcción de caminos y la revocación las hace el adaptador
(pyHanko) y llegan como `SignatureEvaluation`. Lo que se decide con eso está acá.

Reglas (los ids son los de docs/arquitectura/invariantes.md):

- V-01  Las anclas son las implícitas (la raíz de la PoC) más las raíces confiables y habilitadas
        de la fuente (`trust_anchors`).
- V-02  SHA-1 se acepta sólo en lo que firman las raíces confiables que nacieron con SHA-1
        (`legacy_sha1_roots`).
- V-03  La revocación es siempre obligatoria (`ValidationPolicy`: el adaptador valida en hard-fail).
- V-04  Con conexión sólo se valida a la hora actual (`VerificationOptions.check`).
- V-05  Con conexión, o si alguna cadena se completó con la fuente, el nivel no pasa de B-T (`pades_level`).
- V-06  `completed_from_store`: intermedios del camino que no trae el PDF y sí la fuente, sólo si
        la firma es confiable (`completed_from_store`).
- V-07  Los niveles B-B, B-T, B-LT y B-LTA (`pades_level`).
- V-08  Con la hora declarada se valida en el pasado y se avisa que no está probada (`validation_moment`).
- V-09  El motivo de desconfianza aparece sólo si no es confiable (`trust_problem`).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from .certificates import Certificate
from .errors import UnprocessableInput
from .signatures import SignatureKind

# --------------------------------------------------------------------------- opciones


class ValidationTimeMode(StrEnum):
    NOW = "now"
    """A la hora actual."""
    CLAIMED_SIGNING_TIME = "claimed_signing_time"
    """A la hora que declara cada firma (no probada)."""


class DiffPolicyMode(StrEnum):
    DEFAULT = "default"
    """El análisis de modificaciones de pyHanko."""
    ALLOW_UNALLOCATED_FREE_ENTRIES = "allow_unallocated_free_entries"
    """Además acepta entradas libres de objetos que nunca existieron (iText)."""


class RevocationMode(StrEnum):
    OFFLINE = "offline"
    """Sólo la revocación que trae el PDF."""
    ONLINE = "online"
    """Además descarga CRL, OCSP y emisores de las URLs de cada certificado."""


ONLINE_ONLY_NOW = "Con conexión sólo se valida a la hora actual: la revocación que se descarga es de hoy."

ONLINE_NOTE = (
    "Se validó con conexión: además de la revocación que trae el PDF se descargaron CRL y "
    "OCSP actualizadas (y los emisores que faltaban, por AIA) de las URLs de cada certificado. "
    "Una CRL ya descargada se reusa hasta su próxima actualización, porque la CA no publica otra antes. "
    "El resultado dice si las firmas son confiables hoy, no si el PDF alcanza solo: por eso el "
    "nivel alcanzado no pasa de B-T. Para evaluar LT, validá sin conexión."
)

UNALLOCATED_FREES_NOTE = (
    "Se aceptaron entradas libres de la xref para números de objeto que no existían en la "
    "revisión anterior (p. ej. `178 65535 f` de iText): no borran nada. El resto del análisis "
    "de modificaciones es el de pyHanko por defecto."
)

CLAIMED_TIME_WARNING = (
    "Validado a la hora de firma que declara el propio firmante, no a una hora probada por "
    "un sello de tiempo: el firmante pudo haberla elegido. Además se acepta revocación emitida "
    "después de esa hora, lo que no detecta suspensiones levantadas. No prueba que la firma sea LT."
)

STORE_NOTE = (
    "La cadena de alguna firma se completó con certificados de la fuente que el PDF no trae. "
    "La validación es correcta, pero el PDF no es LT por sí mismo: otro validador sin esos "
    "certificados no podría validarlo. Por eso el nivel alcanzado no pasa de B-T."
)


@dataclass(frozen=True)
class VerificationOptions:
    validation_time: ValidationTimeMode = ValidationTimeMode.NOW
    diff_policy: DiffPolicyMode = DiffPolicyMode.DEFAULT
    revocation: RevocationMode = RevocationMode.OFFLINE

    @property
    def online(self) -> bool:
        return self.revocation is RevocationMode.ONLINE

    def check(self) -> None:
        """V-04: con conexión, sólo a la hora actual."""
        if self.online and self.validation_time is not ValidationTimeMode.NOW:
            raise UnprocessableInput(ONLINE_ONLY_NOW)

    @property
    def warning(self) -> str | None:
        return CLAIMED_TIME_WARNING if self.validation_time is ValidationTimeMode.CLAIMED_SIGNING_TIME else None

    @property
    def diff_policy_note(self) -> str | None:
        return UNALLOCATED_FREES_NOTE if self.diff_policy is DiffPolicyMode.ALLOW_UNALLOCATED_FREE_ENTRIES else None

    @property
    def revocation_note(self) -> str | None:
        return ONLINE_NOTE if self.online else None


# --------------------------------------------------------------------------- anclas y política


def trust_anchors(implicit: Sequence[Certificate], trusted_roots: Sequence[Certificate]) -> tuple[Certificate, ...]:
    """V-01: las anclas implícitas primero (la raíz de la PoC) y después las raíces confiables de la fuente."""
    return (*implicit, *trusted_roots)


def legacy_sha1_roots(anchors: Iterable[Certificate]) -> tuple[Certificate, ...]:
    """V-02: las anclas que nacieron con SHA-1 (su propia firma es SHA-1). Lo que firman con su clave
    se acepta en SHA-1; los firmantes, las TSAs y las demás CAs siguen sin poder usarlo."""
    return tuple(a for a in anchors if a.signature_hash_algorithm == "sha1")


@dataclass(frozen=True)
class ValidationPolicy:
    """Lo que el adaptador necesita para validar. La revocación es siempre obligatoria (V-03)."""

    trust_anchors: tuple[Certificate, ...]
    intermediates: tuple[Certificate, ...]
    """Intermedios de la fuente para completar caminos (además de los del PDF)."""
    legacy_sha1_roots: tuple[Certificate, ...]
    diff_policy: DiffPolicyMode
    online: bool


@dataclass(frozen=True)
class ValidatedAt:
    time: datetime
    source: ValidationTimeMode
    """`now` o `claimed_signing_time`: a qué hora se validó en realidad."""

    @property
    def in_the_past(self) -> bool:
        return self.source is ValidationTimeMode.CLAIMED_SIGNING_TIME


def validation_moment(mode: ValidationTimeMode, claimed: datetime | None, now: datetime) -> ValidatedAt:
    """V-08: la hora declarada si se la pidió y la firma declara una; si no, la actual."""
    if mode is ValidationTimeMode.CLAIMED_SIGNING_TIME and claimed is not None:
        return ValidatedAt(claimed, ValidationTimeMode.CLAIMED_SIGNING_TIME)
    return ValidatedAt(now, ValidationTimeMode.NOW)


# --------------------------------------------------------------------------- por qué no es confiable


class TrustReason(StrEnum):
    """Por qué falla un camino, o el resumen de por qué no es confiable."""

    REVOKED = "revoked"
    STALE_REVOCATION = "stale_revocation"
    MISSING_REVOCATION = "missing_revocation"
    ALGORITHM = "algorithm"
    OTHER = "other"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    # Sólo como resumen:
    NO_PATH = "no_path"
    NOT_EVALUATED = "not_evaluated"


# Motivo -> resumen. Ordenados de más a menos informativo: si hay varios caminos, se resume con el
# primero de esta lista que aparezca. Un camino que falla por un certificado vencido suele ser una
# versión vieja de una CA renovada: va al final.
REASONS = {
    TrustReason.REVOKED: "Un certificado de la cadena está revocado.",
    TrustReason.STALE_REVOCATION: (
        "La revocación que trae el PDF (CRL u OCSP) ya no está vigente a la hora de validación, "
        "y sin conexión no se puede conseguir una más nueva."
    ),
    TrustReason.MISSING_REVOCATION: (
        "El PDF no trae revocación (CRL u OCSP) para algún certificado de la cadena, y sin "
        "conexión no se puede conseguir."
    ),
    TrustReason.ALGORITHM: "La cadena usa un algoritmo que la política no permite (p. ej. SHA-1).",
    TrustReason.OTHER: "La cadena no valida.",
    TrustReason.NOT_YET_VALID: "Un certificado de la cadena todavía no es vigente a la hora de validación.",
    TrustReason.EXPIRED: "Un certificado de la cadena está vencido a la hora de validación.",
}
# Con conexión, la revocación también se intentó descargar.
ONLINE_REASONS = {
    TrustReason.STALE_REVOCATION: (
        "Ni la revocación del PDF ni la descargada están vigentes a la hora actual: la CA "
        "publica CRL u OCSP desactualizadas."
    ),
    TrustReason.MISSING_REVOCATION: (
        "No se consiguió revocación (CRL u OCSP) para algún certificado de la cadena: ni en el "
        "PDF ni en las URLs del certificado (no respondieron o no tiene)."
    ),
}
NO_PATH = (
    "No hay un camino desde el certificado hasta una raíz confiable: falta una intermedia o la "
    "raíz no está en la fuente (o no está marcada como confiable).",
    "Agregá la intermedia o la raíz que falta a la fuente de certificados, o marcá la raíz como confiable.",
)
NOT_EVALUATED = ("La firma criptográfica no verifica, así que no se evaluó la confianza.", None)
UNKNOWN = ("pyHanko no la considera confiable, pero todos los caminos validan: revisá el detalle de pyHanko.", None)


@dataclass(frozen=True)
class PathAttempt:
    """Un camino candidato desde el certificado hasta un ancla, y cómo le fue al validarlo."""

    chain: tuple[Certificate, ...]
    """Hoja -> ancla."""
    reason: TrustReason | None
    """Por qué falló; None si valida."""
    message: str | None
    """El mensaje del validador (en inglés); None si valida."""


@dataclass(frozen=True)
class TrustProblem:
    reason: TrustReason
    indication: str | None
    """La indicación AdES de pyHanko (p. ej. `CHAIN_CONSTRAINTS_FAILURE`)."""
    summary: str
    hint: str | None
    paths: tuple[PathAttempt, ...]


def _hint(reason: TrustReason, validated_now: bool, online: bool) -> str | None:
    if reason in (TrustReason.STALE_REVOCATION, TrustReason.MISSING_REVOCATION) and not online:
        claimed = " o a la hora declarada por la firma" if reason is TrustReason.STALE_REVOCATION and validated_now else ""
        return f"Probá validar con conexión, que descarga CRL y OCSP actualizadas{claimed}."
    if reason is TrustReason.EXPIRED and validated_now:
        return "Se validó a la hora actual: probá validar a la hora declarada por la firma."
    return None


def trust_problem(
    *,
    trusted: bool,
    valid: bool,
    indication: str | None,
    attempts: Sequence[PathAttempt],
    validated_now: bool,
    online: bool,
) -> TrustProblem | None:
    """V-09: el motivo de que no sea confiable, a partir de los caminos probados; None si es confiable.

    Si la firma no verifica, no se evaluó la confianza. Si no hay caminos, falta una intermedia o
    la raíz. Si alguno valida, el problema es otro (lo dice el detalle de pyHanko). Si no, el
    motivo más informativo de los que aparecen (orden de `REASONS`).
    """
    if trusted:
        return None
    if not valid:
        return TrustProblem(TrustReason.NOT_EVALUATED, indication, *NOT_EVALUATED, ())
    if not attempts:
        return TrustProblem(TrustReason.NO_PATH, indication, *NO_PATH, ())
    if any(a.reason is None for a in attempts):
        return TrustProblem(TrustReason.OTHER, indication, *UNKNOWN, tuple(attempts))
    failed = {a.reason for a in attempts}
    reason = next(r for r in REASONS if r in failed)
    summary = ONLINE_REASONS.get(reason, REASONS[reason]) if online else REASONS[reason]
    return TrustProblem(reason, indication, summary, _hint(reason, validated_now, online), tuple(attempts))


# --------------------------------------------------------------------------- evaluación de cada firma


@dataclass(frozen=True)
class Modifications:
    level: str | None
    """El nivel de modificación de pyHanko (`NONE`, `LTA_UPDATES`, `FORM_FILLING`, ...)."""
    docmdp_ok: bool | None
    suspicious: str | None
    """Si el análisis encontró una modificación sospechosa, su descripción."""


@dataclass(frozen=True)
class TimestampEvaluation:
    """El sello de tiempo de una firma, validado como lo valida el adaptador."""

    time: datetime
    tsa: Certificate
    valid: bool
    trusted: bool
    indication: str | None
    attempts: tuple[PathAttempt, ...]
    """Los caminos probados, si no es confiable y verifica; vacío si no."""
    path_intermediates: tuple[Certificate, ...]
    """Los intermedios del camino validado (sin hoja ni ancla)."""


@dataclass(frozen=True)
class SignatureEvaluation:
    """Lo que el adaptador sabe de una firma después de validarla."""

    subfilter: str
    signer: Certificate
    bottom_line: bool
    intact: bool
    valid: bool
    trusted: bool
    indication: str | None
    attempts: tuple[PathAttempt, ...]
    """Los caminos probados, si no es confiable y verifica; vacío si no."""
    coverage: str
    path_intermediates: tuple[Certificate, ...]
    """Los intermedios del camino validado (sin hoja ni ancla); vacío si no hubo camino."""
    modifications: Modifications
    details: str
    """El reporte en texto de pyHanko."""
    timestamp: TimestampEvaluation | None


def completed_from_store(
    trusted: bool, path_intermediates: Iterable[Certificate], embedded_sha256: frozenset[str], store_sha256: frozenset[str]
) -> tuple[Certificate, ...]:
    """V-06: los intermedios del camino que el PDF no trae y la fuente sí, sólo si es confiable.

    La hoja siempre está en el PDF y el ancla es, por definición, del validador. Si la validación
    falla, el validador igual devuelve el camino con el que falló, y no se puede decir que la fuente
    lo completó. Con conexión, un intermedio que no está en ninguno de los dos se descargó por AIA.
    """
    if not trusted:
        return ()
    return tuple(c for c in path_intermediates if c.sha256 not in embedded_sha256 and c.sha256 in store_sha256)


@dataclass(frozen=True)
class TimestampVerdict:
    evaluation: TimestampEvaluation
    trust_problem: TrustProblem | None
    completed_from_store: tuple[Certificate, ...]


@dataclass(frozen=True)
class SignatureVerdict:
    field_name: str
    kind: SignatureKind
    evaluation: SignatureEvaluation | None
    """None para un DocTimeStamp: no se valida aparte."""
    validated_at: ValidatedAt | None
    trust_problem: TrustProblem | None
    completed_from_store: tuple[Certificate, ...]
    timestamp: TimestampVerdict | None

    @property
    def used_store(self) -> bool:
        return bool(self.completed_from_store or (self.timestamp and self.timestamp.completed_from_store))


class PadesLevel(StrEnum):
    B_B = "PAdES B-B"
    B_T = "PAdES B-T"
    B_LT = "PAdES B-LT"
    B_LTA = "PAdES B-LTA"


def pades_level(verdicts: Sequence[SignatureVerdict], has_dss: bool, self_contained: bool, online: bool) -> PadesLevel:
    """V-07: B-B; B-T si todas las firmas tienen sello; B-LT si además hay DSS, el PDF alcanza solo y
    todas validan; B-LTA si además hay un DocTimeStamp. V-05: con conexión, o si una cadena se completó
    con la fuente, no se sabe si el PDF alcanza solo: no pasa de B-T."""
    has_doc_ts = any(v.kind is SignatureKind.DOC_TIMESTAMP for v in verdicts)
    sigs = [v.evaluation for v in verdicts if v.kind is SignatureKind.SIGNATURE]
    level = PadesLevel.B_B
    if sigs and all(s.timestamp for s in sigs):
        level = PadesLevel.B_T
        if has_dss and self_contained and not online and all(s.bottom_line for s in sigs):
            level = PadesLevel.B_LTA if has_doc_ts else PadesLevel.B_LT
    return level


# --------------------------------------------------------------------------- reporte


@dataclass(frozen=True)
class DssSummary:
    certs: int
    ocsps: int
    crls: int


@dataclass(frozen=True)
class FetchedCrl:
    issuer: str
    this_update: datetime
    next_update: datetime | None
    from_cache: bool
    fetched_at: datetime | None


@dataclass(frozen=True)
class FetchedOcsp:
    serial_number: int
    status: str
    produced_at: datetime


@dataclass(frozen=True)
class FetchedRevocation:
    """Lo que se descargó en modo con conexión."""

    crls: tuple[FetchedCrl, ...]
    ocsps: tuple[FetchedOcsp, ...]
    certificates: tuple[Certificate, ...]
    """Emisores descargados por AIA."""


@dataclass(frozen=True)
class VerificationReport:
    options: VerificationOptions
    pades_level: PadesLevel
    dss: DssSummary | None
    fetched: FetchedRevocation | None
    trust_anchors: int
    intermediates: int
    self_contained: bool
    signatures: tuple[SignatureVerdict, ...]

    @property
    def store_note(self) -> str | None:
        return None if self.self_contained else STORE_NOTE
