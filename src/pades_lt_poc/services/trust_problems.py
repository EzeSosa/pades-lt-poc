"""Por qué una firma (o su sello de tiempo) no es confiable.

pyHanko resume la falla en una indicación AdES (`CERTIFICATE_CHAIN_GENERAL_FAILURE` y
similares) y el mensaje de pyhanko-certvalidator sólo va al log. Para poder decir el
motivo, se vuelve a validar cada camino candidato con el mismo ValidationContext y se
junta el error de cada uno. Sólo se hace con lo que no resultó confiable.
"""

from __future__ import annotations

from collections.abc import Iterable

from asn1crypto import x509 as asn1_x509
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.errors import (
    DisallowedAlgorithmError,
    ExpiredError,
    InsufficientRevinfoError,
    NotYetValidError,
    PathBuildingError,
    RevokedError,
    ValidationError,
)
from pyhanko_certvalidator.validate import async_validate_path

MAX_PATHS = 5

# Motivo -> resumen. Ordenados de más a menos informativo: si hay varios caminos, se
# resume con el primero de esta lista que aparezca. Un camino que falla por un
# certificado vencido suele ser una versión vieja de una CA renovada: va al final.
REASONS = {
    "revoked": "Un certificado de la cadena está revocado.",
    "stale_revocation": (
        "La revocación que trae el PDF (CRL u OCSP) ya no está vigente a la hora de validación, "
        "y sin conexión no se puede conseguir una más nueva."
    ),
    "missing_revocation": (
        "El PDF no trae revocación (CRL u OCSP) para algún certificado de la cadena, y sin "
        "conexión no se puede conseguir."
    ),
    "algorithm": "La cadena usa un algoritmo que la política no permite (p. ej. SHA-1).",
    "other": "La cadena no valida.",
    "not_yet_valid": "Un certificado de la cadena todavía no es vigente a la hora de validación.",
    "expired": "Un certificado de la cadena está vencido a la hora de validación.",
}
# Con conexión, la revocación también se intentó descargar.
ONLINE_REASONS = {
    "stale_revocation": (
        "Ni la revocación del PDF ni la descargada están vigentes a la hora actual: la CA "
        "publica CRL u OCSP desactualizadas."
    ),
    "missing_revocation": (
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


def _hint(reason: str, validated_now: bool, online: bool) -> str | None:
    if reason in ("stale_revocation", "missing_revocation") and not online:
        claimed = " o a la hora declarada por la firma" if reason == "stale_revocation" and validated_now else ""
        return f"Probá validar con conexión, que descarga CRL y OCSP actualizadas{claimed}."
    if reason == "expired" and validated_now:
        return "Se validó a la hora actual: probá validar a la hora declarada por la firma."
    return None


def _reason(error: ValidationError) -> str:
    if isinstance(error, RevokedError):
        return "revoked"
    if isinstance(error, InsufficientRevinfoError):
        # pyhanko-certvalidator no siempre usa StaleRevinfoError: lo dice el mensaje.
        return "stale_revocation" if "not recent enough" in str(error) else "missing_revocation"
    if isinstance(error, ExpiredError):
        return "expired"
    if isinstance(error, NotYetValidError):
        return "not_yet_valid"
    if isinstance(error, DisallowedAlgorithmError):
        return "algorithm"
    return "other"


def _link(cert: asn1_x509.Certificate) -> dict:
    # Con la vigencia y la huella: una CA renovada tiene el mismo nombre en los dos caminos.
    return {
        "subject": cert.subject.native.get("common_name") or cert.subject.human_friendly,
        "not_after": cert["tbs_certificate"]["validity"]["not_after"].native.isoformat(),
        "sha256": cert.sha256.hex(),
    }


def _problem(reason: str, summary: str, hint: str | None, indication, paths: list[dict]) -> dict:
    return {
        "reason": reason,
        "indication": indication.name if indication else None,
        "summary": summary,
        "hint": hint,
        "paths": paths,
    }


async def diagnose(
    cert: asn1_x509.Certificate,
    other_certs: Iterable[asn1_x509.Certificate],
    vc: ValidationContext,
    *,
    valid: bool,
    indication,
    validated_now: bool,
    online: bool = False,
) -> dict:
    """El motivo de que `cert` no sea confiable, con el error de cada camino probado.

    `paths` va de la hoja a la raíz, con el motivo y el mensaje de pyhanko-certvalidator.
    """
    if not valid:
        return _problem("not_evaluated", *NOT_EVALUATED, indication, [])

    vc.certificate_registry.register_multiple(list(other_certs))
    paths = []
    candidates = vc.path_builder.async_build_paths_lazy(cert)
    try:
        async for path in candidates:
            chain = [_link(c) for c in reversed(list(path.iter_certs(include_root=True)))]
            try:
                await async_validate_path(vc, path)
            except ValidationError as e:
                paths.append({"chain": chain, "reason": _reason(e), "message": e.failure_msg})
            else:
                paths.append({"chain": chain, "reason": None, "message": None})
            if len(paths) == MAX_PATHS:
                break
    except PathBuildingError:
        pass
    finally:
        await candidates.cancel()

    if not paths:
        return _problem("no_path", *NO_PATH, indication, [])
    if any(p["reason"] is None for p in paths):
        # Algún camino valida: el problema está en otro lado (p. ej. el uso de la clave).
        return _problem("other", *UNKNOWN, indication, paths)
    failed = {p["reason"] for p in paths}
    reason = next(r for r in REASONS if r in failed)
    summary = ONLINE_REASONS.get(reason, REASONS[reason]) if online else REASONS[reason]
    return _problem(reason, summary, _hint(reason, validated_now, online), indication, paths)
