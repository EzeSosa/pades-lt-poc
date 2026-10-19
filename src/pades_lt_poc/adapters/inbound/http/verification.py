from typing import Literal

from fastapi import APIRouter, File, Form, UploadFile

from ....domain.certificates import Certificate
from ....domain.verification import (
    DiffPolicyMode,
    FetchedRevocation,
    PathAttempt,
    RevocationMode,
    SignatureVerdict,
    TrustProblem,
    ValidationTimeMode,
    VerificationOptions,
    VerificationReport,
)
from .dependencies import VerifySignaturesDep

router = APIRouter(tags=["Verificación"])


@router.post("/verify")
async def verify(
    verifier: VerifySignaturesDep,
    pdf: UploadFile = File(...),
    validation_time: Literal["now", "claimed_signing_time"] = Form(
        "now",
        description=(
            "now: valida a la hora actual (por defecto). claimed_signing_time: valida cada firma "
            "a la hora que ella misma declara; sirve para firmas sin sello de tiempo cuya "
            "revocación embebida ya venció, pero esa hora no está probada."
        ),
    ),
    diff_policy: Literal["default", "allow_unallocated_free_entries"] = Form(
        "default",
        description=(
            "Análisis de las modificaciones posteriores a cada firma. default: el de pyHanko. "
            "allow_unallocated_free_entries: además acepta entradas libres de objetos que nunca existieron."
        ),
    ),
    revocation: Literal["offline", "online"] = Form(
        "offline",
        description=(
            "offline: sólo la revocación que trae el PDF (por defecto). online: además descarga CRL, "
            "OCSP y emisores faltantes de las URLs de cada certificado; sólo con validation_time=now, "
            "y el nivel alcanzado no pasa de B-T."
        ),
    ),
) -> dict:
    """Valida las firmas con el material del PDF y la fuente de certificados; con conexión, si se pide."""
    options = VerificationOptions(ValidationTimeMode(validation_time), DiffPolicyMode(diff_policy), RevocationMode(revocation))
    return present_report(await verifier.verify(await pdf.read(), options))


# --------------------------------------------------------------------------- presenters
def present_report(report: VerificationReport) -> dict:
    options = report.options
    dss = report.dss
    return {
        "validation_time": {"mode": options.validation_time.value, "warning": options.warning},
        "diff_policy": {"mode": options.diff_policy.value, "note": options.diff_policy_note},
        "revocation": {
            "mode": options.revocation.value,
            "fetched": _present_fetched(report.fetched) if report.fetched else None,
            "note": options.revocation_note,
        },
        "pades_level": report.pades_level.value,
        "dss": {"Certs": dss.certs, "OCSPs": dss.ocsps, "CRLs": dss.crls} if dss else None,
        "certificate_store": {
            "trusted_roots": report.trust_anchors,
            "intermediates": report.intermediates,
            "self_contained": report.self_contained,
            "note": report.store_note,
        },
        "signatures": [_present_signature(v) for v in report.signatures],
    }


def _present_signature(verdict: SignatureVerdict) -> dict:
    e = verdict.evaluation
    if e is None:  # DocTimeStamp
        return {"field": verdict.field_name, "type": verdict.kind.value}
    ts = verdict.timestamp
    return {
        "field": verdict.field_name,
        "type": verdict.kind.value,
        "subfilter": e.subfilter,
        "signer": e.signer.display_name,
        "bottom_line": e.bottom_line,
        "intact": e.intact,
        "valid": e.valid,
        "trusted": e.trusted,
        # Si no es confiable, por qué: resumen, sugerencia y el error de cada camino probado.
        "trust_problem": _present_problem(verdict.trust_problem),
        "coverage": e.coverage,
        # Intermedios del camino del firmante que no vienen en el PDF sino en la fuente.
        "completed_from_store": [_present_store_link(c) for c in verdict.completed_from_store],
        # Qué cambió después de la firma: si es sospechoso, `bottom_line` da false.
        "modifications": {
            "level": e.modifications.level,
            "docmdp_ok": e.modifications.docmdp_ok,
            "suspicious": e.modifications.suspicious,
        },
        "validated_at": {"time": verdict.validated_at.time.isoformat(), "source": verdict.validated_at.source.value},
        "signature_timestamp": (
            {
                "time": ts.evaluation.time.isoformat(),
                "tsa": ts.evaluation.tsa.display_name,
                "valid": ts.evaluation.valid,
                "trusted": ts.evaluation.trusted,
                "trust_problem": _present_problem(ts.trust_problem),
                "completed_from_store": [_present_store_link(c) for c in ts.completed_from_store],
            }
            if ts
            else None
        ),
        "details": e.details,
    }


def _present_store_link(cert: Certificate) -> dict:
    return {"subject": cert.display_name, "sha256": cert.sha256}


def _present_problem(problem: TrustProblem | None) -> dict | None:
    if problem is None:
        return None
    return {
        "reason": problem.reason.value,
        "indication": problem.indication,
        "summary": problem.summary,
        "hint": problem.hint,
        "paths": [_present_attempt(a) for a in problem.paths],
    }


def _present_attempt(attempt: PathAttempt) -> dict:
    return {
        # Con la vigencia y la huella: una CA renovada tiene el mismo nombre en los dos caminos.
        "chain": [
            {"subject": c.common_name or c.display_name, "not_after": c.not_after.isoformat(), "sha256": c.sha256}
            for c in attempt.chain
        ],
        "reason": attempt.reason.value if attempt.reason else None,
        "message": attempt.message,
    }


def _present_fetched(fetched: FetchedRevocation) -> dict:
    return {
        "crls": [
            {
                "issuer": c.issuer,
                "this_update": c.this_update.isoformat(),
                "next_update": c.next_update.isoformat() if c.next_update else None,
                "from_cache": c.from_cache,
                "fetched_at": c.fetched_at.isoformat() if c.fetched_at else None,
            }
            for c in fetched.crls
        ],
        "ocsps": [
            {"serial_number": format(o.serial_number, "x"), "status": o.status, "produced_at": o.produced_at.isoformat()}
            for o in fetched.ocsps
        ],
        "certs": [{"subject": c.display_name, "sha256": c.sha256} for c in fetched.certificates],
    }
