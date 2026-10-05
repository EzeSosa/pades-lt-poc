"""Validación offline (sólo con el DSS embebido) de las firmas de un PDF."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from asn1crypto import x509 as asn1_x509
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import DEFAULT_DIFF_POLICY, StandardDiffPolicy, SuspiciousModification
from pyhanko.sign.validation import DocumentSecurityStore, async_validate_pdf_signature
from pyhanko.sign.validation.pdf_embedded import EmbeddedPdfSignature
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.policy_decl import DEFAULT_WEAK_HASH_ALGOS, DisallowWeakAlgorithmsPolicy

from .. import pki
from . import read_signed_pdf

TRUST_DIR = Path(__file__).parent.parent / "trust"

ValidationTime = Literal["now", "claimed_signing_time"]
DiffPolicyName = Literal["default", "allow_unallocated_free_entries"]

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


def bundled_roots() -> list[asn1_x509.Certificate]:
    """Raíces de `trust/` (las AC Raíz de Argentina de 2007 y 2016), en DER."""
    return [load_cert_from_pemder(str(p)) for p in sorted(TRUST_DIR.glob("*.der"))]


class LegacyRootsPolicy(DisallowWeakAlgorithmsPolicy):
    """Rechaza SHA-1 como pyHanko, salvo en lo que firman las claves de `roots`.

    La AC Raíz de Argentina de 2007 firma con SHA-1 a sus CAs y a su CRL. Se lo
    acepta sólo para la clave de las raíces que nacieron con SHA-1: los firmantes,
    las TSAs y las demás CAs siguen sin poder usarlo.
    """

    def __init__(self, roots: list[asn1_x509.Certificate]) -> None:
        super().__init__()
        self._legacy_keys = {r.public_key.dump() for r in roots}
        self._legacy = DisallowWeakAlgorithmsPolicy(weak_hash_algos=DEFAULT_WEAK_HASH_ALGOS - {"sha1"})

    def signature_algorithm_allowed(self, algo, moment, public_key):
        if public_key is not None and public_key.dump() in self._legacy_keys:
            return self._legacy.signature_algorithm_allowed(algo, moment, public_key)
        return super().signature_algorithm_allowed(algo, moment, public_key)


class UnallocatedFreesPolicy(StandardDiffPolicy):
    """La política por defecto de pyHanko, salvo que acepta entradas libres de objetos que nunca existieron.

    iText marca a veces un número de objeto reservado y nunca escrito como `65535 f`
    (muerto para siempre). pyHanko lo trata como si se borrara un objeto, pero un
    número >= al /Size de la revisión anterior no pudo haber existido: no se borra nada.
    Liberar un objeto que sí existía sigue siendo sospechoso.
    """

    def __init__(self) -> None:
        d = DEFAULT_DIFF_POLICY
        super().__init__(d.global_rules, d.form_rule, reject_object_freeing=False)

    def apply(self, old, new, field_mdp_spec=None, doc_mdp=None):
        prev_size = new.reader.trailer.flatten(new.revision - 1)["/Size"]
        freed = {ref for ref in new.refs_freed_in_revision() if ref.idnum < prev_size}
        if freed:
            raise SuspiciousModification(
                f"The refs {freed} were freed in the revision provided. "
                "The configured difference analysis policy does not allow object freeing."
            )
        return super().apply(old, new, field_mdp_spec, doc_mdp)


DIFF_POLICIES = {"default": DEFAULT_DIFF_POLICY, "allow_unallocated_free_entries": UnallocatedFreesPolicy()}


class SignatureVerifier:
    """Valida OFFLINE: sin fetching y con revocación obligatoria.

    Sólo pasa si todo lo necesario (certs + CRLs/OCSP) está dentro del PDF, lo que
    prueba que la firma es B-LT.
    """

    def __init__(self, trust_roots: list[asn1_x509.Certificate]) -> None:
        self.trust_roots = trust_roots
        self.algorithm_policy = LegacyRootsPolicy(
            [r for r in trust_roots if r["signature_algorithm"].hash_algo == "sha1"]
        )

    @classmethod
    def from_pki(cls) -> SignatureVerifier:
        """Confía en la raíz de la PoC y en las de PKIs reales incluidas en el paquete."""
        root = load_cert_from_pemder(str(pki.entity(pki.ROOT).cert_path))
        return cls([root, *bundled_roots()])

    async def verify(self, pdf: bytes, validation_time: ValidationTime, diff_policy: DiffPolicyName) -> dict:
        reader = read_signed_pdf(pdf)
        has_dss = "/DSS" in reader.root
        dss_store = DocumentSecurityStore.read_dss(reader) if has_dss else None
        now = datetime.now(UTC)

        results = []
        for sig in reader.embedded_signatures:
            if sig.sig_object.get("/Type") == "/DocTimeStamp":
                results.append({"field": sig.field_name, "type": "DocTimeStamp"})
                continue
            # La hora declarada sale del atributo signingTime del CMS o, si no está, de /M.
            claimed = sig.self_reported_timestamp if validation_time == "claimed_signing_time" else None
            moment, source = (claimed, "claimed_signing_time") if claimed else (now, "now")
            vc = self._context_at(dss_store, moment, in_the_past=claimed is not None)
            results.append(await self._verify_signature(sig, vc, DIFF_POLICIES[diff_policy], moment, source))

        return {
            "validation_time": {
                "mode": validation_time,
                "warning": CLAIMED_TIME_WARNING if validation_time == "claimed_signing_time" else None,
            },
            "diff_policy": {
                "mode": diff_policy,
                "note": UNALLOCATED_FREES_NOTE if diff_policy == "allow_unallocated_free_entries" else None,
            },
            "pades_level": _pades_level(results, has_dss),
            "dss": _dss_summary(reader) if has_dss else None,
            "signatures": results,
        }

    def _context_at(
        self, dss_store: DocumentSecurityStore | None, moment: datetime, in_the_past: bool
    ) -> ValidationContext:
        # Validando en el pasado, la revocación embebida es posterior a `moment` (se obtuvo
        # después de firmar) y pyHanko la descarta salvo con `retroactive_revinfo`.
        kwargs = dict(
            trust_roots=self.trust_roots,
            allow_fetching=False,
            revocation_mode="hard-fail",
            algorithm_usage_policy=self.algorithm_policy,
            moment=moment,
            retroactive_revinfo=in_the_past,
        )
        if dss_store:
            return dss_store.as_validation_context(kwargs)
        # Sin DSS no hay revocación: listas vacías para que la firma resulte no confiable
        # (pyHanko lanza ValueError si en hard-fail sin fetching no recibe ninguna).
        return ValidationContext(**kwargs, crls=[], ocsps=[])

    @staticmethod
    async def _verify_signature(
        sig: EmbeddedPdfSignature,
        vc: ValidationContext,
        diff_policy: StandardDiffPolicy,
        moment: datetime,
        source: str,
    ) -> dict:
        status = await async_validate_pdf_signature(
            sig, signer_validation_context=vc, ts_validation_context=vc, diff_policy=diff_policy
        )
        return {
            "field": sig.field_name,
            "type": "Signature",
            "subfilter": str(sig.sig_object.get("/SubFilter")),
            "signer": status.signing_cert.subject.human_friendly,
            "bottom_line": status.bottom_line,
            "intact": status.intact,
            "valid": status.valid,
            "trusted": status.trusted,
            "coverage": status.coverage.name,
            # Qué cambió después de la firma: si es sospechoso, `bottom_line` da false.
            "modifications": {
                "level": status.modification_level.name if status.modification_level else None,
                "docmdp_ok": status.docmdp_ok,
                "suspicious": (
                    str(status.diff_result) if isinstance(status.diff_result, SuspiciousModification) else None
                ),
            },
            "validated_at": {"time": moment.isoformat(), "source": source},
            "signature_timestamp": (
                {
                    "time": status.timestamp_validity.timestamp.isoformat(),
                    "tsa": status.timestamp_validity.signing_cert.subject.human_friendly,
                    "valid": status.timestamp_validity.valid,
                    "trusted": status.timestamp_validity.trusted,
                }
                if status.timestamp_validity
                else None
            ),
            "details": status.pretty_print_details(),
        }


def _pades_level(results: list[dict], has_dss: bool) -> str:
    has_doc_ts = any(r["type"] == "DocTimeStamp" for r in results)
    sigs = [r for r in results if r["type"] == "Signature"]
    level = "PAdES B-B"
    if sigs and all(r["signature_timestamp"] for r in sigs):
        level = "PAdES B-T"
        if has_dss and all(r["bottom_line"] for r in sigs):
            level = "PAdES B-LTA" if has_doc_ts else "PAdES B-LT"
    return level


def _dss_summary(reader: PdfFileReader) -> dict[str, int]:
    # Los arrays del DSS pueden ser referencias indirectas: `[]` las resuelve, `.get` no.
    dss = reader.root["/DSS"]
    return {k: len(dss[f"/{k}"]) if f"/{k}" in dss else 0 for k in ("Certs", "OCSPs", "CRLs")}
