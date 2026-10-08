"""Validación offline de las firmas de un PDF: el DSS embebido más la fuente de certificados."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from asn1crypto import x509 as asn1_x509
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import DEFAULT_DIFF_POLICY, StandardDiffPolicy, SuspiciousModification
from pyhanko.sign.validation import DocumentSecurityStore, async_validate_pdf_signature
from pyhanko.sign.validation.generic_cms import extract_certs_for_validation, extract_tst_data_iter
from pyhanko.sign.validation.pdf_embedded import EmbeddedPdfSignature
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.fetchers import FetcherBackend, Fetchers
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.policy_decl import DEFAULT_WEAK_HASH_ALGOS, DisallowWeakAlgorithmsPolicy

from .. import pki
from . import UnprocessableInput, read_signed_pdf
from . import crl_index
from .fetching import RevocationFetcherBackend
from .store import CertificateStore
from .trust_problems import diagnose

ValidationTime = Literal["now", "claimed_signing_time"]
DiffPolicyName = Literal["default", "allow_unallocated_free_entries"]
RevocationMode = Literal["offline", "online"]


ONLINE_CLOCK_SKEW = timedelta(minutes=2)

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
    """Valida con revocación obligatoria (hard-fail), sin conexión por defecto.

    Anclas de confianza: la raíz de la PoC (implícita, porque se regenera con la PKI) y
    las raíces confiables habilitadas de la fuente. Los intermedios habilitados de la
    fuente completan cadenas que el PDF no trae; cuando se usan, la firma lo informa en
    `completed_from_store` y el PDF deja de contar como LT por sí mismo.

    Sin conexión (`offline`) sólo cuenta la revocación que trae el PDF. Con conexión
    (`online`) además se descargan CRL, OCSP y emisores faltantes (AIA) de las URLs de
    cada certificado; sólo a la hora actual, porque pyHanko no descarga para validar en
    el pasado. Lo descargado se informa en `revocation.fetched`.

    La fuente se lee en cada verificación, así que un cambio en el ABM aplica enseguida.
    """

    def __init__(
        self,
        store: CertificateStore,
        own_roots: list[asn1_x509.Certificate],
        fetcher_backend: Callable[[], FetcherBackend] = RevocationFetcherBackend,
    ) -> None:
        self.store = store
        self.own_roots = own_roots
        self.fetcher_backend = fetcher_backend
        # Buscar un serial en una CRL grande (la de la ONTI) recorriéndola en Python tarda
        # segundos: se usa un índice armado con `cryptography` (ver crl_index).
        crl_index.install()

    @classmethod
    def from_pki(cls, store: CertificateStore) -> SignatureVerifier:
        return cls(store, [load_cert_from_pemder(str(pki.entity(pki.ROOT).cert_path))])

    def trust_roots(self) -> list[asn1_x509.Certificate]:
        return [*self.own_roots, *self.store.snapshot().trusted_roots]

    def algorithm_policy(self) -> LegacyRootsPolicy:
        return _legacy_policy(self.trust_roots())

    async def verify(
        self,
        pdf: bytes,
        validation_time: ValidationTime,
        diff_policy: DiffPolicyName,
        revocation: RevocationMode = "offline",
    ) -> dict:
        online = revocation == "online"
        if online and validation_time != "now":
            raise UnprocessableInput(
                "Con conexión sólo se valida a la hora actual: la revocación que se descarga es de hoy."
            )
        reader = read_signed_pdf(pdf)
        has_dss = "/DSS" in reader.root
        dss_store = DocumentSecurityStore.read_dss(reader) if has_dss else None
        now = datetime.now(UTC)
        snapshot = self.store.snapshot()
        roots = [*self.own_roots, *snapshot.trusted_roots]
        sources = _Sources(_embedded_certs(reader, dss_store), snapshot.sha256)

        async with AsyncExitStack() as stack:
            # Un solo juego de fetchers para todo el PDF: lo descargado para una firma sirve a las demás.
            fetchers = await stack.enter_async_context(self.fetcher_backend()) if online else None
            context = _ContextFactory(dss_store, roots, list(snapshot.intermediates), _legacy_policy(roots), fetchers)
            results = []
            for sig in reader.embedded_signatures:
                if sig.sig_object.get("/Type") == "/DocTimeStamp":
                    results.append({"field": sig.field_name, "type": "DocTimeStamp"})
                    continue
                # La hora declarada sale del atributo signingTime del CMS o, si no está, de /M.
                claimed = sig.self_reported_timestamp if validation_time == "claimed_signing_time" else None
                moment, source = (claimed, "claimed_signing_time") if claimed else (now, "now")
                vc = context.at(moment, in_the_past=claimed is not None)
                results.append(
                    await _verify_signature(sig, vc, DIFF_POLICIES[diff_policy], moment, source, sources, online)
                )
            fetched = _fetched_summary(fetchers) if online else None

        self_contained = not any(_used_store(r) for r in results)
        return {
            "validation_time": {
                "mode": validation_time,
                "warning": CLAIMED_TIME_WARNING if validation_time == "claimed_signing_time" else None,
            },
            "diff_policy": {
                "mode": diff_policy,
                "note": UNALLOCATED_FREES_NOTE if diff_policy == "allow_unallocated_free_entries" else None,
            },
            "revocation": {
                "mode": revocation,
                "fetched": fetched,
                "note": ONLINE_NOTE if online else None,
            },
            # Con conexión no se sabe si el PDF alcanza solo: el nivel no pasa de B-T.
            "pades_level": _pades_level(results, has_dss, self_contained and not online),
            "dss": _dss_summary(reader) if has_dss else None,
            "certificate_store": {
                "trusted_roots": len(roots),
                "intermediates": len(snapshot.intermediates),
                "self_contained": self_contained,
                "note": None if self_contained else STORE_NOTE,
            },
            "signatures": results,
        }


def _legacy_policy(roots: list[asn1_x509.Certificate]) -> LegacyRootsPolicy:
    """SHA-1 sólo para lo que firman las raíces confiables que nacieron con SHA-1."""
    return LegacyRootsPolicy([r for r in roots if r["signature_algorithm"].hash_algo == "sha1"])


class _ContextFactory:
    """Arma el ValidationContext de cada firma: DSS + fuente, a la hora que corresponda.

    Con `fetchers` (modo con conexión) se descarga lo que falte; pyHanko no admite
    descargar con una hora fija, así que valida a la hora actual.
    """

    def __init__(self, dss_store, roots, intermediates, policy, fetchers: Fetchers | None = None) -> None:
        self.dss_store, self.roots, self.intermediates, self.policy = dss_store, roots, intermediates, policy
        self.fetchers = fetchers

    def at(self, moment: datetime, in_the_past: bool) -> ValidationContext:
        # Validando en el pasado, la revocación embebida es posterior a `moment` (se obtuvo
        # después de firmar) y pyHanko la descarta salvo con `retroactive_revinfo`.
        kwargs = dict(
            trust_roots=self.roots,
            other_certs=self.intermediates,  # el DSS los suma a los suyos
            revocation_mode="hard-fail",
            algorithm_usage_policy=self.policy,
            retroactive_revinfo=in_the_past,
        )
        if self.fetchers:
            # Lo descargado se emite "ahora" según el reloj del servidor remoto: con 1 s de
            # tolerancia (lo de pyHanko), un par de segundos de desfasaje lo vuelven "del futuro".
            kwargs.update(allow_fetching=True, fetchers=self.fetchers, time_tolerance=ONLINE_CLOCK_SKEW)
        else:
            kwargs.update(allow_fetching=False, moment=moment)
        if self.dss_store:
            return self.dss_store.as_validation_context(kwargs)
        # Sin DSS no hay revocación: listas vacías para que la firma resulte no confiable
        # (pyHanko lanza ValueError si en hard-fail sin fetching no recibe ninguna).
        return ValidationContext(**kwargs, crls=[], ocsps=[])


def _embedded_certs(reader: PdfFileReader, dss_store: DocumentSecurityStore | None) -> set[bytes]:
    """Todos los certificados que trae el PDF (DER): DSS, CMS de cada firma y sus sellos de tiempo."""
    certs = list(dss_store.load_certs()) if dss_store else []
    for sig in reader.embedded_signatures:
        found = extract_certs_for_validation(sig.signed_data)
        certs += [found.signer_cert, *found.other_certs]
        for token in extract_tst_data_iter(sig.signer_info, signed=False):
            found = extract_certs_for_validation(token)
            certs += [found.signer_cert, *found.other_certs]
    return {c.dump() for c in certs}


@dataclass(frozen=True)
class _Sources:
    """De dónde puede salir cada certificado: el PDF (DER) o la fuente (SHA-256 en hex)."""

    embedded: set[bytes]
    store: frozenset[str]


def _from_store(path: ValidationPath | None, trusted: bool, sources: _Sources) -> list[dict]:
    """Eslabones intermedios del camino que el PDF no trae y la fuente sí.

    La hoja siempre está en el PDF y la raíz es, por definición, del validador. Sólo
    cuenta si la validación salió bien: si falla, pyHanko igual devuelve el camino con
    el que falló, y no se puede decir que la fuente completó la cadena. Con conexión,
    un intermedio que no está en ninguno de los dos se descargó por AIA.
    """
    if path is None or not trusted:
        return []
    intermediates = list(path.iter_certs(include_root=False))[:-1]  # sin la hoja
    return [
        {"subject": c.subject.human_friendly, "sha256": c.sha256.hex()}
        for c in intermediates
        if c.dump() not in sources.embedded and c.sha256.hex() in sources.store
    ]


def _fetched_summary(fetchers: Fetchers) -> dict:
    """Lo que se descargó en modo con conexión: CRLs, respuestas OCSP y emisores (AIA).

    Una CRL puede venir del caché (`from_cache`): se descargó en una verificación anterior
    (`fetched_at`) y sigue vigente.
    """
    from_cache = getattr(fetchers.crl_fetcher, "from_cache", {})

    def crl(c) -> dict:
        tbs = c["tbs_cert_list"]
        next_update = tbs["next_update"].native
        cached = from_cache.get(id(c))
        return {
            "issuer": c.issuer.human_friendly,
            "this_update": tbs["this_update"].native.isoformat(),
            "next_update": next_update.isoformat() if next_update else None,
            "from_cache": cached is not None,
            "fetched_at": cached.fetched_at.isoformat() if cached else None,
        }

    def ocsp(r) -> dict:
        data = r["response_bytes"]["response"].parsed["tbs_response_data"]
        [single, *_] = data["responses"]
        return {
            "serial_number": format(single["cert_id"]["serial_number"].native, "x"),
            "status": single["cert_status"].name,
            "produced_at": data["produced_at"].native.isoformat(),
        }

    return {
        # La misma CRL puede llegar de dos URLs (p. ej. cdp1 y cdp2): se lista una vez.
        "crls": [crl(c) for c in {c.dump(): c for c in fetchers.crl_fetcher.fetched_crls()}.values()],
        "ocsps": [ocsp(r) for r in fetchers.ocsp_fetcher.fetched_responses()],
        "certs": [{"subject": c.subject.human_friendly, "sha256": c.sha256.hex()} for c in fetchers.cert_fetcher.fetched_certs()],
    }


def _used_store(result: dict) -> bool:
    ts = result.get("signature_timestamp") or {}
    return bool(result.get("completed_from_store") or ts.get("completed_from_store"))


async def _verify_signature(
    sig: EmbeddedPdfSignature,
    vc: ValidationContext,
    diff_policy: StandardDiffPolicy,
    moment: datetime,
    source: str,
    sources: _Sources,
    online: bool,
) -> dict:
    status = await async_validate_pdf_signature(
        sig, signer_validation_context=vc, ts_validation_context=vc, diff_policy=diff_policy
    )
    ts = status.timestamp_validity
    validated_now = source == "now"
    signer_problem = ts_problem = None
    if not status.trusted:
        signer_problem = await diagnose(
            status.signing_cert,
            extract_certs_for_validation(sig.signed_data).other_certs,
            vc,
            valid=status.valid,
            indication=status.trust_problem_indic,
            validated_now=validated_now,
            online=online,
        )
    if ts and not ts.trusted:
        tokens = extract_tst_data_iter(sig.signer_info, signed=False)
        ts_problem = await diagnose(
            ts.signing_cert,
            [c for token in tokens for c in extract_certs_for_validation(token).other_certs],
            vc,
            valid=ts.valid,
            indication=ts.trust_problem_indic,
            validated_now=validated_now,
            online=online,
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
        # Si no es confiable, por qué: resumen, sugerencia y el error de cada camino probado.
        "trust_problem": signer_problem,
        "coverage": status.coverage.name,
        # Intermedios del camino del firmante que no vienen en el PDF sino en la fuente.
        "completed_from_store": _from_store(status.validation_path, status.trusted, sources),
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
                "time": ts.timestamp.isoformat(),
                "tsa": ts.signing_cert.subject.human_friendly,
                "valid": ts.valid,
                "trusted": ts.trusted,
                "trust_problem": ts_problem,
                "completed_from_store": _from_store(ts.validation_path, ts.trusted, sources),
            }
            if ts
            else None
        ),
        "details": status.pretty_print_details(),
    }


def _pades_level(results: list[dict], has_dss: bool, self_contained: bool) -> str:
    has_doc_ts = any(r["type"] == "DocTimeStamp" for r in results)
    sigs = [r for r in results if r["type"] == "Signature"]
    level = "PAdES B-B"
    if sigs and all(r["signature_timestamp"] for r in sigs):
        level = "PAdES B-T"
        # LT exige que el PDF alcance solo: si la cadena se completó con la fuente, no lo es.
        if has_dss and self_contained and all(r["bottom_line"] for r in sigs):
            level = "PAdES B-LTA" if has_doc_ts else "PAdES B-LT"
    return level


def _dss_summary(reader: PdfFileReader) -> dict[str, int]:
    # Los arrays del DSS pueden ser referencias indirectas: `[]` las resuelve, `.get` no.
    dss = reader.root["/DSS"]
    return {k: len(dss[f"/{k}"]) if f"/{k}" in dss else 0 for k in ("Certs", "OCSPs", "CRLs")}
