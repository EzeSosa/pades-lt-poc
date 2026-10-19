"""`SignatureValidator` con pyHanko: valida cada firma de un PDF con el DSS, la fuente y, si se pide, conexión.

Lo que pyHanko devuelve se traduce a `SignatureEvaluation`; ningún tipo de pyHanko sale de este
módulo. Ver docs/arquitectura/adaptadores.md.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import datetime, timedelta

from asn1crypto import x509 as asn1_x509
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import SuspiciousModification
from pyhanko.sign.validation import DocumentSecurityStore, async_validate_pdf_signature
from pyhanko.sign.validation.generic_cms import extract_certs_for_validation, extract_tst_data_iter
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.fetchers import FetcherBackend, Fetchers
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.policy_decl import AlgorithmUsagePolicy

from ....application.ports import CertificateCodec, SignatureRef
from ....domain.signatures import SignatureKind
from ....domain.verification import (
    DssSummary,
    FetchedCrl,
    FetchedOcsp,
    FetchedRevocation,
    Modifications,
    SignatureEvaluation,
    TimestampEvaluation,
    ValidatedAt,
    ValidationPolicy,
)
from .convert import CertificateConverter, to_asn1
from .policies import DIFF_POLICIES, LegacyRootsPolicy
from .signed_pdf_reader import open_signed_pdf
from .trust_paths import attempts

# Lo descargado se emite "ahora" según el reloj del servidor remoto: con 1 s de tolerancia (lo de
# pyHanko), un par de segundos de desfasaje lo vuelven "del futuro".
ONLINE_CLOCK_SKEW = timedelta(minutes=2)


class PyHankoSignatureValidator:
    """Implementa `application.ports.SignatureValidator`.

    `fetcher_backend` crea un juego de fetchers (CRL, OCSP, AIA) por sesión con conexión; los
    certificados se convierten con el `CertificateCodec`.
    """

    def __init__(self, codec: CertificateCodec, fetcher_backend: Callable[[], FetcherBackend]) -> None:
        self.codec = codec
        self.fetcher_backend = fetcher_backend

    @asynccontextmanager
    async def open(self, pdf: bytes, policy: ValidationPolicy) -> AsyncIterator[_Session]:
        reader = open_signed_pdf(pdf)
        async with AsyncExitStack() as stack:
            # Un solo juego de fetchers para todo el PDF: lo descargado para una firma sirve a las demás.
            fetchers = await stack.enter_async_context(self.fetcher_backend()) if policy.online else None
            yield _Session(reader, policy, fetchers, CertificateConverter(self.codec))


class _Session:
    """Implementa `application.ports.ValidationSession`."""

    def __init__(self, reader: PdfFileReader, policy: ValidationPolicy, fetchers: Fetchers | None, convert: CertificateConverter) -> None:
        self._sigs = reader.embedded_signatures
        self._fetchers = fetchers
        self._convert = convert
        self._diff_policy = DIFF_POLICIES[policy.diff_policy]
        has_dss = "/DSS" in reader.root
        dss_store = DocumentSecurityStore.read_dss(reader) if has_dss else None
        self.dss = _dss_summary(reader) if has_dss else None
        self.embedded_sha256 = frozenset(c.sha256.hex() for c in _embedded_certs(reader, dss_store))
        self.signatures = tuple(
            SignatureRef(
                i,
                sig.field_name,
                SignatureKind.DOC_TIMESTAMP if sig.sig_object.get("/Type") == "/DocTimeStamp" else SignatureKind.SIGNATURE,
            )
            for i, sig in enumerate(self._sigs)
        )
        self._contexts = _ContextFactory(
            dss_store,
            to_asn1(policy.trust_anchors),
            to_asn1(policy.intermediates),
            LegacyRootsPolicy(to_asn1(policy.legacy_sha1_roots)),
            fetchers,
        )

    def claimed_signing_time(self, ref: SignatureRef) -> datetime | None:
        # El atributo signingTime del CMS o, si no está, /M.
        return self._sigs[ref.index].self_reported_timestamp

    async def evaluate(self, ref: SignatureRef, at: ValidatedAt) -> SignatureEvaluation:
        sig = self._sigs[ref.index]
        vc = self._contexts.at(at.time, in_the_past=at.in_the_past)
        status = await async_validate_pdf_signature(
            sig, signer_validation_context=vc, ts_validation_context=vc, diff_policy=self._diff_policy
        )
        # Los caminos probados sólo se buscan si verifica y no es confiable: es caro (revalida cada camino).
        signer_attempts = ()
        if status.valid and not status.trusted:
            others = extract_certs_for_validation(sig.signed_data).other_certs
            signer_attempts = await attempts(status.signing_cert, others, vc, self._convert)
        ts = status.timestamp_validity
        timestamp = None
        if ts:
            ts_attempts = ()
            if ts.valid and not ts.trusted:
                tokens = extract_tst_data_iter(sig.signer_info, signed=False)
                others = [c for token in tokens for c in extract_certs_for_validation(token).other_certs]
                ts_attempts = await attempts(ts.signing_cert, others, vc, self._convert)
            timestamp = TimestampEvaluation(
                time=ts.timestamp,
                tsa=self._convert(ts.signing_cert),
                valid=ts.valid,
                trusted=ts.trusted,
                indication=ts.trust_problem_indic.name if ts.trust_problem_indic else None,
                attempts=ts_attempts,
                path_intermediates=self._intermediates(ts.validation_path),
            )
        return SignatureEvaluation(
            subfilter=str(sig.sig_object.get("/SubFilter")),
            signer=self._convert(status.signing_cert),
            bottom_line=status.bottom_line,
            intact=status.intact,
            valid=status.valid,
            trusted=status.trusted,
            indication=status.trust_problem_indic.name if status.trust_problem_indic else None,
            attempts=signer_attempts,
            coverage=status.coverage.name,
            path_intermediates=self._intermediates(status.validation_path),
            modifications=Modifications(
                level=status.modification_level.name if status.modification_level else None,
                docmdp_ok=status.docmdp_ok,
                suspicious=str(status.diff_result) if isinstance(status.diff_result, SuspiciousModification) else None,
            ),
            details=status.pretty_print_details(),
            timestamp=timestamp,
        )

    def fetched(self) -> FetchedRevocation | None:
        return _fetched_summary(self._fetchers, self._convert) if self._fetchers else None

    def _intermediates(self, path: ValidationPath | None) -> tuple:
        """Los intermedios del camino, sin el ancla ni la hoja. Aunque la validación falle, pyHanko
        devuelve el camino con el que falló: decidir si cuenta es del dominio."""
        if path is None:
            return ()
        return tuple(self._convert(c) for c in list(path.iter_certs(include_root=False))[:-1])


class _ContextFactory:
    """Arma el ValidationContext de cada firma: DSS + fuente, a la hora que corresponda.

    Con `fetchers` (modo con conexión) se descarga lo que falte; pyHanko no admite
    descargar con una hora fija, así que valida a la hora actual.
    """

    def __init__(self, dss_store, roots, intermediates, policy: AlgorithmUsagePolicy, fetchers: Fetchers | None = None) -> None:
        self.dss_store, self.roots, self.intermediates, self.policy = dss_store, roots, intermediates, policy
        self.fetchers = fetchers

    def at(self, moment: datetime, in_the_past: bool) -> ValidationContext:
        # Validando en el pasado, la revocación embebida es posterior a `moment` (se obtuvo
        # después de firmar) y pyHanko la descarta salvo con `retroactive_revinfo`.
        kwargs = dict(
            trust_roots=self.roots,
            other_certs=self.intermediates,  # el DSS los suma a los suyos
            revocation_mode="hard-fail",  # V-03
            algorithm_usage_policy=self.policy,
            retroactive_revinfo=in_the_past,
        )
        if self.fetchers:
            kwargs.update(allow_fetching=True, fetchers=self.fetchers, time_tolerance=ONLINE_CLOCK_SKEW)
        else:
            kwargs.update(allow_fetching=False, moment=moment)
        if self.dss_store:
            return self.dss_store.as_validation_context(kwargs)
        # Sin DSS no hay revocación: listas vacías para que la firma resulte no confiable
        # (pyHanko lanza ValueError si en hard-fail sin fetching no recibe ninguna).
        return ValidationContext(**kwargs, crls=[], ocsps=[])


def _embedded_certs(reader: PdfFileReader, dss_store: DocumentSecurityStore | None) -> list[asn1_x509.Certificate]:
    """Todos los certificados que trae el PDF: DSS, CMS de cada firma y sus sellos de tiempo."""
    certs = list(dss_store.load_certs()) if dss_store else []
    for sig in reader.embedded_signatures:
        found = extract_certs_for_validation(sig.signed_data)
        certs += [found.signer_cert, *found.other_certs]
        for token in extract_tst_data_iter(sig.signer_info, signed=False):
            found = extract_certs_for_validation(token)
            certs += [found.signer_cert, *found.other_certs]
    return certs


def _dss_summary(reader: PdfFileReader) -> DssSummary:
    # Los arrays del DSS pueden ser referencias indirectas: `[]` las resuelve, `.get` no.
    dss = reader.root["/DSS"]
    count = {k: len(dss[f"/{k}"]) if f"/{k}" in dss else 0 for k in ("Certs", "OCSPs", "CRLs")}
    return DssSummary(certs=count["Certs"], ocsps=count["OCSPs"], crls=count["CRLs"])


def _fetched_summary(fetchers: Fetchers, convert: CertificateConverter) -> FetchedRevocation:
    """Lo que se descargó en modo con conexión: CRLs, respuestas OCSP y emisores (AIA).

    Una CRL puede venir del caché: se descargó en una verificación anterior (`fetched_at`) y
    sigue vigente.
    """
    from_cache = getattr(fetchers.crl_fetcher, "from_cache", {})

    def crl(c) -> FetchedCrl:
        tbs = c["tbs_cert_list"]
        cached = from_cache.get(id(c))
        return FetchedCrl(
            issuer=c.issuer.human_friendly,
            this_update=tbs["this_update"].native,
            next_update=tbs["next_update"].native,
            from_cache=cached is not None,
            fetched_at=cached.fetched_at if cached else None,
        )

    def ocsp(r) -> FetchedOcsp:
        data = r["response_bytes"]["response"].parsed["tbs_response_data"]
        [single, *_] = data["responses"]
        return FetchedOcsp(
            serial_number=single["cert_id"]["serial_number"].native,
            status=single["cert_status"].name,
            produced_at=data["produced_at"].native,
        )

    return FetchedRevocation(
        # La misma CRL puede llegar de dos URLs (p. ej. cdp1 y cdp2): se lista una vez.
        crls=tuple(crl(c) for c in {c.dump(): c for c in fetchers.crl_fetcher.fetched_crls()}.values()),
        ocsps=tuple(ocsp(r) for r in fetchers.ocsp_fetcher.fetched_responses()),
        certificates=tuple(convert(c) for c in fetchers.cert_fetcher.fetched_certs()),
    )
