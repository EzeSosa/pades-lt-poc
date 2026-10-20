"""Caso de uso: validar las firmas de un PDF con el material del PDF y la fuente de certificados."""

from __future__ import annotations

from collections.abc import Sequence

from ...domain.certificates import Certificate
from ...domain.signatures import SignatureKind
from ...domain.source import TrustSnapshot
from ...domain.verification import (
    SignatureVerdict,
    TimestampVerdict,
    ValidationPolicy,
    ValidationTimeMode,
    VerificationOptions,
    VerificationReport,
    completed_from_store,
    legacy_sha1_roots,
    pades_level,
    trust_anchors,
    trust_problem,
    validation_moment,
)
from ..ports import Clock, SignatureValidator
from .certificate_source import CertificateSource


class VerifySignatures:
    """Valida con revocación obligatoria (hard-fail), sin conexión por defecto (reglas V-01 a V-10).

    Anclas de confianza: las implícitas (la raíz de la PoC, que se regenera con la PKI) y las
    raíces confiables habilitadas de la fuente. Los intermedios habilitados de la fuente completan
    cadenas que el PDF no trae; cuando se usan, la firma lo informa en `completed_from_store` y el
    PDF deja de contar como LT por sí mismo.

    La fuente se lee en cada verificación (un snapshot), así que un cambio del ABM aplica enseguida.

    El análisis del documento (protección, formulario, revisiones) es otro caso de uso: `AnalyzeDocument`.
    """

    def __init__(
        self, validator: SignatureValidator, source: CertificateSource, implicit_anchors: Sequence[Certificate], clock: Clock
    ) -> None:
        self.validator = validator
        self.source = source
        self.implicit_anchors = tuple(implicit_anchors)
        self.clock = clock

    def trust_roots(self, snapshot: TrustSnapshot | None = None) -> tuple[Certificate, ...]:
        """V-01: las anclas implícitas y las raíces confiables habilitadas de la fuente.

        `verify` pasa el snapshot que ya tomó, para que anclas e intermedios salgan del mismo estado
        de la fuente aunque el ABM cambie en el medio (F-05).
        """
        snapshot = snapshot or self.source.snapshot()
        return trust_anchors(self.implicit_anchors, snapshot.trusted_roots)

    async def verify(self, pdf: bytes, options: VerificationOptions) -> VerificationReport:
        options.check()  # V-04
        snapshot = self.source.snapshot()
        anchors = self.trust_roots(snapshot)
        policy = ValidationPolicy(
            trust_anchors=anchors,
            intermediates=snapshot.intermediates,
            legacy_sha1_roots=legacy_sha1_roots(anchors),  # V-02
            diff_policy=options.diff_policy,
            online=options.online,
        )
        now = self.clock.now()
        verdicts = []
        async with self.validator.open(pdf, policy) as session:
            for ref in session.signatures:
                if ref.kind is SignatureKind.DOC_TIMESTAMP:
                    verdicts.append(SignatureVerdict(ref.field_name, ref.kind, None, None, None, (), None))
                    continue
                # La hora declarada sólo se lee si se pidió validar a esa hora.
                claimed = session.claimed_signing_time(ref) if options.validation_time is ValidationTimeMode.CLAIMED_SIGNING_TIME else None
                at = validation_moment(options.validation_time, claimed, now)  # V-08
                evaluation = await session.evaluate(ref, at)
                validated_now = not at.in_the_past

                def problem(trusted, valid, indication, attempts):  # V-09
                    return trust_problem(
                        trusted=trusted,
                        valid=valid,
                        indication=indication,
                        attempts=attempts,
                        validated_now=validated_now,
                        online=options.online,
                    )

                def from_store(trusted, intermediates):  # V-06
                    return completed_from_store(trusted, intermediates, session.embedded_sha256, snapshot.known_sha256)

                ts = evaluation.timestamp
                verdicts.append(
                    SignatureVerdict(
                        field_name=ref.field_name,
                        kind=ref.kind,
                        evaluation=evaluation,
                        validated_at=at,
                        trust_problem=problem(evaluation.trusted, evaluation.valid, evaluation.indication, evaluation.attempts),
                        completed_from_store=from_store(evaluation.trusted, evaluation.path_intermediates),
                        timestamp=(
                            TimestampVerdict(
                                ts,
                                problem(ts.trusted, ts.valid, ts.indication, ts.attempts),
                                from_store(ts.trusted, ts.path_intermediates),
                            )
                            if ts
                            else None
                        ),
                    )
                )
            fetched = session.fetched()
            dss = session.dss

        self_contained = not any(v.used_store for v in verdicts)
        return VerificationReport(
            options=options,
            pades_level=pades_level(verdicts, dss is not None, self_contained, options.online),  # V-05, V-07
            dss=dss,
            fetched=fetched,
            trust_anchors=len(anchors),
            intermediates=len(snapshot.intermediates),
            self_contained=self_contained,
            signatures=tuple(verdicts),
        )
