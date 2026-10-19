"""Los caminos candidatos de un certificado no confiable, y el error de cada uno.

pyHanko resume la falla en una indicación AdES (`CERTIFICATE_CHAIN_GENERAL_FAILURE` y
similares) y el mensaje de pyhanko-certvalidator sólo va al log. Para poder decir el
motivo, se vuelve a validar cada camino candidato con el mismo ValidationContext y se
junta el error de cada uno. Sólo se hace con lo que no resultó confiable.

Qué motivo se muestra y con qué sugerencia lo decide el dominio (`domain.verification.trust_problem`).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

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

from ....domain.certificates import Certificate
from ....domain.verification import PathAttempt, TrustReason

MAX_PATHS = 5


def reason(error: ValidationError) -> TrustReason:
    """El motivo de negocio de un error de pyhanko-certvalidator."""
    if isinstance(error, RevokedError):
        return TrustReason.REVOKED
    if isinstance(error, InsufficientRevinfoError):
        # pyhanko-certvalidator no siempre usa StaleRevinfoError: lo dice el mensaje.
        return TrustReason.STALE_REVOCATION if "not recent enough" in str(error) else TrustReason.MISSING_REVOCATION
    if isinstance(error, ExpiredError):
        return TrustReason.EXPIRED
    if isinstance(error, NotYetValidError):
        return TrustReason.NOT_YET_VALID
    if isinstance(error, DisallowedAlgorithmError):
        return TrustReason.ALGORITHM
    return TrustReason.OTHER


async def attempts(
    cert: asn1_x509.Certificate,
    other_certs: Iterable[asn1_x509.Certificate],
    vc: ValidationContext,
    convert: Callable[[asn1_x509.Certificate], Certificate],
) -> tuple[PathAttempt, ...]:
    """Hasta `MAX_PATHS` caminos desde `cert` hasta un ancla, cada uno con su error (o ninguno).

    `other_certs` son los certificados que trae la firma (o el sello), para construir caminos.
    Cada camino va de la hoja al ancla. Sin caminos, la tupla está vacía.
    """
    vc.certificate_registry.register_multiple(list(other_certs))
    found = []
    candidates = vc.path_builder.async_build_paths_lazy(cert)
    try:
        async for path in candidates:
            chain = tuple(convert(c) for c in reversed(list(path.iter_certs(include_root=True))))
            try:
                await async_validate_path(vc, path)
            except ValidationError as e:
                found.append(PathAttempt(chain, reason(e), e.failure_msg))
            else:
                found.append(PathAttempt(chain, None, None))
            if len(found) == MAX_PATHS:
                break
    except PathBuildingError:
        pass
    finally:
        await candidates.cancel()
    return tuple(found)
