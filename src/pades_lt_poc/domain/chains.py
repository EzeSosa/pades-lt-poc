"""Cadenas de certificados (hoja -> raíz) armadas sin exigir confianza, y de dónde salió cada eslabón.

Reglas (los ids son los de docs/arquitectura/invariantes.md):

- C-01  Primero la integridad criptográfica; la cadena se arma sólo si la firma verifica. No se
        exige confianza (`chain_for`).
- C-02  Orígenes en orden cms > dss > store > aia; el firmante primero; ante duplicados gana el
        primer origen (`candidate_pool`, `build_chain`).
- C-03  Los emisores que faltan se descargan por AIA caIssuers sólo si se pide, sólo por
        http(s) (`http_ca_issuer_urls`) y una vez por URL en cada pedido (caso de uso).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum

from .certificates import Certificate
from .signatures import CmsSignature

ALTERED_DOCUMENT = "el documento fue alterado"
ALTERED_TIMESTAMP = "el sello no corresponde a esta firma"


class CertSource(StrEnum):
    """De dónde salió un eslabón de la cadena, en orden de precedencia."""

    CMS = "cms"
    """El CMS de la firma (o del sello)."""
    DSS = "dss"
    """El DSS del PDF."""
    STORE = "store"
    """La fuente de certificados."""
    AIA = "aia"
    """Descargado de la URL AIA caIssuers del eslabón anterior."""


@dataclass(frozen=True)
class ChainLink:
    certificate: Certificate
    source: CertSource
    in_store: bool
    """Si está en la fuente de certificados (habilitado o no), venga de donde venga."""


@dataclass(frozen=True)
class ChainResult:
    """La integridad de una firma y, si verifica, la cadena de su firmante."""

    crypto_valid: bool
    intact: bool
    valid: bool
    error: str | None
    """Por qué no verifica; None si verifica."""
    links: tuple[ChainLink, ...] | None
    """Hoja -> raíz; None si la firma no verifica (C-01)."""
    chain_complete: bool | None
    """Si termina en un autofirmado; None si no se armó."""
    aia_errors: tuple[str, ...]
    """Los problemas al buscar emisores por AIA, si se buscó y faltó alguno."""


IssuerLookup = Callable[[Certificate], tuple[list[Certificate], list[str]]]
"""Dado un certificado, sus posibles emisores descargados y los errores al buscarlos."""

IssuedBy = Callable[[Certificate, Certificate], bool]


def http_ca_issuer_urls(cert: Certificate) -> tuple[list[str], str | None]:
    """C-03: las URLs AIA caIssuers que se pueden descargar (http/https), o por qué no hay ninguna."""
    if cert.ca_issuer_urls is None:
        return [], f"{cert.subject}: no tiene AIA caIssuers"
    urls = [u for u in cert.ca_issuer_urls if u.lower().startswith(("http://", "https://"))]
    return urls, None if urls else f"{cert.subject}: no tiene AIA caIssuers por HTTP"


def candidate_pool(cms: CmsSignature, extra: Iterable[tuple[Certificate, CertSource]]) -> list[tuple[Certificate, CertSource]]:
    """C-02: el firmante primero, después los demás del CMS y los `extra` en su orden, sin duplicados
    (un certificado que aparece en dos lugares queda con el primer origen)."""
    pool: dict[Certificate, CertSource] = {}
    for cert, source in [(cms.signer, CertSource.CMS), *((c, CertSource.CMS) for c in cms.other_certificates), *extra]:
        pool.setdefault(cert, source)
    return list(pool.items())


def build_chain(
    pool: list[tuple[Certificate, CertSource]], issued_by: IssuedBy, lookup: IssuerLookup | None
) -> tuple[list[tuple[Certificate, CertSource]], list[str]]:
    """Sube desde el primero de `pool` (la hoja) buscando el emisor de cada eslabón, hasta un autofirmado.

    El emisor se busca primero en `pool`, en orden, y si no está y hay `lookup`, entre lo que
    devuelva para el eslabón (origen AIA). Un certificado no se repite en la cadena. Si no se
    encuentra un emisor, la cadena queda incompleta. Devuelve la cadena y los errores de `lookup`.
    """
    chain = [pool[0]]
    errors: list[str] = []
    while not chain[-1][0].self_signed:
        current, used = chain[-1][0], {c for c, _ in chain}
        issuer = next(((c, s) for c, s in pool if c not in used and issued_by(current, c)), None)
        if issuer is None and lookup is not None:
            fetched, errs = lookup(current)
            issuer = next(((c, CertSource.AIA) for c in fetched if c not in used and issued_by(current, c)), None)
            if issuer is None:
                errors.extend(errs or [f"{current.subject}: AIA no trae a su emisor"])
        if issuer is None:
            break
        chain.append(issuer)
    return chain, errors


def chain_for(
    cms: CmsSignature,
    extra: Iterable[tuple[Certificate, CertSource]],
    altered: str,
    issued_by: IssuedBy,
    lookup: IssuerLookup | None,
    known_sha256: frozenset[str],
) -> ChainResult:
    """C-01: la integridad de `cms` y, si verifica, la cadena de su firmante con `extra` y `lookup`.

    `altered` es el motivo a mostrar si lo cubierto cambió. `known_sha256` son las huellas de la
    fuente de certificados, para marcar `in_store` en cada eslabón.
    """
    integrity = cms.integrity
    if not integrity.ok:
        return ChainResult(False, integrity.intact, integrity.valid, integrity.failure(altered), None, None, ())
    chain, errors = build_chain(candidate_pool(cms, extra), issued_by, lookup)
    links = tuple(ChainLink(c, s, c.sha256 in known_sha256) for c, s in chain)
    return ChainResult(True, True, True, None, links, chain[-1][0].self_signed, tuple(errors))
