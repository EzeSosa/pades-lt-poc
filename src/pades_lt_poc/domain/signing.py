"""Firma PAdES de un PDF: qué se puede firmar, en qué campo y con qué perfil.

Reglas (los ids son los de docs/arquitectura/invariantes.md):

- S-01  Un PDF inválido o cifrado no se firma (`check_signable`; el adaptador rechaza lo que no
        puede leer).
- S-02  El campo de firma es el primer `FirmaN` libre del formulario (`free_field_name`).
- S-03  Cada firma usa un firmante nuevo (contrato del adaptador: pyHanko le deja estado).
- S-04  PAdES (`ETSI.CAdES.detached`) con SHA-256, sello de tiempo de firma (B-T), DSS con la
        cadena y la revocación (B-LT) y, si se pide, un DocTimeStamp (B-LTA); revocación
        obligatoria al firmar (`SignatureSpec`).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .errors import UnprocessablePdf

FIELD_PREFIX = "Firma"
ENCRYPTED = "El PDF está protegido con contraseña: quitale la protección antes de firmarlo."


@dataclass(frozen=True)
class SignRequest:
    reason: str
    location: str
    lta: bool
    """Si además se agrega un DocTimeStamp (B-LTA)."""


@dataclass(frozen=True)
class SignatureSpec:
    """Lo que el adaptador tiene que producir (S-04). El perfil es fijo; sólo varían estos campos."""

    field_name: str
    reason: str
    location: str
    lta: bool
    digest_algorithm: str = "sha256"
    subfilter: str = "ETSI.CAdES.detached"


def check_signable(encrypted: bool) -> None:
    """S-01: un PDF cifrado no se puede firmar sin su contraseña."""
    if encrypted:
        raise UnprocessablePdf(ENCRYPTED)


def free_field_name(taken: Iterable[str]) -> str:
    """S-02: `FirmaN` con el menor N que no use ningún campo del formulario, sea de firma o no.

    `taken` son los nombres completos de los campos (con los de sus padres, separados por punto).
    Contar las firmas no alcanza: el PDF puede traer un campo `Firma2` con una sola firma, o un
    campo de texto `Firma1`, y no se puede firmar sobre ninguno de los dos.
    """
    taken = set(taken)
    n = 1
    while f"{FIELD_PREFIX}{n}" in taken:
        n += 1
    return f"{FIELD_PREFIX}{n}"


def spec_for(request: SignRequest, field_names: Iterable[str]) -> SignatureSpec:
    return SignatureSpec(free_field_name(field_names), request.reason, request.location, request.lta)
