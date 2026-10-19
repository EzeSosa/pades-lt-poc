"""El testbed: el "mundo externo" que la PoC simula para poder firmar y validar sin depender de nadie.

- `pki.py`: una mini PKI de dos niveles (raíz, intermedia y firmante, TSA y respondedor OCSP),
  con sus CRLs, su respondedor OCSP y revocación manual.
- `tsa.py`: el motor de una TSA RFC 3161.
- `http.py`: los endpoints que los publican (`/pki`, `/ocsp`, `/tsa`), como lo haría una CA real.

En un sistema real nada de esto existe: la CA, el OCSP y la TSA son servicios de terceros. Por
eso el núcleo (dominio, aplicación y adaptadores) no lo importa: lo conecta la raíz de
composición (`bootstrap.py`), que le saca a la PKI la identidad del firmante, el ancla implícita
y la TSA. Ver docs/adr/0003-testbed-fuera-del-nucleo.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pyhanko.sign.timestamps import DummyTimeStamper

from .pki import MiniPki
from .tsa import load_tsa


@dataclass(frozen=True)
class Testbed:
    pki: MiniPki
    tsa_engine: DummyTimeStamper

    __test__ = False  # no es una clase de tests (pytest)

    @classmethod
    def create(cls, directory: Path, base_url: str) -> Testbed:
        """La PKI de `directory` (generada si no existe), publicada bajo `base_url`, y su TSA."""
        pki = MiniPki(directory, base_url)
        pki.ensure()
        return cls(pki, load_tsa(pki))
