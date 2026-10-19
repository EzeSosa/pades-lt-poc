"""Configuración de la app: se lee una sola vez, al crearla, y se pasa explícitamente.

Ningún módulo lee variables de entorno al importarse (ver docs/arquitectura/README.md).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

DEFAULT_BASE_URL = "http://127.0.0.1:8000"


@dataclass(frozen=True)
class Settings:
    pki_dir: Path
    """Carpeta de la mini PKI (certificados, claves y revocaciones). `$PKI_DIR`, por defecto `./pki`."""

    public_base_url: str
    """URL con la que la app se ve desde afuera. Queda grabada en los certificados de la PKI (CDP,
    AIA y OCSP) al generarse, y la firma la usa para pedir el sello a su propia TSA. `$PUBLIC_BASE_URL`."""

    cert_store_db: Path
    """Base SQLite de la fuente de certificados. `$CERT_STORE_DB`, por defecto `certs.db` junto a la PKI."""

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> Settings:
        pki_dir = Path(env.get("PKI_DIR") or Path.cwd() / "pki")
        return cls(
            pki_dir=pki_dir,
            public_base_url=(env.get("PUBLIC_BASE_URL") or DEFAULT_BASE_URL).rstrip("/"),
            cert_store_db=Path(env.get("CERT_STORE_DB") or pki_dir.parent / "certs.db"),
        )
