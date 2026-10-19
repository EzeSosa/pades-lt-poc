"""`SeedCatalog` con los archivos de `seed/`, empaquetados con la app."""

from __future__ import annotations

from pathlib import Path

from ...domain.source import SeedCertificate

SEED_DIR = Path(__file__).parent.parent.parent / "seed"

# Archivo (DER) -> nota. Es la carga inicial: se aplica una sola vez, al crear la base.
SEEDS = {
    "ac-raiz-argentina-2007.der": "AC Raíz de la Infraestructura de Firma Digital de Argentina (2007). Firma con SHA-1 a sus CAs.",
    "ac-raiz-argentina-2016.der": "AC Raíz de la Infraestructura de Firma Digital de Argentina (2016).",
    "ac-onti-firma-digital.der": "AC de Firma Digital de la ONTI, emitida por la AC Raíz 2007. Emite los certificados de CiDi.",
}


class PackagedSeedCatalog:
    """Implementa `application.ports.SeedCatalog` con `SEEDS`, leídos de `directory`."""

    def __init__(self, directory: Path = SEED_DIR, seeds: dict[str, str] = SEEDS) -> None:
        self.directory = directory
        self._seeds = dict(seeds)

    def seeds(self) -> list[SeedCertificate]:
        return [SeedCertificate((self.directory / name).read_bytes(), notes) for name, notes in self._seeds.items()]
