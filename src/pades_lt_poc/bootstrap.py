"""Raíz de composición: el único lugar que crea los servicios y los conecta entre sí.

Recibe la configuración ya leída (`config.Settings`), arma cada pieza con sus dependencias
explícitas y devuelve un `Services` que la app guarda en `app.state.services` durante su
lifespan. Lo que antes era estado global del proceso (el índice de CRLs instalado en
pyhanko-certvalidator, el caché de CRLs descargadas) se crea o se instala acá, una vez.

Ver docs/arquitectura/README.md.
"""

from __future__ import annotations

from dataclasses import dataclass

from pyhanko.keys import load_cert_from_pemder
from pyhanko.sign.timestamps import DummyTimeStamper

from .adapters.outbound.clock import SystemClock
from .adapters.outbound.crypto.codec import CryptographyCertificateCodec
from .adapters.outbound.seed_catalog import PackagedSeedCatalog
from .adapters.outbound.sqlite.certificate_repository import SqliteCertificateRepository
from .application.ports import Clock
from .application.use_cases.certificate_source import CertificateSource
from .config import Settings
from .pki import MiniPki
from .services import crl_index
from .services.certificates import CertificateExtractor
from .services.fetching import CrlCache, RevocationFetcherBackend
from .services.inspection import CertificateInspector
from .services.signing import PdfSigner
from .services.timestamping import load_tsa
from .services.verification import SignatureVerifier


@dataclass(frozen=True)
class Services:
    settings: Settings
    pki: MiniPki
    tsa_engine: DummyTimeStamper
    signer: PdfSigner
    clock: Clock
    repository: SqliteCertificateRepository
    source: CertificateSource
    crl_cache: CrlCache
    verifier: SignatureVerifier
    certificate_extractor: CertificateExtractor
    certificate_inspector: CertificateInspector

    def close(self) -> None:
        self.repository.close()


def build(settings: Settings, clock: Clock | None = None) -> Services:
    """Crea la PKI si no existe, abre la fuente (con su carga inicial la primera vez) y arma los servicios.

    `clock` es el reloj del sistema salvo que se pase otro (los tests).
    """
    clock = clock or SystemClock()
    pki = MiniPki(settings.pki_dir, settings.public_base_url)
    pki.ensure()

    # Buscar un serial en una CRL grande (la de la ONTI) recorriéndola en Python tarda segundos:
    # se reemplaza la búsqueda de pyhanko-certvalidator por un índice armado con `cryptography`.
    # Es global al proceso (pyHanko no la recibe por parámetro) y vale con y sin conexión.
    crl_index.install()

    codec = CryptographyCertificateCodec()
    repository = SqliteCertificateRepository(settings.cert_store_db, codec)
    # La fuente de certificados: la primera vez que se crea la base, con su carga inicial.
    source = CertificateSource(repository, codec, PackagedSeedCatalog(), clock)
    source.initialize()
    # Las CRL descargadas se guardan entre verificaciones hasta su nextUpdate.
    crl_cache = CrlCache()
    poc_root = load_cert_from_pemder(str(pki.entity(pki.ROOT).cert_path))
    return Services(
        settings=settings,
        pki=pki,
        tsa_engine=load_tsa(pki),
        signer=PdfSigner.from_pki(pki),
        clock=clock,
        repository=repository,
        source=source,
        crl_cache=crl_cache,
        verifier=SignatureVerifier(source, [poc_root], lambda: RevocationFetcherBackend(crl_cache=crl_cache)),
        certificate_extractor=CertificateExtractor(source),
        certificate_inspector=CertificateInspector(source),
    )
