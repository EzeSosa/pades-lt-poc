"""Raíz de composición: el único lugar que crea los servicios y los conecta entre sí.

Recibe la configuración ya leída (`config.Settings`), arma cada pieza con sus dependencias
explícitas y devuelve un `Services` que la app guarda en `app.state.services` durante su
lifespan. Lo que antes era estado global del proceso (el índice de CRLs instalado en
pyhanko-certvalidator, el caché de CRLs descargadas) se crea o se instala acá, una vez.

Ver docs/arquitectura/README.md.
"""

from __future__ import annotations

from dataclasses import dataclass

from pyhanko.sign.timestamps import DummyTimeStamper

from .adapters.outbound.clock import SystemClock
from .adapters.outbound.crypto.codec import CryptographyCertificateCodec
from .adapters.outbound.http.issuer_fetcher import HttpIssuerFetcher
from .adapters.outbound.pyhanko import crl_index
from .adapters.outbound.pyhanko.fetching import CrlCache, RevocationFetcherBackend
from .adapters.outbound.pyhanko.signed_pdf_reader import PyHankoSignedPdfReader
from .adapters.outbound.pyhanko.signer import PyHankoPdfSigner
from .adapters.outbound.pyhanko.validator import PyHankoSignatureValidator
from .adapters.outbound.seed_catalog import PackagedSeedCatalog
from .adapters.outbound.sqlite.certificate_repository import SqliteCertificateRepository
from .application.ports import Clock, IssuerFetcher
from .application.use_cases.certificate_chains import ExtractCertificateChains
from .application.use_cases.certificate_source import CertificateSource
from .application.use_cases.inspect_certificates import InspectCertificates
from .application.use_cases.sign_pdf import SignPdf
from .application.use_cases.verify_signatures import VerifySignatures
from .config import Settings
from .pki import MiniPki
from .services.timestamping import load_tsa


@dataclass(frozen=True)
class Services:
    settings: Settings
    pki: MiniPki
    tsa_engine: DummyTimeStamper
    sign_pdf: SignPdf
    clock: Clock
    repository: SqliteCertificateRepository
    source: CertificateSource
    crl_cache: CrlCache
    verify_signatures: VerifySignatures
    extract_chains: ExtractCertificateChains
    inspect_certificates: InspectCertificates

    def close(self) -> None:
        self.repository.close()


def build(settings: Settings, *, clock: Clock | None = None, issuer_fetcher: IssuerFetcher | None = None) -> Services:
    """Crea la PKI si no existe, abre la fuente (con su carga inicial la primera vez) y arma los servicios.

    `clock` y `issuer_fetcher` son el reloj del sistema y la descarga AIA por HTTP salvo que se
    pasen otros (los tests).
    """
    clock = clock or SystemClock()
    issuer_fetcher = issuer_fetcher or HttpIssuerFetcher()
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
    # La raíz de la PoC es ancla implícita: se regenera con la PKI, así que guardada en la fuente quedaría vieja.
    [poc_root] = codec.parse(pki.entity(pki.ROOT).cert_path.read_bytes())
    return Services(
        settings=settings,
        pki=pki,
        tsa_engine=load_tsa(pki),
        # El firmante de la PoC, con su cadena; al firmar, la cadena se valida contra la raíz de la PoC.
        sign_pdf=SignPdf(
            PyHankoPdfSigner.from_files(
                key=pki.entity(pki.SIGNER).key_path,
                cert=pki.entity(pki.SIGNER).cert_path,
                chain=[pki.entity(pki.INTERMEDIATE).cert_path, pki.entity(pki.ROOT).cert_path],
                trust_root=pki.entity(pki.ROOT).cert_path,
            )
        ),
        clock=clock,
        repository=repository,
        source=source,
        crl_cache=crl_cache,
        verify_signatures=VerifySignatures(
            PyHankoSignatureValidator(codec, lambda: RevocationFetcherBackend(crl_cache=crl_cache)), source, [poc_root], clock
        ),
        extract_chains=ExtractCertificateChains(PyHankoSignedPdfReader(codec), codec, source, issuer_fetcher),
        inspect_certificates=InspectCertificates(codec, source),
    )
