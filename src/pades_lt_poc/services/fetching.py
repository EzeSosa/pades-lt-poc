"""Descarga de CRL, OCSP y emisores (AIA) para /verify con conexión.

Los fetchers de aiohttp de pyhanko-certvalidator, con dos arreglos:

- Un timeout no es un error de descarga para pyHanko (sólo `ClientError`): se propaga y la
  verificación entera falla. Acá se convierte en CRLFetchError / OCSPFetchError /
  CertificateFetchError, que pyHanko sí trata como "no se pudo descargar".
- `fetched_certs()` de AIOHttpCertificateFetcher arma un set con la lista de cada URL y
  lanza TypeError en cuanto descargó algo: se aplanan los resultados por URL.

Las CRL tienen un timeout propio, más largo: la de la AC ONTI pesa ~9 MB y tarda >10 s. Y
se guardan entre verificaciones (`CrlCache`) hasta su `nextUpdate`: hasta entonces la CA no
publica otra, así que volver a bajarla no aporta nada. Las respuestas OCSP no se guardan:
son por certificado, chicas y rápidas.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime

from asn1crypto import crl as asn1_crl
from pyhanko_certvalidator.errors import CertificateFetchError, CRLFetchError, OCSPFetchError
from pyhanko_certvalidator.fetchers import FetcherBackend, Fetchers
from pyhanko_certvalidator.fetchers.aiohttp_fetchers.cert_fetch_client import AIOHttpCertificateFetcher
from pyhanko_certvalidator.fetchers.aiohttp_fetchers.crl_client import AIOHttpCRLFetcher, _grab_crl
from pyhanko_certvalidator.fetchers.aiohttp_fetchers.ocsp_client import AIOHttpOCSPFetcher
from pyhanko_certvalidator.fetchers.aiohttp_fetchers.util import LazySession

TIMEOUT = 10  # segundos por pedido OCSP o AIA
CRL_TIMEOUT = 60  # segundos por CRL
MAX_CACHED_CRLS = 32


@dataclass(frozen=True)
class CachedCrl:
    crl: asn1_crl.CertificateList
    fetched_at: datetime
    next_update: datetime


class CrlCache:
    """Las CRL descargadas, por URL, hasta su `nextUpdate`. Una por proceso (`CRL_CACHE`)."""

    def __init__(self, max_entries: int = MAX_CACHED_CRLS) -> None:
        self.max_entries = max_entries
        self._entries: OrderedDict[str, CachedCrl] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, url: str, now: datetime | None = None) -> CachedCrl | None:
        now = now or datetime.now(UTC)
        with self._lock:
            entry = self._entries.get(url)
            if entry is None:
                return None
            if now >= entry.next_update:
                del self._entries[url]
                return None
            self._entries.move_to_end(url)
            return entry

    def put(self, url: str, crl: asn1_crl.CertificateList) -> None:
        # Sin nextUpdate no hay hasta cuándo guardarla.
        next_update = crl["tbs_cert_list"]["next_update"].native
        if next_update is None:
            return
        with self._lock:
            self._entries[url] = CachedCrl(crl, datetime.now(UTC), next_update)
            self._entries.move_to_end(url)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


CRL_CACHE = CrlCache()


class _TimeoutAsFetchError:
    """Mixin: un timeout en la tarea de descarga se convierte en el error de descarga de pyHanko."""

    fetch_error: type[Exception]
    what: str

    async def _post_fetch_task(self, tag, async_fun):
        async def guarded():
            try:
                return await async_fun()
            except TimeoutError as e:  # asyncio.TimeoutError es TimeoutError desde 3.11
                where = tag if isinstance(tag, str) else "su URL"
                raise self.fetch_error(
                    f"Se agotó el tiempo ({self.per_request_timeout} s) al descargar {self.what} de {where}"
                ) from e

        return await super()._post_fetch_task(tag, guarded)


class _CRLFetcher(_TimeoutAsFetchError, AIOHttpCRLFetcher):
    fetch_error, what = CRLFetchError, "la CRL"

    def __init__(self, *args, cache: CrlCache, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.cache = cache
        self.from_cache: dict[int, CachedCrl] = {}  # id(crl) -> entrada, para informar de dónde salió

    async def _single_fetch(self, url):
        # Lo mismo que AIOHttpCRLFetcher._single_fetch, pero antes de descargar mira el caché.
        async def task():
            cached = self.cache.get(url)
            if cached is not None:
                self.from_cache[id(cached.crl)] = cached
                return cached.crl
            fetched = await _grab_crl(
                url, user_agent=self.user_agent, session=self.get_session(), timeout=self.per_request_timeout
            )
            self.cache.put(url, fetched)
            return fetched

        return await self._post_fetch_task(url, task)


class _OCSPFetcher(_TimeoutAsFetchError, AIOHttpOCSPFetcher):
    fetch_error, what = OCSPFetchError, "la respuesta OCSP"


class _CertificateFetcher(_TimeoutAsFetchError, AIOHttpCertificateFetcher):
    fetch_error, what = CertificateFetchError, "el emisor"

    def fetched_certs(self):
        certs = {c.sha256: c for _url, found in self._iter_results() for c in found}
        return list(certs.values())


class RevocationFetcherBackend(FetcherBackend):
    """Un juego de fetchers con una sesión HTTP propia, que se cierra al salir del `async with`."""

    def __init__(self, timeout: float = TIMEOUT, crl_timeout: float = CRL_TIMEOUT, crl_cache: CrlCache = CRL_CACHE) -> None:
        self.session = LazySession()
        self.timeout, self.crl_timeout, self.crl_cache = timeout, crl_timeout, crl_cache

    def get_fetchers(self) -> Fetchers:
        return Fetchers(
            ocsp_fetcher=_OCSPFetcher(self.session, per_request_timeout=self.timeout),
            crl_fetcher=_CRLFetcher(self.session, per_request_timeout=self.crl_timeout, cache=self.crl_cache),
            cert_fetcher=_CertificateFetcher(self.session, per_request_timeout=self.timeout),
        )

    async def close(self) -> None:
        await self.session.close()
