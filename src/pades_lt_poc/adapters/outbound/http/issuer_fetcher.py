"""`IssuerFetcher` con `requests`: descarga lo publicado en una URL AIA caIssuers."""

from __future__ import annotations

from collections.abc import Callable

import requests

from ....application.ports import IssuerFetchError
from ....domain.certificates import Certificate
from ..crypto.codec import parse_certs, to_domain

TIMEOUT = 5  # segundos por descarga


def http_get(url: str) -> bytes:
    r = requests.get(url, timeout=TIMEOUT)
    r.raise_for_status()
    return r.content


class HttpIssuerFetcher:
    """Implementa `application.ports.IssuerFetcher`.

    `get` hace la descarga (por defecto, `http_get`); los tests lo reemplazan para no salir a la red.
    """

    def __init__(self, get: Callable[[str], bytes] = http_get) -> None:
        self.get = get

    def fetch(self, url: str) -> list[Certificate]:
        try:
            # Los `.crt`/`.p7c` publicados en AIA pueden venir en DER, PEM o PKCS#7.
            return [to_domain(c) for c in parse_certs(self.get(url))]
        except (requests.RequestException, ValueError) as e:
            raise IssuerFetchError(str(e)) from e
