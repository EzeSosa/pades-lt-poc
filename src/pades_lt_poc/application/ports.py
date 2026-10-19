"""Los puertos de salida: lo que los casos de uso necesitan del exterior, como `typing.Protocol`.

Cada puerto documenta su contrato (qué recibe, qué devuelve, qué errores lanza y si bloquea).
Las implementaciones están en `adapters/outbound/`. Ver docs/arquitectura/puertos.md.
"""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from ..domain.certificates import Certificate, CertificateDetails
from ..domain.signatures import SignatureKind, SignedDocument
from ..domain.source import EntryChanges, NewEntry, SeedCertificate, StoredCertificate
from ..domain.verification import DssSummary, FetchedRevocation, SignatureEvaluation, ValidatedAt, ValidationPolicy


class CertificateCodec(Protocol):
    """Convierte bytes en certificados de dominio y verifica quién emitió a quién.

    Es determinístico, no hace E/S y no bloquea más que el cómputo criptográfico.
    """

    def parse(self, data: bytes) -> list[Certificate]:
        """Los certificados de `data`, en el orden en que vienen.

        Acepta un certificado DER o PEM (uno o varios), un PKCS#7 (DER o PEM, como los `.p7c`
        de AIA) o el base64 de un DER, con o sin espacios y saltos de línea.

        Lanza `UnprocessableCertificate` si no es ninguno de esos formatos.
        """
        ...

    def issued_by(self, cert: Certificate, issuer: Certificate) -> bool:
        """True si `issuer` firmó `cert`: el nombre del emisor coincide y la firma verifica con su clave.

        Sólo criptografía, sin política de algoritmos: acepta firmas SHA-1, que siguen usando
        PKIs reales. Qué algoritmos se aceptan al validar es una regla aparte.
        """
        ...

    def describe(self, cert: Certificate) -> CertificateDetails:
        """El detalle legible de `cert`: versión, nombres atributo por atributo, algoritmo de firma,
        clave pública y cada extensión como líneas de texto. Ver docs/arquitectura/puertos.md."""
        ...


class SignedPdfReader(Protocol):
    """Lee las firmas de un PDF y verifica su integridad criptográfica (sin confianza ni revocación).

    Bloquea sólo por el cómputo (hashes del documento y verificación de firmas).
    """

    def read(self, pdf: bytes) -> SignedDocument:
        """Las firmas de `pdf`, con sus certificados y su integridad, y los certificados del DSS.

        Lanza `UnprocessablePdf("El PDF no tiene firmas")` si no tiene ninguna.
        """
        ...


class IssuerFetchError(Exception):
    """No se pudo descargar o interpretar lo publicado en una URL de emisor. El mensaje dice por qué."""


class IssuerFetcher(Protocol):
    """Descarga los certificados publicados en una URL AIA caIssuers.

    Hace E/S de red y bloquea (con un timeout por descarga). No cachea: el caché por pedido es
    del caso de uso.
    """

    def fetch(self, url: str) -> list[Certificate]:
        """Los certificados publicados en `url` (DER, PEM o PKCS#7).

        Lanza `IssuerFetchError` si la descarga falla o lo descargado no es un certificado.
        """
        ...


class Clock(Protocol):
    """La hora actual. Un puerto para poder fijarla en los tests."""

    def now(self) -> datetime:
        """La hora actual, con zona horaria (UTC)."""
        ...


class SeedCatalog(Protocol):
    """La carga inicial de la fuente de certificados."""

    def seeds(self) -> list[SeedCertificate]:
        """Los certificados de la carga inicial (un DER cada uno), en el orden en que se cargan.

        Siempre los mismos: es un catálogo fijo. Puede leer archivos (bloquea poco).
        """
        ...


class CertificateRepository(Protocol):
    """Dónde se guarda la fuente de certificados.

    Cada operación es atómica: o se aplica entera o no se aplica nada. La implementación se
    usa desde varios hilos a la vez (FastAPI atiende endpoints sincrónicos en un threadpool)
    y tiene que serializar lo que haga falta. Todas las operaciones bloquean (E/S).

    Una entrada se identifica por su `id`, que asigna el repositorio, y es única por la huella
    SHA-256 de su certificado.
    """

    def all(self) -> list[StoredCertificate]:
        """Todas las entradas, en el orden en que se agregaron."""
        ...

    def get(self, cert_id: int) -> StoredCertificate | None:
        ...

    def insert_missing(
        self, entries: Sequence[NewEntry], now: datetime
    ) -> tuple[list[StoredCertificate], list[StoredCertificate]]:
        """Agrega las entradas cuyo certificado no esté, con `created_at` y `updated_at` = `now`.

        Devuelve (agregadas, las que ya estaban), cada lista en el orden de `entries`. Las que
        ya estaban no se tocan.
        """
        ...

    def apply_initial_load(self, entries: Sequence[NewEntry], now: datetime) -> bool:
        """Aplica la carga inicial si nunca se aplicó: `insert_missing(entries)` y la marca de
        aplicada, en la misma transacción. Si falla en el medio, no queda ni lo uno ni lo otro y
        se puede volver a intentar. Devuelve si la aplicó.

        Una vez aplicada no se vuelve a aplicar aunque se borren sus certificados (F-04).
        """
        ...

    def update(self, cert_id: int, changes: EntryChanges, now: datetime) -> StoredCertificate | None:
        """Aplica `changes` (sólo los campos que no son None) y fija `updated_at` = `now`.

        Sin cambios, no toca nada. Devuelve la entrada como quedó, o None si no existe.
        """
        ...

    def delete(self, cert_id: int) -> bool:
        """Borra la entrada. Devuelve False si no existía."""
        ...


@dataclass(frozen=True)
class SignatureRef:
    """Una firma de la sesión de validación: su posición, su campo y su tipo."""

    index: int
    field_name: str
    kind: SignatureKind


class ValidationSession(Protocol):
    """Un PDF abierto para validar, con una política fija. La da `SignatureValidator.open`.

    Con conexión, las descargas (CRL, OCSP, emisores) se comparten entre las firmas del PDF: lo
    descargado para una sirve para las demás.
    """

    signatures: tuple[SignatureRef, ...]
    """En el orden del documento."""
    dss: DssSummary | None
    """Cuántos certificados, respuestas OCSP y CRLs tiene el DSS; None si no tiene DSS."""
    embedded_sha256: frozenset[str]
    """Huellas de todos los certificados que trae el PDF: DSS, CMS de cada firma y sus sellos."""

    def claimed_signing_time(self, ref: SignatureRef) -> datetime | None:
        """La hora que declara la firma (atributo signingTime del CMS o, si no está, /M); None si no declara."""
        ...

    async def evaluate(self, ref: SignatureRef, at: ValidatedAt) -> SignatureEvaluation:
        """Valida una firma (no un DocTimeStamp) a la hora `at`, con revocación obligatoria (V-03).

        Si `at.in_the_past`, acepta revocación posterior a esa hora (se obtuvo después de firmar).
        Con conexión, valida a la hora actual (el validador no descarga para validar en el pasado).
        Si la firma o su sello verifican pero no son confiables, prueba cada camino candidato y lo
        informa en `attempts`.
        """
        ...

    def fetched(self) -> FetchedRevocation | None:
        """Lo descargado hasta ahora; None si la sesión no es con conexión."""
        ...


class SignatureValidator(Protocol):
    """Valida firmas PAdES: integridad, camino hasta un ancla, revocación, sello de tiempo y modificaciones.

    Async: con conexión descarga CRL, OCSP y emisores.
    """

    def open(self, pdf: bytes, policy: ValidationPolicy) -> AbstractAsyncContextManager[ValidationSession]:
        """Abre `pdf` para validar con `policy`. Al salir del `async with` libera las conexiones.

        Lanza `UnprocessablePdf("El PDF no tiene firmas")` si no tiene ninguna.
        """
        ...
