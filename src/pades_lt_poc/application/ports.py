"""Los puertos de salida: lo que los casos de uso necesitan del exterior, como `typing.Protocol`.

Cada puerto documenta su contrato (qué recibe, qué devuelve, qué errores lanza y si bloquea).
Las implementaciones están en `adapters/outbound/`. Ver docs/arquitectura/puertos.md.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from ..domain.certificates import Certificate
from ..domain.source import EntryChanges, NewEntry, SeedCertificate, StoredCertificate


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
