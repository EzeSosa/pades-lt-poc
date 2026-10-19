"""Los puertos de salida: lo que los casos de uso necesitan del exterior, como `typing.Protocol`.

Cada puerto documenta su contrato (qué recibe, qué devuelve, qué errores lanza y si bloquea).
Las implementaciones están en `adapters/outbound/`. Ver docs/arquitectura/puertos.md.
"""

from __future__ import annotations

from typing import Protocol

from ..domain.certificates import Certificate


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
