# Puertos

Los puertos de salida son lo que los casos de uso necesitan del exterior. Están en `application/ports.py` como `typing.Protocol`: la aplicación depende del protocolo y la raíz de composición (`bootstrap.py`) elige la implementación. Cualquier clase con los mismos métodos cumple el puerto (tipado estructural), así que un fake de test no necesita heredar de nada.

Cada puerto documenta su **contrato**: qué recibe, qué devuelve, qué errores lanza, si hace E/S y si bloquea. Una implementación nueva tiene que cumplirlo entero, y los tests del adaptador lo verifican.

> Este documento crece con la migración. Hoy tiene `CertificateCodec` (paso 2).

| Puerto | Implementaciones | Lo usa |
|--------|------------------|--------|
| [`CertificateCodec`](#certificatecodec) | `CryptographyCertificateCodec` | La fuente de certificados (`CertificateStore`) |

## `CertificateCodec`

Convierte bytes en [certificados de dominio](dominio.md#certificado-domaincertificatespy) y verifica quién emitió a quién. Es el único camino para que un certificado entre al dominio.

**Propiedades**: determinístico, sin E/S y sin estado. Bloquea sólo por el cómputo criptográfico (parsear y verificar una firma RSA de 3072 bits lleva milisegundos), así que se puede llamar desde el event loop.

### `parse(data: bytes) -> list[Certificate]`

Los certificados de `data`, en el orden en que vienen.

| Entrada | Resultado |
|---------|-----------|
| Un certificado DER | Una lista con ese certificado. |
| Uno o varios certificados PEM | Todos, en orden. |
| Un PKCS#7 (DER o PEM, como los `.p7c`/`.p7b` de AIA) | Todos los que trae. El orden es el del `SET` del PKCS#7, que no tiene orden definido. |
| El base64 de un DER, con o sin espacios y saltos de línea | Ese certificado. Es el formato del `der_b64` de la API. |
| Cualquier otra cosa | `UnprocessableCertificate("No es un certificado DER, PEM, PKCS#7 ni base64 de un DER")` |

Todos los campos del `Certificate` vienen calculados (ver [dominio](dominio.md#certificado-domaincertificatespy)), incluida la verificación de la autofirma.

### `issued_by(cert: Certificate, issuer: Certificate) -> bool`

`True` si `issuer` firmó `cert`: el emisor de `cert` coincide con el sujeto de `issuer` **y** la firma de `cert` verifica con la clave pública de `issuer`. No basta con el nombre: una CA con el mismo nombre y otra clave no es el emisor.

Es sólo criptografía, sin política de algoritmos: acepta firmas con SHA-1, que siguen usando PKIs reales (la AC Raíz de Argentina 2007 firma así a la AC ONTI). Qué algoritmos se aceptan al **validar** una firma es una regla aparte, que se aplica en la validación (`LegacyRootsPolicy`).

No lanza errores: un par de certificados incompatibles (claves de tipos que no se verifican entre sí, algoritmos desconocidos) da `False`.

Tests del adaptador: `tests/test_codec.py`.
