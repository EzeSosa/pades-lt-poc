# Dominio

El paquete `pades_lt_poc.domain` contiene los modelos, las reglas y los errores de las operaciones de negocio. Es **Python puro**: no importa ninguna biblioteca de infraestructura ni otra capa del paquete (lo verifica el contrato "El dominio es Python puro" de import-linter). Por eso se prueba con datos armados a mano, sin PKI, sin red y sin PDFs.

> Este documento crece con la migración. Hoy cubre el certificado y los errores (paso 2). La fuente, la validación y la firma se agregan en sus pasos.

## Lenguaje ubicuo

Cómo se llama cada concepto en la documentación (castellano) y en el código (inglés). Las definiciones técnicas completas están en el [glosario de pades.md](../pades.md#12-glosario).

| Término | En el código | Qué es |
|---------|--------------|--------|
| Certificado | `Certificate` | Un certificado X.509, identificado por su DER. |
| Huella | `sha256`, `sha1` | El hash del DER, en hexadecimal en minúsculas. La SHA-256 identifica al certificado en la fuente. |
| Vigencia | `not_before`, `not_after`, `ValidityStatus` | El intervalo en el que el certificado es válido, y dónde cae un momento respecto de él. |
| CA | `is_ca` | Un certificado con `basicConstraints` `cA=TRUE`: puede emitir otros. |
| Autofirmado | `self_signed` | Un certificado cuya propia clave verifica su firma. |
| Raíz | `CaKind.ROOT` | Una CA autofirmada. |
| Intermedio | `CaKind.INTERMEDIATE` | Una CA emitida por otra. |
| Hoja (*end entity*) | `ca_kind is None` | Un certificado que no es CA: el de un firmante, una TSA o un respondedor OCSP. |
| Emitido por | `CertificateCodec.issued_by(cert, issuer)` | `issuer` firmó a `cert`: el nombre coincide y la firma verifica. |

## Certificado (`domain/certificates.py`)

`Certificate` es un objeto de valor inmutable. La decisión de construirlo sobre el DER está en [ADR-0002](../adr/0002-certificado-de-dominio-sobre-der.md).

| Campo | Tipo | Significado |
|-------|------|-------------|
| `der` | `bytes` | El certificado. **Única** componente de la identidad: igualdad y hash miran sólo este campo. |
| `sha256` | `str` | Huella SHA-256 del DER, hex en minúsculas. |
| `sha1` | `str` | Huella SHA-1 del DER, hex en minúsculas. Informativa. |
| `subject` | `str` | Sujeto en RFC 4514 (`CN=PoC Root CA,O=PoC PAdES,C=AR`). |
| `issuer` | `str` | Emisor en RFC 4514. |
| `serial_number` | `int` | Número de serie. |
| `not_before`, `not_after` | `datetime` (UTC) | Vigencia. |
| `is_ca` | `bool` | `basicConstraints` `cA`. Sin la extensión, `False`. |
| `self_signed` | `bool` | Su propia clave verifica su firma. Un certificado con sujeto igual a emisor pero firmado por otra clave **no** es autofirmado. |

Comportamiento:

| Método | Regla |
|--------|-------|
| `validity_status(now)` | `NOT_YET_VALID` si `now < not_before`; `EXPIRED` si `now > not_after`; si no, `VALID`. Los dos extremos son vigentes. |
| `days_left(now)` | Días completos hasta `not_after` (`timedelta.days`): negativo si ya venció. |
| `ca_kind` | `ROOT` si es CA y autofirmado, `INTERMEDIATE` si es CA y no autofirmado, `None` si no es CA. Una hoja autofirmada no es raíz. |

Los valores de `ValidityStatus` (`valid`, `expired`, `not_yet_valid`) y de `CaKind` (`root`, `intermediate`) son los mismos que expone la API.

Tests: `tests/test_domain_certificates.py`.

## Errores (`domain/errors.py`)

Los errores de negocio no saben de HTTP. El adaptador HTTP decide el status (hoy, el handler de `app.py` y los routers).

| Error | Cuándo | HTTP |
|-------|--------|------|
| `UnprocessableInput` | La entrada no se puede procesar. Base de los dos siguientes; también se lanza directo para una combinación de opciones inválida (p. ej. `revocation=online` con `validation_time=claimed_signing_time`) o un cambio inválido en la fuente (marcar como confiable un intermedio). | 422 |
| `UnprocessablePdf` | No es un PDF, está dañado o cifrado, no tiene firmas, o pyHanko no pudo firmarlo. | 422 |
| `UnprocessableCertificate` | No es un certificado en un formato conocido, o no es del tipo esperado (la fuente sólo acepta CAs). | 422 |
| `CertificateNotFound` | No hay un certificado con ese id en la fuente. | 404 |
| `DuplicateCertificate` | Todos los certificados recibidos ya estaban en la fuente. `args[0]` lleva sus ids. | 409 |

El mensaje de cada error es el que ve el usuario (`detail` en la respuesta), así que está en castellano y dice qué hacer cuando se puede.
