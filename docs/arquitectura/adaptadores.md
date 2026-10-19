# Adaptadores

Los adaptadores conectan la aplicación con el exterior. Los **de salida** (`adapters/outbound/`) implementan los [puertos](puertos.md) con una biblioteca concreta. Los **de entrada** (por ahora, los `routers/` de FastAPI) traducen un pedido externo a un caso de uso.

Un adaptador de salida no conoce HTTP, ni la raíz de composición, ni el código que todavía no se migró (`services/`, `pki.py`). Lo verifica el contrato "Los adaptadores de salida no conocen HTTP, la composición ni el código sin migrar" de import-linter.

> Este documento crece con la migración. Hoy tiene el codec de certificados (paso 2) y los de la fuente de certificados (paso 3).

## `adapters/outbound/crypto/codec.py`: certificados con `cryptography`

Implementa [`CertificateCodec`](puertos.md#certificatecodec) con la clase `CryptographyCertificateCodec`.

### Cómo parsea

`parse` prueba los formatos en orden y se queda con el primero que funciona: DER, PEM (uno o varios), PKCS#7 DER y PKCS#7 PEM (`parse_certs`). Si ninguno funciona, quita los espacios y saltos de línea, decodifica como base64 estricto y vuelve a probar (`load_certs`). Si tampoco funciona, lanza `UnprocessableCertificate`.

Cada certificado se convierte al de dominio con `to_domain`: huellas sobre el DER, sujeto y emisor en RFC 4514 (`Name.rfc4514_string()`), vigencia en UTC (`not_valid_*_utc`), `is_ca` desde `basicConstraints` y `self_signed` verificando la firma con su propia clave.

### SHA-1: verificación a mano

`cryptography` se niega a verificar firmas SHA-1: `verify_directly_issued_by` lanza `ValueError("Unsupported signature algorithm")`. Pero la AC Raíz de Argentina 2007 firma con SHA-1 a la AC ONTI, emisora de los certificados de CiDi, y sin esa verificación no se puede armar la cadena ni saber que la raíz es autofirmada.

`issued_by` captura ese error puntual y verifica a mano (`_verify_legacy`): compara el emisor de `cert` con el sujeto de `issuer` y verifica la firma sobre el `tbsCertificate` con la clave del emisor, con PKCS#1 v1.5 (RSA) o ECDSA y el hash que declara el certificado. Cualquier otro error (clave de otro tipo, firma inválida) da `False`.

Esto no relaja ninguna política de validación: sólo responde quién firmó a quién. La validación de firmas sigue rechazando SHA-1 salvo para lo que firman las raíces confiables que nacieron con SHA-1 (ver [pades.md](../pades.md#caso-real-pki-de-firma-digital-de-argentina)).

### Funciones sobre `cryptography.x509.Certificate`

Mientras se migran la extracción de cadenas y la inspección (paso 4), el módulo expone también funciones sobre objetos de `cryptography`, que usan `services/certificates.py` y `services/inspection.py`:

| Función | Qué hace | La usa |
|---------|----------|--------|
| `parse_certs(data)` | DER, PEM o PKCS#7; `ValueError` si no es ninguno. Sin base64: es lo que se publica en AIA. | Descarga AIA (`AiaFetcher`) |
| `load_certs(data)` | `parse_certs` más base64; `UnprocessableCertificate`. | Inspección |
| `issued_by(cert, issuer)` | La verificación de emisor, con el caso SHA-1. | Armado de cadenas, inspección |
| `is_ca(cert)` | `basicConstraints` `cA`. | Inspección |
| `to_domain(cert)` | `cryptography` → `Certificate`. | El propio codec |

Cuando esos servicios pasen a casos de uso, estas funciones quedan como detalle interno del adaptador.

Tests: `tests/test_codec.py`.

## `adapters/outbound/sqlite/certificate_repository.py`: la fuente en SQLite

Implementa [`CertificateRepository`](puertos.md#certificaterepository) con `SqliteCertificateRepository(path, codec)`. El esquema (tablas `certificates` y `meta`, columnas y restricciones) y cómo consultarlo a mano están en [pades.md](../pades.md#la-base-sqlite).

- **Una conexión compartida** (`check_same_thread=False`), serializada con un `RLock`: FastAPI atiende los endpoints sincrónicos en varios hilos, y SQLite no admite escrituras concurrentes en una misma conexión.
- **Transacciones**: cada escritura va dentro de `with self._db` (commit al salir, rollback si hay una excepción). `apply_initial_load` inserta la carga y escribe la marca `seeded_at` en la misma transacción.
- **Columnas redundantes**: `subject`, `issuer`, `not_before` y `not_after` se guardan para poder consultar la base con `sqlite3` sin parsear el DER. Al leer, el `Certificate` se reconstruye desde el DER con el `CertificateCodec`, así que las columnas no pueden desincronizarse del modelo.
- **Restricciones**: `sha256` único, `kind` y `origin` dentro de sus valores, y `CHECK (kind = 'root' OR trusted = 0)`: segunda línea de defensa de F-02.
- **Horas**: `created_at`, `updated_at` y `seeded_at` se guardan en ISO 8601 al segundo (`2026-10-18T12:00:00+00:00`).

## `adapters/outbound/seed_catalog.py`: la carga inicial empaquetada

Implementa [`SeedCatalog`](puertos.md#seedcatalog) con `PackagedSeedCatalog`: lee los archivos DER de `src/pades_lt_poc/seed/` (`SEED_DIR`) según el diccionario `SEEDS` (archivo → nota). Hoy son la AC Raíz de Argentina 2007 y 2016 y la AC ONTI.

Para cambiar la carga inicial: agregar el `.der` a `seed/` y su entrada a `SEEDS`. Sólo afecta a las bases nuevas (F-04); en una existente, **Restaurar carga inicial** (`POST /store/certificates/seed`) agrega lo que falte.

## `adapters/outbound/clock.py`: el reloj del sistema

Implementa [`Clock`](puertos.md#clock) con `SystemClock`: `datetime.now(UTC)`.
