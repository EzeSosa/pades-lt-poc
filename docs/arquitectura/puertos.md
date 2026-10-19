# Puertos

Los puertos de salida son lo que los casos de uso necesitan del exterior. Están en `application/ports.py` como `typing.Protocol`: la aplicación depende del protocolo y la raíz de composición (`bootstrap.py`) elige la implementación. Cualquier clase con los mismos métodos cumple el puerto (tipado estructural), así que un fake de test no necesita heredar de nada.

Cada puerto documenta su **contrato**: qué recibe, qué devuelve, qué errores lanza, si hace E/S y si bloquea. Una implementación nueva tiene que cumplirlo entero, y los tests del adaptador lo verifican.

> Este documento crece con la migración. Hoy tiene `CertificateCodec` (paso 2), los de la fuente de certificados (paso 3) los de la extracción de cadenas (paso 4) y el de la validación (paso 5).

| Puerto | Implementaciones | Lo usa |
|--------|------------------|--------|
| [`CertificateCodec`](#certificatecodec) | `CryptographyCertificateCodec` | `CertificateSource`, `ExtractCertificateChains`, `InspectCertificates`, `SqliteCertificateRepository`, `PyHankoSignedPdfReader` |
| [`SignedPdfReader`](#signedpdfreader) | `PyHankoSignedPdfReader`; `FakeReader` (tests) | `ExtractCertificateChains` |
| [`IssuerFetcher`](#issuerfetcher) | `HttpIssuerFetcher`; `FakeFetcher` (tests) | `ExtractCertificateChains` |
| [`SignatureValidator`](#signaturevalidator) | `PyHankoSignatureValidator`; `FakeValidator` (tests) | `VerifySignatures` |
| [`CertificateRepository`](#certificaterepository) | `SqliteCertificateRepository`; `InMemoryCertificateRepository` (tests) | `CertificateSource` |
| [`SeedCatalog`](#seedcatalog) | `PackagedSeedCatalog`; `StaticSeedCatalog` (tests) | `CertificateSource` |
| [`Clock`](#clock) | `SystemClock`; `FixedClock` y `TestClock` (tests) | `CertificateSource`, `VerifySignatures`, `routers/store.py`, `routers/certificates.py` |

Los fakes de los tests están en `tests/fakes.py` (y `TestClock` en `tests/conftest.py`; `FakeReader` y `FakeFetcher` en `tests/test_extract_chains.py`; `FakeValidator` en `tests/test_verify_signatures.py`).

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

### `describe(cert: Certificate) -> CertificateDetails`

El [detalle legible](dominio.md#detalle-legible-certificatedetails-en-domaincertificatespy) de `cert`: versión, sujeto y emisor atributo por atributo, algoritmo de firma, clave pública y cada extensión como líneas de texto. No lanza errores para un certificado que `parse` aceptó: una extensión que no se sabe interpretar se muestra en texto genérico o en hexadecimal.

Tests del adaptador: `tests/test_codec.py`.

## `CertificateRepository`

Dónde se guarda la fuente de certificados. Trabaja con [entradas de dominio](dominio.md#modelos): recibe `NewEntry` y `EntryChanges`, devuelve `StoredCertificate`.

**Propiedades**:

- **Atómico**: cada operación se aplica entera o no se aplica nada. Si una entrada de un lote no se puede guardar (p. ej. viola una restricción), no queda guardada ninguna.
- **Concurrente**: se usa desde varios hilos a la vez (FastAPI atiende los endpoints sincrónicos en un threadpool) y tiene que serializar lo que haga falta.
- **Bloquea**: hace E/S. Desde código async, llamarlo fuera del event loop.
- **Identidad**: el repositorio asigna el `id` (entero, no se reusa después de borrar) y no admite dos entradas con la misma huella SHA-256.
- **Horas**: las recibe de quien llama (`now`) y las guarda **al segundo**.

| Operación | Contrato |
|-----------|----------|
| `all()` | Todas las entradas, en el orden en que se agregaron. |
| `get(id)` | La entrada, o `None`. |
| `insert_missing(entries, now)` | Agrega las entradas cuyo certificado no esté, habilitadas y con `created_at = updated_at = now`. Devuelve `(agregadas, ya_estaban)`, cada lista en el orden de `entries`. Las que ya estaban no se tocan. |
| `apply_initial_load(entries, now)` | Si la carga inicial nunca se aplicó: `insert_missing(entries)` más la marca de aplicada, en la misma transacción, y devuelve `True`. Si ya se aplicó, no hace nada y devuelve `False`, aunque falten sus certificados (F-04). Si falla en el medio, no queda ni la carga ni la marca. |
| `update(id, changes, now)` | Aplica los campos de `changes` que no son `None` y fija `updated_at = now`. Sin cambios, no toca nada. Devuelve la entrada como quedó, o `None` si no existe. |
| `delete(id)` | Borra la entrada. `False` si no existía. |

El repositorio **no** aplica las reglas de negocio (eso es el dominio), salvo como segunda línea de defensa las que se pueden expresar como restricción: la implementación SQLite rechaza un intermedio confiable con un `CHECK`.

Tests de contrato (contra SQLite y contra el fake): `tests/test_certificate_repository.py`.

## `SeedCatalog`

La carga inicial de la fuente. `seeds()` devuelve una lista fija de `SeedCertificate` (el DER de un certificado y su nota), en el orden en que se cargan. Puede leer archivos; no falla en una instalación correcta.

## `Clock`

`now()` devuelve la hora actual con zona horaria (UTC). Existe para poder fijar la hora en los tests: la vigencia de un certificado (`validity_status`) y las horas de la fuente (`created_at`, `updated_at`) salen de acá.

La validación toma de acá la hora actual (`validated_at` y el `moment` sin conexión); con conexión pyHanko valida a su propia hora actual, porque no admite descargar con una hora fija. La firma todavía usa la hora del sistema (paso 6).

## `SignedPdfReader`

Lee las firmas de un PDF y verifica su **integridad criptográfica**, sin confianza ni revocación. Devuelve un [`SignedDocument`](dominio.md#firmas-de-un-pdf-domainsignaturespy).

**Propiedades**: sin E/S de red. Bloquea por el cómputo (hashes del documento, verificación de firmas), proporcional al tamaño del PDF.

### `read(pdf: bytes) -> SignedDocument`

| Situación | Resultado |
|-----------|-----------|
| El PDF tiene firmas | Las firmas en el orden del documento, con su tipo, su CMS (firmante, demás certificados, integridad) y su sello de tiempo (el primer token no firmado), y los certificados del DSS. |
| El PDF no tiene firmas | `UnprocessablePdf("El PDF no tiene firmas")` |
| Una firma no permite identificar al firmante | `CmsSignature.signer = None`, sin otros certificados, y la integridad con `error`. No es una excepción: las demás firmas se leen igual. |

Qué cubre la integridad de cada firma:

| Firma | `intact` significa |
|-------|--------------------|
| `/Sig` | El `message-digest` coincide con el hash del ByteRange. |
| `/DocTimeStamp` | El `messageImprint` del TSTInfo coincide con el hash del ByteRange (y los atributos firmados cubren el TSTInfo). |
| Sello de una firma | El `messageImprint` coincide con el hash del **valor de la firma**. |

`valid` es que la firma verifique con la clave del firmante, en los tres casos.

## `IssuerFetcher`

Descarga los certificados publicados en una URL AIA caIssuers.

**Propiedades**: E/S de red, bloquea, con un timeout por descarga. **No cachea**: el caché por pedido es del caso de uso (C-03), así una URL que falla en un pedido se vuelve a intentar en el siguiente.

### `fetch(url: str) -> list[Certificate]`

| Situación | Resultado |
|-----------|-----------|
| La URL publica uno o varios certificados en DER, PEM o PKCS#7 | Esos certificados. |
| La descarga falla (conexión, timeout, status HTTP de error) | `IssuerFetchError` con el motivo. |
| Lo descargado no es un certificado | `IssuerFetchError("no es un certificado DER, PEM ni PKCS#7")` |

`IssuerFetchError` está en `application/ports.py`: es una señal del adaptador al caso de uso, no un error de negocio. El caso de uso la convierte en un `aia_errors` con la URL (`<url>: <motivo>`).

## `SignatureValidator`

Valida firmas PAdES: integridad, camino hasta un ancla, revocación, sello de tiempo y modificaciones posteriores. Es el puerto que encapsula a pyHanko.

**Propiedades**: async (con conexión descarga CRL, OCSP y emisores). Cada `open` es una sesión independiente; con conexión, las descargas se comparten entre las firmas de la sesión y las conexiones se cierran al salir del `async with`. La revocación es siempre obligatoria (V-03): una firma sin revocación disponible no es confiable.

### `open(pdf, policy) -> async context manager de ValidationSession`

Abre el PDF para validar con la [`ValidationPolicy`](dominio.md#política). Lanza `UnprocessablePdf("El PDF no tiene firmas")` si no tiene ninguna.

### `ValidationSession`

| Miembro | Contrato |
|---------|----------|
| `signatures` | Las firmas (`SignatureRef`: `index`, `field_name`, `kind`), en el orden del documento. |
| `dss` | `DssSummary` (certificados, respuestas OCSP y CRLs del DSS), o `None` sin DSS. |
| `embedded_sha256` | Huellas de todos los certificados que trae el PDF: DSS, CMS de cada firma y de sus sellos. |
| `claimed_signing_time(ref)` | La hora que declara la firma (atributo `signingTime` o, si no está, `/M`), o `None`. |
| `await evaluate(ref, at)` | Valida una firma (no un DocTimeStamp) a la hora `at` y devuelve una `SignatureEvaluation`. Si `at.in_the_past`, acepta revocación posterior a esa hora. Con conexión, valida a la hora actual. Si la firma o su sello verifican pero no son confiables, prueba cada camino candidato (hasta 5) y los informa en `attempts`. |
| `fetched()` | Lo descargado hasta el momento (`FetchedRevocation`), o `None` si la sesión no es con conexión. |

`SignatureRef` está en `application/ports.py`: es un identificador de la sesión, no un concepto de negocio.
