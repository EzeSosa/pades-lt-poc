# Adaptadores

Los adaptadores conectan la aplicación con el exterior. Los **de salida** (`adapters/outbound/`) implementan los [puertos](puertos.md) con una biblioteca concreta. Los **de entrada** (por ahora, los `routers/` de FastAPI) traducen un pedido externo a un caso de uso.

Un adaptador de salida no conoce HTTP, ni la raíz de composición, ni el código que todavía no se migró (`services/`, `pki.py`). Lo verifica el contrato "Los adaptadores de salida no conocen HTTP, la composición ni el código sin migrar" de import-linter.

> Este documento crece con la migración. Hoy tiene el codec de certificados (paso 2), los de la fuente de certificados (paso 3) los de la extracción de cadenas (paso 4) y el de la validación (paso 5).

## `adapters/outbound/crypto/codec.py`: certificados con `cryptography`

Implementa [`CertificateCodec`](puertos.md#certificatecodec) con la clase `CryptographyCertificateCodec`.

### Cómo parsea

`parse` prueba los formatos en orden y se queda con el primero que funciona: DER, PEM (uno o varios), PKCS#7 DER y PKCS#7 PEM (`parse_certs`). Si ninguno funciona, quita los espacios y saltos de línea, decodifica como base64 estricto y vuelve a probar (`load_certs`). Si tampoco funciona, lanza `UnprocessableCertificate`.

Cada certificado se convierte al de dominio con `to_domain`: huellas sobre el DER, sujeto y emisor en RFC 4514 (`Name.rfc4514_string()`), vigencia en UTC (`not_valid_*_utc`), `is_ca` desde `basicConstraints`, `self_signed` verificando la firma con su propia clave y `ca_issuer_urls` con las URIs caIssuers de la extensión AIA.

### SHA-1: verificación a mano

`cryptography` se niega a verificar firmas SHA-1: `verify_directly_issued_by` lanza `ValueError("Unsupported signature algorithm")`. Pero la AC Raíz de Argentina 2007 firma con SHA-1 a la AC ONTI, emisora de los certificados de CiDi, y sin esa verificación no se puede armar la cadena ni saber que la raíz es autofirmada.

`issued_by` captura ese error puntual y verifica a mano (`_verify_legacy`): compara el emisor de `cert` con el sujeto de `issuer` y verifica la firma sobre el `tbsCertificate` con la clave del emisor, con PKCS#1 v1.5 (RSA) o ECDSA y el hash que declara el certificado. Cualquier otro error (clave de otro tipo, firma inválida) da `False`.

Esto no relaja ninguna política de validación: sólo responde quién firmó a quién. La validación de firmas sigue rechazando SHA-1 salvo para lo que firman las raíces confiables que nacieron con SHA-1 (ver [pades.md](../pades.md#caso-real-pki-de-firma-digital-de-argentina)).

### Funciones sobre `cryptography.x509.Certificate`

Además de la clase del puerto, el módulo expone funciones sobre objetos de `cryptography` que usan otros adaptadores:

| Función | Qué hace | La usa |
|---------|----------|--------|
| `parse_certs(data)` | DER, PEM o PKCS#7; `ValueError` si no es ninguno. Sin base64: es lo que se publica en AIA. | `HttpIssuerFetcher` |
| `to_domain(cert)` | `cryptography` → `Certificate`. | El propio codec, `HttpIssuerFetcher` |
| `load_certs(data)`, `issued_by`, `is_ca`, `ca_issuer_urls` | Las piezas de `parse` y `to_domain`. | El propio codec |

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

## `adapters/outbound/crypto/details.py`: el detalle legible

Implementa `CertificateCodec.describe` (el codec lo delega acá). Los nombres son los de RFC 5280 / `cryptography`, sin traducir.

| Extensión | Líneas de `values` |
|-----------|--------------------|
| BasicConstraints | `CA=sí` o `CA=no`, con `, pathLen=N` si tiene límite |
| KeyUsage | un uso por línea (`digital_signature`, `key_cert_sign`, ...); `encipher_only`/`decipher_only` sólo con `key_agreement` |
| ExtendedKeyUsage | un propósito por línea (`timeStamping`, `OCSPSigning`, ...) |
| AIA / SIA | `<método>: <ubicación>` (`OCSP: http://...`, `caIssuers: http://...`) |
| CRL Distribution Points / Freshest CRL | una URI por línea |
| CertificatePolicies | `Política <oid>`, y una línea por calificador: `CPS: <uri>` o `Aviso: <texto>` (sin el NUL final que agregan algunas CAs) |
| SAN / IAN | un nombre por línea |
| SKI / AKI | el identificador en hex con `:` |
| OCSP no-check | `presente: el respondedor OCSP no se valida contra revocación` |
| Desconocida | el valor decodificado si es un ASN.1 simple (texto o entero), en hex con `:` si es un octet string, si no el DER en hex |

Los OIDs que `cryptography` no nombra pero aparecen en las CAs de la PKI argentina (Microsoft AD CS) se nombran a mano (`EXTRA_OID_NAMES`: `msCertificateTemplateName`, `msCAVersion`, `msPreviousCACertHash`, ...). Para decodificar valores ASN.1 desconocidos usa `asn1crypto`.

Tests: `tests/test_inspection.py`, goldens `inspect_*`.

## `adapters/outbound/pyhanko/signed_pdf_reader.py`: las firmas de un PDF con pyHanko

Implementa [`SignedPdfReader`](puertos.md#signedpdfreader) con `PyHankoSignedPdfReader(codec)`.

- **Apertura**: `open_signed_pdf` abre el PDF con `PdfFileReader(strict=False)` (muchos PDFs reales tienen errores menores) y rechaza los que no tienen firmas. La usa también la verificación, que todavía no se migró.
- **Integridad** (`check_integrity`): con `validate_sig_integrity` de pyHanko. Para un TSTInfo (DocTimeStamp o sello de una firma), los atributos firmados cubren el TSTInfo y aparte se compara su `messageImprint` con lo que el sello dice cubrir (`covered_digest`): el ByteRange (`sig.compute_digest`) o el valor de la firma (`message_imprint_checker`). Un `SignatureValidationError` (p. ej. el firmante no está en el CMS) se devuelve como `Integrity(False, False, mensaje)`.
- **Certificados**: `extract_certs_for_validation` separa al firmante de los demás. Cada certificado de `asn1crypto` se convierte con el `CertificateCodec`, una vez por lectura (el mismo suele estar en el CMS, en el sello y en el DSS).
- **Sello de una firma**: el primer token RFC 3161 de los atributos no firmados (`extract_tst_data_iter`), con su `genTime`.

Tests: `tests/test_certificates.py` (por HTTP, con PDFs firmados en el test), `test_certificates.py::test_timestamp_not_matching_signature` (integridad de un sello).

## `adapters/outbound/http/issuer_fetcher.py`: AIA con `requests`

Implementa [`IssuerFetcher`](puertos.md#issuerfetcher) con `HttpIssuerFetcher(get=http_get)`. `http_get` hace un `GET` con 5 s de timeout y falla con los status de error; lo descargado se parsea con `parse_certs` (DER, PEM o PKCS#7). Los errores de `requests` y de parseo se convierten en `IssuerFetchError` con su mensaje.

`get` es reemplazable: la app de los tests usa un `HttpIssuerFetcher` cuyo `get` falla siempre ("sin red en los tests") salvo que el test ponga una ruta (fixture `aia`). Así se prueba el adaptador real sin salir a la red.

Tests: `tests/test_issuer_fetcher.py` (contra la app escuchando en un puerto real).

## `adapters/outbound/pyhanko/`: la validación con pyHanko

Implementa [`SignatureValidator`](puertos.md#signaturevalidator). Ningún tipo de pyHanko ni de pyhanko-certvalidator sale de este paquete: todo se traduce a modelos del [dominio](dominio.md#validación-domainverificationpy).

| Módulo | Qué tiene |
|--------|-----------|
| `validator.py` | `PyHankoSignatureValidator` y su sesión: abre el PDF, arma el `ValidationContext` de cada firma (`_ContextFactory`), llama a `async_validate_pdf_signature` y traduce el resultado. |
| `policies.py` | `LegacyRootsPolicy` (SHA-1 sólo para las claves de `legacy_sha1_roots`, V-02) y `UnallocatedFreesPolicy` (entradas libres de iText); `DIFF_POLICIES` por `DiffPolicyMode`. |
| `trust_paths.py` | Los caminos candidatos de un certificado no confiable, revalidados uno por uno, con el `TrustReason` de cada error. |
| `fetching.py` | Los fetchers de CRL, OCSP y AIA para el modo con conexión, con timeouts que no tiran abajo la verificación y el caché de CRLs (`CrlCache`). |
| `crl_index.py` | Un índice de seriales por CRL que reemplaza la búsqueda de pyhanko-certvalidator (CRLs grandes). |
| `convert.py` | asn1crypto ↔ `Certificate`. |
| `signed_pdf_reader.py` | El lector de PDFs firmados (paso 4); `open_signed_pdf` lo usa también el validador. |

### El `ValidationContext` de cada firma

| Parámetro | Valor | Por qué |
|-----------|-------|---------|
| `trust_roots` | `policy.trust_anchors` | V-01 |
| `other_certs` | `policy.intermediates` | Los intermedios de la fuente; el DSS suma los suyos. |
| `revocation_mode` | `hard-fail` | V-03 |
| `algorithm_usage_policy` | `LegacyRootsPolicy(policy.legacy_sha1_roots)` | V-02 |
| `retroactive_revinfo` | `at.in_the_past` | Validando en el pasado, la revocación embebida es posterior a la hora de validación (V-08). |
| `moment` | `at.time` | Sólo sin conexión: pyHanko no descarga con una hora fija. |
| `allow_fetching`, `fetchers`, `time_tolerance` | `True`, los de la sesión, 2 minutos | Sólo con conexión. La tolerancia cubre el desfasaje de reloj con el servidor que responde (con 1 s, una respuesta "de recién" parecía del futuro). |

Con DSS, el contexto se arma desde el DSS (`as_validation_context`), que agrega sus certificados, CRLs y respuestas OCSP. Sin DSS se pasan listas vacías de revocación: pyHanko lanza `ValueError` si en hard-fail sin descargas no recibe ninguna.

Cada firma usa un contexto nuevo; firma y sello usan el mismo.

### Caminos probados (`trust_paths.attempts`)

pyHanko resume una falla de confianza en una indicación AdES y el mensaje real sólo va al log. Para poder decir por qué, se vuelve a validar cada camino candidato (`path_builder.async_build_paths_lazy`, hasta 5) con el mismo contexto, registrando antes los certificados que trae la firma, y se guarda el error de cada uno. Sólo se hace cuando verifica y no es confiable, porque es caro.

| Error de pyhanko-certvalidator | `TrustReason` |
|--------------------------------|---------------|
| `RevokedError` | `revoked` |
| `InsufficientRevinfoError` con "not recent enough" en el mensaje | `stale_revocation` |
| Otro `InsufficientRevinfoError` | `missing_revocation` |
| `ExpiredError` | `expired` |
| `NotYetValidError` | `not_yet_valid` |
| `DisallowedAlgorithmError` | `algorithm` |
| Cualquier otro `ValidationError` | `other` |

### Intermedios del camino

`path_intermediates` son los certificados del `validation_path` de pyHanko sin el ancla ni la hoja. pyHanko devuelve el camino aunque la validación falle; decidir si cuenta (sólo si es confiable, V-06) es del dominio.

### Modo con conexión (`fetching.py`)

`RevocationFetcherBackend` crea un juego de fetchers aiohttp por sesión, con dos arreglos sobre los de pyhanko-certvalidator:

- Un timeout no es un error de descarga para pyHanko (sólo `ClientError`): se propagaba y la verificación entera fallaba. Se convierte en `CRLFetchError`, `OCSPFetchError` o `CertificateFetchError`, que pyHanko trata como "no se pudo descargar".
- `fetched_certs()` de `AIOHttpCertificateFetcher` lanzaba `TypeError` en cuanto descargaba algo: se aplanan los resultados por URL.

Timeouts: 10 s por OCSP o AIA y 60 s por CRL (la de la AC ONTI pesa ~9 MB). Las CRL se guardan en un `CrlCache` (uno por app, lo crea `bootstrap.build`) hasta su `nextUpdate`, con hasta 32 entradas; las respuestas OCSP no se guardan. Lo descargado se informa en `FetchedRevocation`, y cada CRL dice si salió del caché.

### Índice de CRLs (`crl_index.py`)

pyhanko-certvalidator busca un serial recorriendo la CRL con asn1crypto, entrada por entrada: con la CRL de la AC ONTI (~240 mil entradas) cada búsqueda tarda ~2 s. `install()` reemplaza esa función (`validate_crl.find_cert_in_list`) por una que consulta primero un índice de seriales armado con `cryptography` (~0,15 s por CRL, cacheado por huella, hasta 16). Si el serial no está, responde enseguida; si está, o la CRL es indirecta, delega en la original. Es un parche global al proceso: lo instala `bootstrap.build`, una vez.

Tests: `tests/test_verify.py`, `tests/test_verify_online.py`, `tests/test_crl_index.py`, `tests/test_store.py` y la suite de PDFs (por HTTP y con PDFs reales), goldens `verify_*`.
