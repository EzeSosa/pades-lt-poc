# Dominio

El paquete `pades_lt_poc.domain` contiene los modelos, las reglas y los errores de las operaciones de negocio. Es **Python puro**: no importa ninguna biblioteca de infraestructura ni otra capa del paquete (lo verifica el contrato "El dominio es Python puro" de import-linter). Por eso se prueba con datos armados a mano, sin PKI, sin red y sin PDFs.

> Este documento crece con la migración. Hoy cubre el certificado y los errores (paso 2), la fuente de certificados (paso 3) y las firmas de un PDF y sus cadenas (paso 4). La validación y la firma se agregan en sus pasos. Las reglas, con sus ids, están juntas en [invariantes.md](invariantes.md).

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
| Fuente de certificados | `CertificateSource`, `StoredCertificate` | Las raíces e intermedios que usa el validador además de lo que trae el PDF. |
| Ancla de confianza | `trusted` en una raíz, `TrustSnapshot.trusted_roots` | Una raíz en la que el validador confía sin más. |
| Habilitado | `enabled` | Si el validador usa el certificado. Deshabilitado, sigue en la fuente pero no cuenta. |
| Origen | `Origin` | De dónde salió: la carga inicial (`seed`), a mano (`manual`) o un PDF (`pdf`). |
| Carga inicial | `SeedCatalog`, `CertificateSource.initialize` | Los certificados que trae la fuente la primera vez (AC Raíz 2007 y 2016, AC ONTI). |
| Snapshot | `TrustSnapshot` | Lo que usa el validador de la fuente en un instante, inmutable. |
| Firma CMS | `CmsSignature` | Una firma CMS/PKCS#7: el certificado firmante, los demás que trae y su integridad. |
| Integridad | `Integrity` | El chequeo criptográfico: `intact` (lo cubierto no cambió) y `valid` (la firma verifica con la clave). Sin confianza ni revocación. |
| Sello de tiempo | `TimestampToken` | Un token RFC 3161: la hora sellada y la firma CMS de la TSA. |
| Sello de documento | `SignatureKind.DOC_TIMESTAMP` | Un `/DocTimeStamp` (PAdES B-LTA): un sello sobre todo el documento. |
| Cadena | `ChainResult`, `ChainLink` | Los certificados de hoja a raíz, cada uno con su origen. |
| Origen de un eslabón | `CertSource` | `cms`, `dss`, `store` o `aia`. |
| Detalle legible | `CertificateDetails` | Lo que muestra la inspección: nombres atributo por atributo, clave y extensiones como texto. |

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
| `ca_issuer_urls` | `tuple[str, ...] \| None` | Las URIs AIA caIssuers (dónde se publica el emisor), en orden, incluidas las que no son HTTP. `None` si no tiene la extensión AIA; vacía si la tiene sin caIssuers. |

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

## Fuente de certificados (`domain/source.py`)

La fuente son las raíces e intermedios que el validador usa además de lo que trae cada PDF: las raíces confiables son anclas de confianza de `/verify`, y los intermedios completan cadenas en `/verify` y `/certificates`. Los conceptos (por qué un validador necesita su propia fuente, qué pasa cuando completa una cadena) están en [pades.md](../pades.md#la-fuente-de-certificados).

### Modelos

| Modelo | Qué es |
|--------|--------|
| `StoredCertificate` | Una entrada de la fuente: `id`, `certificate`, `kind` (`CaKind`), `trusted`, `enabled`, `origin` (`Origin`), `notes`, `created_at`, `updated_at`. |
| `NewEntry` | Un certificado listo para entrar, con las reglas ya aplicadas (tipo y confianza efectiva). Lo arma `new_entries`. |
| `EntryChanges` | Lo que se puede cambiar de una entrada: `enabled`, `trusted`, `notes`. `None` es "no cambiar"; `notes=""` sí es un cambio. |
| `AddResult` | El resultado de un alta: `added` y `already_present`. |
| `SeedCertificate` | Un certificado de la carga inicial (`der`) con su nota. |
| `TrustSnapshot` | Lo que usa el validador, en un instante: `trusted_roots`, `intermediates`, `chain_certs` y `known_sha256`. |
| `SourceSummary` | Los contadores del listado: `total`, `trusted_roots`, `intermediates`, `disabled`. |
| `Origin` | `seed` (carga inicial), `manual` (archivo o base64 cargado a mano), `pdf` (tomado de un PDF desde la inspección). |

### `TrustSnapshot`

Se arma con `TrustSnapshot.from_entries(entradas)` y conserva el orden de las entradas (el orden en que se agregaron) dentro de cada grupo:

| Campo | Contiene | Lo usa |
|-------|----------|--------|
| `trusted_roots` | Raíces **habilitadas** y **confiables** | `/verify`: anclas de confianza, junto con la raíz de la PoC |
| `intermediates` | Intermedios **habilitados** | `/verify`: completan cadenas |
| `chain_certs` | Raíces e intermedios **habilitados**, confiables o no | `/certificates`: arman cadenas sin exigir confianza |
| `known_sha256` | Huellas de **todo** lo que está en la fuente, habilitado o no | `in_store` de `/certificates` y `/certificates/inspect` |

Es inmutable: el caso de uso lo reemplaza entero después de cada cambio, así que una verificación que tomó un snapshot ve raíces e intermedios del mismo estado aunque el ABM cambie en el medio.

### Reglas

| Id | Regla | Dónde |
|----|-------|-------|
| F-01 | La fuente sólo guarda CAs. Si alguno de los certificados recibidos no lo es, no se agrega ninguno, y el error los nombra a todos. | `new_entries` |
| F-02 | Sólo una raíz puede ser ancla de confianza. Al **agregar**, `trusted` se aplica sólo a las raíces y un intermedio queda no confiable sin error (un PKCS#7 puede traer los dos). Al **cambiar**, pedir `trusted=true` para un intermedio es un error. Dejar de confiar siempre se puede. | `new_entries`, `check_changes` |
| F-03 | Si todos los certificados recibidos ya estaban, es un error (`DuplicateCertificate` con sus ids). Si estaban algunos, se agregan los demás y se informan los dos grupos. | `CertificateSource.add` |
| F-04 | La carga inicial se aplica una sola vez, la primera vez que se crea la base: lo que se borre después queda borrado. Restaurarla agrega sólo lo que falta, sin tocar lo que está. | `CertificateSource.initialize`, `restore_seed`; atomicidad en el repositorio |
| F-05 | Un cambio aplica enseguida (el snapshot se recarga), y una verificación usa raíces e intermedios de un mismo snapshot. | `CertificateSource._reload`, `TrustSnapshot` |
| F-06 | Para confiar y completar cadenas cuenta sólo lo habilitado; para decir si un certificado ya está, cuenta todo. | `TrustSnapshot.from_entries` |

Además:

- **Tipo**: una CA autofirmada es raíz; una CA emitida por otra, intermedio (`Certificate.ca_kind`).
- **Orden del listado**: primero las raíces y cada grupo por sujeto (`listing_order`).
- **Resumen**: `trusted_roots` e `intermediates` cuentan lo que usa el validador (el snapshot); `disabled`, lo deshabilitado (`summarize`).

Tests: `tests/test_domain_source.py` (reglas, puro), `tests/test_certificate_source.py` (caso de uso con fakes).

## Firmas de un PDF (`domain/signatures.py`)

Las firmas de un PDF tal como las necesita el negocio. Las arma el puerto [`SignedPdfReader`](puertos.md#signedpdfreader) con pyHanko; el dominio no lee PDFs.

| Modelo | Qué es |
|--------|--------|
| `SignedDocument` | `signatures` (en el orden del documento, nunca vacío) y `dss_certificates` (los del DSS, si hay). |
| `EmbeddedSignature` | `field_name`, `kind` (`SignatureKind`), `cms` (la firma) y `timestamp` (el sello de la firma, si tiene; siempre `None` en un DocTimeStamp). |
| `SignatureKind` | `Signature` (`/Sig`) o `DocTimeStamp`. Los valores son los de la API (`type`). |
| `CmsSignature` | `signer` (`None` si no se pudo identificar), `other_certificates` (en orden) e `integrity`. |
| `TimestampToken` | `time` (la hora sellada, `genTime`) y `cms` (la firma de la TSA). |
| `Integrity` | `intact`, `valid` y `error` (si el chequeo no se pudo hacer). `ok` es `intact and valid`. |

`Integrity.failure(altered)` es el motivo a mostrar cuando no verifica: el `error` si lo hay; si no, `altered` cuando lo cubierto cambió (`"el documento fue alterado"` para una firma, `"el sello no corresponde a esta firma"` para su sello), y si no, `"firma inválida"`.

Qué cubre cada integridad lo decide el adaptador: para una firma (`/Sig`), el hash del ByteRange; para un DocTimeStamp, que el `messageImprint` del TSTInfo coincida con el ByteRange; para el sello de una firma, que coincida con el **valor de la firma**. Ver [pades.md](../pades.md#extracción-de-certificados-post-certificates).

## Cadenas (`domain/chains.py`)

La cadena de una firma, de la hoja a la raíz, armada **sin exigir confianza**: sirve para ver la PKI de cualquier firma, también de PKIs ajenas.

| Modelo / función | Qué es |
|------------------|--------|
| `CertSource` | De dónde salió un eslabón, en orden de precedencia: `cms`, `dss`, `store`, `aia`. |
| `ChainLink` | Un eslabón: `certificate`, `source` e `in_store` (si está en la fuente, habilitado o no). |
| `ChainResult` | `crypto_valid`, `intact`, `valid`, `error`, `links` (hoja → raíz, `None` si no verifica), `chain_complete` (si termina en un autofirmado) y `aia_errors`. |
| `candidate_pool(cms, extra)` | Los candidatos en orden: el firmante, los demás del CMS y los `extra`; un certificado repetido queda con su primer origen (C-02). |
| `build_chain(pool, issued_by, lookup)` | Sube desde la hoja buscando el emisor de cada eslabón: primero en el pool, en orden, y si no está y hay `lookup`, entre lo que devuelva (origen `aia`). No repite certificados. Se detiene en un autofirmado o cuando no encuentra al emisor. |
| `chain_for(cms, extra, altered, issued_by, lookup, known_sha256)` | La integridad y, si verifica, la cadena (C-01). |
| `http_ca_issuer_urls(cert)` | Las URLs AIA caIssuers que se pueden descargar (http/https), o por qué no hay ninguna (C-03). |

`issued_by` y `lookup` son funciones que recibe: el dominio no verifica firmas ni descarga nada. `issued_by` es `CertificateCodec.issued_by`; `lookup` lo arma el caso de uso con el `IssuerFetcher`.

Errores de armado que se informan en `aia_errors`:

| Mensaje | Cuándo |
|---------|--------|
| `<url>: <motivo>` | La descarga de esa URL falló o no trajo certificados. |
| `<sujeto>: no tiene AIA caIssuers` | El eslabón no tiene la extensión AIA. |
| `<sujeto>: no tiene AIA caIssuers por HTTP` | La tiene, pero sin URLs http(s). |
| `<sujeto>: AIA no trae a su emisor` | Se descargó, pero ninguno de los certificados firmó al eslabón. |

Si el emisor se encuentra, los errores de otras URLs del mismo eslabón no se informan.

Tests: `tests/test_domain_chains.py` (puro), `tests/test_extract_chains.py` (caso de uso con fakes).

## Detalle legible (`CertificateDetails`, en `domain/certificates.py`)

Lo que muestra `/certificates/inspect` además de lo que ya tiene `Certificate`: `version`, `subject` e `issuer` atributo por atributo (`NameAttribute`: `oid`, `name`, `value`), `signature_algorithm`, `public_key` (`PublicKeyInfo`: `type`, `size` y, si es EC, `curve`) y `extensions` (`ExtensionInfo`: `oid`, `name`, `critical` y `values`, una línea de texto por valor). Lo arma `CertificateCodec.describe`; qué texto lleva cada extensión está en [adaptadores.md](adaptadores.md#adaptersoutboundcryptodetailspy-el-detalle-legible).
