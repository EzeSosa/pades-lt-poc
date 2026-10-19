# Casos de uso

Un caso de uso es una operación de negocio: recibe lo que pide quien la usa, aplica las reglas del [dominio](dominio.md) y usa el exterior sólo a través de [puertos](puertos.md). Están en `application/use_cases/` y no saben de HTTP: los endpoints de `routers/` traducen el pedido, llaman al caso de uso y arman la respuesta (presenters).

> Este documento crece con la migración. Hoy tiene la fuente de certificados (paso 3) y la extracción e inspección de certificados (paso 4). La validación y la firma siguen en `services/` y se agregan en sus pasos.

| Caso de uso | Endpoints | Puertos |
|-------------|-----------|---------|
| [`CertificateSource`](#certificatesource-la-fuente-de-certificados) | `/store/certificates*` (y el snapshot que leen `/verify`, `/certificates` y `/certificates/inspect`) | `CertificateRepository`, `CertificateCodec`, `SeedCatalog`, `Clock` |
| [`ExtractCertificateChains`](#extractcertificatechains-la-cadena-de-cada-firma) | `POST /certificates` | `SignedPdfReader`, `CertificateCodec`, `IssuerFetcher` (y el snapshot de `CertificateSource`) |
| [`InspectCertificates`](#inspectcertificates-el-detalle-de-un-certificado) | `POST /certificates/inspect` | `CertificateCodec` (y el snapshot de `CertificateSource`) |

## `CertificateSource`: la fuente de certificados

`application/use_cases/certificate_source.py`. Administra la fuente (ABM y carga inicial) y le da al validador su snapshot. Las reglas F-01 a F-06 están en [dominio.md](dominio.md#reglas) e [invariantes.md](invariantes.md#fuente-de-certificados-f).

**Estado en memoria.** Guarda el `TrustSnapshot` vigente y lo reemplaza entero después de cada cambio (`_reload`, bajo un lock para que una recarga vieja no pise a una nueva). `snapshot()` no bloquea; todo lo demás sí, porque usa el repositorio. La copia es de cada proceso: con varios workers, un cambio sólo llega al proceso que lo atendió. La PoC corre con un solo worker.

**Ciclo de vida.** `bootstrap.build` lo crea y llama a `initialize()` una vez, al arrancar. Antes de eso el snapshot está vacío.

### Operaciones

| Operación | Entrada | Salida | Reglas | Errores (HTTP) |
|-----------|---------|--------|--------|----------------|
| `initialize()` | — | — | F-04: aplica la carga inicial si nunca se aplicó, y carga el snapshot. | `UnprocessableCertificate` si un certificado de la carga inicial no es una CA (error de empaquetado: la app no arranca). |
| `snapshot()` | — | `TrustSnapshot` | F-05, F-06 | — |
| `list(kind=None)` | `CaKind` opcional | `list[StoredCertificate]` | Raíces primero, cada grupo por sujeto. | — |
| `summary()` | — | `SourceSummary` | Cuenta lo que usa el validador. | — |
| `get(id)` | id | `StoredCertificate` | — | `CertificateNotFound` (404) |
| `add(data, trusted, notes, origin)` | DER, PEM, PKCS#7 o base64 | `AddResult` | F-01, F-02, F-03; recarga el snapshot. | `UnprocessableCertificate` (422): no es un certificado, o alguno no es CA. `DuplicateCertificate` (409): ya estaban todos. |
| `update(id, changes)` | id, `EntryChanges` | `StoredCertificate` | F-02; sin cambios no toca nada (ni `updated_at`); recarga el snapshot. | `CertificateNotFound` (404), `UnprocessableInput` (422): confiar en un intermedio. |
| `delete(id)` | id | — | Recarga el snapshot. | `CertificateNotFound` (404) |
| `restore_seed()` | — | `list[StoredCertificate]` (los agregados) | F-04: sólo lo que falta. | — |

Las horas (`created_at`, `updated_at`) salen del `Clock`. El repositorio las guarda al segundo.

### Alta, paso a paso

```mermaid
sequenceDiagram
    participant R as routers/store.py
    participant S as CertificateSource
    participant C as CertificateCodec
    participant D as domain/source.py
    participant Repo as CertificateRepository
    R->>S: add(data, trusted, notes, origin)
    S->>C: parse(data)
    C-->>S: [Certificate]  (o UnprocessableCertificate)
    S->>D: new_entries(certs, trusted, notes, origin)
    D-->>S: [NewEntry]  (F-01: o UnprocessableCertificate; F-02: trusted sólo en raíces)
    S->>Repo: insert_missing(entries, clock.now())
    Repo-->>S: (agregadas, ya estaban)  — atómico
    alt no se agregó nada
        S-->>R: DuplicateCertificate(ids)  (F-03)
    else
        S->>Repo: all()
        S->>S: snapshot = TrustSnapshot.from_entries(...)  (F-05)
        S-->>R: AddResult
    end
    R->>R: present(entrada, clock.now())  → JSON
```

### Carga inicial

```mermaid
sequenceDiagram
    participant B as bootstrap.build
    participant S as CertificateSource
    participant Cat as SeedCatalog
    participant Repo as CertificateRepository
    B->>S: initialize()
    S->>Cat: seeds()
    S->>S: new_entries(..., trusted=True, origin=seed) por cada uno
    S->>Repo: apply_initial_load(entries, now)
    Note over Repo: si ya hay marca: no hace nada<br/>si no: inserta lo que falta + marca, en una transacción
    S->>Repo: all()
    S->>S: snapshot
```

La carga inicial pide `trusted=True` para todos sus certificados; F-02 hace que la AC ONTI, que es intermedia, quede no confiable.

### Presentación (HTTP)

`routers/store.py` arma el JSON con `present(entrada, now)`: los campos del certificado (`sha256`, `subject`, `issuer`, `not_before`, `not_after`, `der_b64`), los de la entrada (`id`, `kind`, `trusted`, `enabled`, `origin`, `notes`, `created_at`, `updated_at`) y `validity_status`, que se calcula con la hora del `Clock` de la app. El router también resuelve lo que es propio de HTTP: exigir uno solo de `crt` o `b64`, y llevar el alta fuera del event loop (`run_in_threadpool`), porque bloquea.

Tests: `tests/test_certificate_source.py` (con fakes), `tests/test_store.py` (por HTTP), goldens `store_*`.

## `ExtractCertificateChains`: la cadena de cada firma

`application/use_cases/certificate_chains.py`. Por cada firma del PDF (incluidos los DocTimeStamp), su integridad y, si verifica, la cadena de su firmante; y para cada firma con sello de tiempo, lo mismo para la TSA. No exige confianza. Las reglas C-01 a C-03 están en [dominio.md](dominio.md#cadenas-domainchainspy).

**Bloquea**: puede descargar emisores por AIA. El router lo llama con `run_in_threadpool`.

| Entrada | Salida | Errores (HTTP) |
|---------|--------|----------------|
| `pdf` (bytes), `fetch_missing` (bool) | `list[SignatureChains]`: por firma, `field_name`, `kind`, `chain` (`ChainResult`) y `timestamp` (`TimestampChain`: hora y `ChainResult`, o `None`) | `UnprocessablePdf` (422): el PDF no tiene firmas |

### Qué candidatos tiene cada cadena

| Cadena | Candidatos, en orden de precedencia |
|--------|------------------------------------|
| Firma (o DocTimeStamp) | firmante y demás certificados de su CMS (`cms`) → DSS (`dss`) → fuente, habilitados (`store`) → AIA si `fetch_missing` (`aia`) |
| Sello de la firma | firmante y demás certificados del token (`cms`) → demás certificados del CMS de la **firma** (`cms`) → DSS → fuente → AIA |

El sello de una firma se analiza sólo si la firma verifica (C-01): si el documento se alteró, no hay un valor de firma confiable que el sello pueda cubrir.

### Paso a paso

```mermaid
sequenceDiagram
    participant R as routers/certificates.py
    participant U as ExtractCertificateChains
    participant P as SignedPdfReader
    participant S as CertificateSource
    participant D as domain/chains.py
    participant F as IssuerFetcher
    R->>U: extract(pdf, fetch_missing)  (en un hilo)
    U->>P: read(pdf)
    P-->>U: SignedDocument  (o UnprocessablePdf)
    U->>S: snapshot()
    loop cada firma
        U->>D: chain_for(cms, dss + fuente, ...)
        opt falta un emisor y fetch_missing
            D->>U: lookup(eslabón)
            U->>F: fetch(url)  (una vez por URL en el pedido)
        end
        opt tiene sello y la firma verifica
            U->>D: chain_for(token, cms de la firma + dss + fuente, ...)
        end
    end
    U-->>R: [SignatureChains]
    R->>R: present_signature(...)  → JSON
```

### Presentación (HTTP)

`routers/certificates.py::present_signature` arma, por firma, `field`, `type` y los campos de la cadena: `crypto_valid`, `intact`, `valid` y, si no verifica, `error` y `certificates: null`; si verifica, `chain_complete`, `certificates` y, si hubo, `aia_errors`. Las firmas (no los DocTimeStamp) llevan además `signature_timestamp` (`null` si no tiene o si la firma no verifica). Cada certificado: `type` (`end_entity` en la posición 0, `root` si es autofirmado, si no `intermediate`), `source`, `self_signed`, `subject`, `issuer`, `serial_number` (hex), vigencia, `sha256_fingerprint`, `der_b64` e `in_store`.

Tests: `tests/test_extract_chains.py` (con fakes), `tests/test_certificates.py` (por HTTP), goldens `certificates_*`.

## `InspectCertificates`: el detalle de un certificado

`application/use_cases/inspect_certificates.py`. El detalle legible de los certificados recibidos (uno, o todos los de un PKCS#7, en orden) y si cada uno ya está en la fuente. No hace E/S.

| Entrada | Salida | Errores (HTTP) |
|---------|--------|----------------|
| `data`: DER, PEM, PKCS#7 o base64 de un DER | `list[InspectedCertificate]`: `certificate`, `details` (`CertificateDetails`) e `in_store` | `UnprocessableCertificate` (422) |

El router exige uno solo de `crt` (archivo) o `b64` (texto) y arma el JSON con `present_inspected`: los campos del certificado y del detalle, `validity` con `status` y `days_left` calculados con el `Clock` de la app, las huellas y `in_store`.

Tests: `tests/test_inspection.py` (por HTTP), goldens `inspect_*`.
