# Arquitectura

Este documento describe cómo está organizado el código, qué puede depender de qué y por qué. La decisión de fondo (arquitectura hexagonal, pyHanko como adaptador, contrato HTTP congelado) está en [ADR-0001](../adr/0001-arquitectura-hexagonal.md); los conceptos de firma digital, en [pades.md](../pades.md).

| Documento | Contenido |
|-----------|-----------|
| [dominio.md](dominio.md) | Lenguaje ubicuo, modelos, reglas y errores del dominio |
| [invariantes.md](invariantes.md) | Catálogo de reglas de negocio con id, motivo, dónde se aplican y qué test las cubre |
| [casos-de-uso.md](casos-de-uso.md) | Cada caso de uso: operaciones, errores, secuencias y presentación HTTP |
| [puertos.md](puertos.md) | El contrato de cada puerto de salida |
| [adaptadores.md](adaptadores.md) | Cada adaptador: con qué biblioteca y qué resuelve |
| [ADRs](../adr/README.md) | Las decisiones de arquitectura, con su contexto |

> **Migración en curso.** La estructura objetivo está descripta en el ADR-0001. Este documento refleja lo que **ya existe** y se actualiza en cada paso. Estado de los pasos:
>
> | Paso | Contenido | Estado |
> |------|-----------|--------|
> | 0 | Red de seguridad: tests de contrato, suite de PDFs, reglas de dependencias | Hecho |
> | 1 | Configuración y raíz de composición | Hecho |
> | 2 | Modelo de dominio base y `CertificateCodec` | Hecho |
> | 3 | Fuente de certificados | Hecho |
> | 4 | Certificados (extracción e inspección) | Hecho |
> | 5 | Validación | Hecho |
> | 6 | Firma | Hecho |
> | 7 | Testbed (PKI, OCSP, TSA) fuera del núcleo | Hecho |
> | 8 | Limpieza | Pendiente |

## Mapa actual

```
src/pades_lt_poc/
├── domain/         Python puro: modelos, reglas y errores (dominio.md)
│   ├── certificates.py   Certificate (sobre el DER), ValidityStatus, CaKind, CertificateDetails
│   ├── signatures.py     las firmas de un PDF: SignedDocument, CmsSignature, Integrity, TimestampToken
│   ├── chains.py         armado de cadenas sin exigir confianza: reglas C-01 a C-03
│   ├── verification.py   validación: opciones, anclas, motivo de desconfianza, nivel PAdES (V-01 a V-10)
│   ├── signing.py        firma: perfil, campo libre, PDFs cifrados (S-01 a S-04)
│   ├── source.py         la fuente de certificados: entradas, TrustSnapshot, reglas F-01 a F-06
│   └── errors.py         errores de negocio
├── application/      depende sólo del dominio
│   ├── ports.py          los puertos de salida (puertos.md)
│   └── use_cases/
│       ├── certificate_source.py     CertificateSource: ABM, carga inicial y snapshot (casos-de-uso.md)
│       ├── certificate_chains.py     ExtractCertificateChains: la cadena de cada firma (/certificates)
│       ├── inspect_certificates.py   InspectCertificates: detalle legible (/certificates/inspect)
│       ├── verify_signatures.py      VerifySignatures: validación de las firmas (/verify)
│       └── sign_pdf.py               SignPdf: firma PAdES (/sign)
├── adapters/outbound/  implementaciones de los puertos (adaptadores.md)
│   ├── crypto/codec.py, details.py  CertificateCodec con cryptography (parseo, emisor, detalle legible)
│   ├── pyhanko/                     SignatureValidator y SignedPdfReader con pyHanko: validator, policies,
│   │                                trust_paths, fetching (CRL/OCSP/AIA), crl_index, signed_pdf_reader, signer
│   ├── http/issuer_fetcher.py       IssuerFetcher (AIA) con requests
│   ├── sqlite/certificate_repository.py   CertificateRepository en SQLite
│   ├── seed_catalog.py              SeedCatalog con los archivos de seed/
│   └── clock.py                     Clock con el reloj del sistema
├── config.py       Settings: la configuración, leída una vez del entorno
├── bootstrap.py    raíz de composición: build(settings, clock, issuer_fetcher) -> Services
├── app.py          create_app(settings, clock, issuer_fetcher): FastAPI, lifespan, routers y manejo de errores
├── dependencies.py inyecta en los endpoints los casos de uso de app.state.services
├── routers/        endpoints HTTP de las operaciones de negocio, con sus presenters
└── testbed/        el mundo externo simulado (ADR-0003): MiniPki, motor de la TSA y sus endpoints (/pki, /ocsp, /tsa)
```

Flujo de arranque:

```
create_app(settings)                       importar app.py no lee nada ni crea nada
   └── lifespan (al arrancar uvicorn o el TestClient)
         └── bootstrap.build(settings) ──► Services
               ├── Testbed.create(settings.pki_dir, settings.public_base_url)
               │                                  (genera la PKI si no existe; carga el motor de la TSA)
               ├── crl_index.install()            (adapters/outbound/pyhanko: global de pyhanko-certvalidator, una vez)
               ├── SqliteCertificateRepository(settings.cert_store_db, codec)
               ├── CertificateSource(repositorio, codec, PackagedSeedCatalog(), clock).initialize()
               │                                  (carga inicial la primera vez, y el snapshot)
               ├── CrlCache()                     (uno por app)
               ├── SignPdf(PyHankoPdfSigner.from_files(clave, cert y cadena del firmante, raíz de la PoC))
               ├── VerifySignatures(PyHankoSignatureValidator(codec, fetchers con el CrlCache),
               │                    source, [raíz de la PoC], clock)
               ├── ExtractCertificateChains(PyHankoSignedPdfReader(codec), codec, source, issuer_fetcher)
               └── InspectCertificates(codec, source)
         app.state.services = Services          lo leen las dependencias de dependencies.py
         ... al cerrar: services.close()        (cierra la conexión SQLite del repositorio)
```

## Configuración (`config.py`)

`Settings` es un dataclass inmutable con todo lo que se puede configurar. `Settings.from_env()` lo arma desde las variables de entorno; es **el único lugar** del paquete que las lee (lo verifica `tests/test_architecture.py::test_only_config_reads_the_environment`).

| Campo | Variable | Por defecto | Para qué |
|-------|----------|-------------|----------|
| `pki_dir` | `PKI_DIR` | `./pki` | Carpeta de la mini PKI: certificados, claves y `revoked.json`. |
| `public_base_url` | `PUBLIC_BASE_URL` | `http://127.0.0.1:8000` | URL con la que se ve la app. Queda grabada en los certificados al generar la PKI (CDP, AIA, OCSP). Se le quita la `/` final. |
| `cert_store_db` | `CERT_STORE_DB` | `certs.db` junto a `pki_dir` | Base SQLite de la fuente de certificados. |

Una variable vacía cuenta como no definida.

**Por qué así.** Antes `pki.PKI_DIR`, `pki.BASE_URL` y `store.DB_PATH` se calculaban al importar los módulos. Eso obligaba a los tests a fijar las variables de entorno antes del primer import, y hacía imposible tener dos configuraciones en un mismo proceso. Ahora la configuración es un valor que se pasa: `create_app(Settings(...))` en los tests, `create_app()` (que llama a `from_env()`) en producción.

## Raíz de composición (`bootstrap.py`)

`build(settings, *, clock=None, issuer_fetcher=None)` es el **único** lugar que crea servicios y decide qué implementación recibe cada uno. Devuelve un `Services` (dataclass inmutable) con todo lo creado; la app lo guarda en `app.state.services` y los endpoints lo reciben por `dependencies.py`. `Services.close()` libera lo que haya que liberar (hoy, la conexión SQLite). `clock` e `issuer_fetcher` son el reloj del sistema (`SystemClock`) y la descarga AIA por HTTP (`HttpIssuerFetcher()`) salvo que se pasen otros: los tests pasan un reloj que se puede fijar y una descarga AIA sin red.

Lo que antes era estado global del proceso ahora se crea o se instala acá:

- **Índice de CRLs** (`adapters/outbound/pyhanko/crl_index.install()`): reemplaza una función de pyhanko-certvalidator, que no la recibe por parámetro, así que sigue siendo global al proceso. Se instala en `build`, no como efecto lateral de crear el validador. Llamarla más de una vez no tiene efecto adicional.
- **Caché de CRLs** (`CrlCache`): era un singleton del módulo `fetching` (`CRL_CACHE`). Ahora hay uno por app, que se pasa al `RevocationFetcherBackend` de cada verificación con conexión. Los tests lo vacían con `services.crl_cache.clear()`.
- **La PKI de prueba** (`MiniPki`, en `testbed/`): antes eran funciones de módulo que leían `PKI_DIR` y `BASE_URL`; ahora es un objeto con su carpeta y su URL, y `bootstrap.build` saca de ella lo que necesita cada pieza: los archivos del firmante para `PyHankoPdfSigner.from_files`, la raíz como ancla implícita de `VerifySignatures`, y la PKI entera para la TSA (`load_tsa(pki)`). Ningún caso de uso ni adaptador la conoce.

### Arranque con uvicorn

Como `app.py` ya no crea la app al importarse, uvicorn la construye con la factory:

```powershell
uv run pades-lt-poc                                         # main(): uvicorn.run(..., factory=True)
uv run uvicorn --factory pades_lt_poc.app:create_app        # a mano
```

El `Dockerfile` usa la misma forma (`CMD ["uvicorn", "--factory", "pades_lt_poc.app:create_app", ...]`).

### En los tests

`tests/conftest.py` arma un `Settings` con una carpeta temporal y un puerto libre, crea la app con `create_app(SETTINGS, clock=CLOCK, issuer_fetcher=HttpIssuerFetcher(get=AIA))` y expone:

- `pki`: una `MiniPki` sobre la misma carpeta y URL que la de la app, para leer certificados y claves, revocar y armar CRLs y respuestas OCSP. Los tests la importan con `from conftest import pki`.
- La fixture `services`: los `Services` de la app (`services.source`, `services.verify_signatures`, `services.crl_cache`, ...).
- La fixture `clock`: el reloj de la app (`TestClock`). Da la hora real, salvo dentro de `with clock.frozen_at(momento):`.
- La fixture `aia`: lo que "descarga" la app por AIA. Falla siempre (sin red), salvo que el test ponga `aia.route = url -> bytes`.

Los fakes de los puertos (repositorio en memoria, reloj fijo, catálogo estático) están en `tests/fakes.py`, para probar casos de uso sin la app.

## Reglas de dependencias

Se verifican en `tests/test_architecture.py` (import-linter, contratos en `[tool.importlinter]` de `pyproject.toml`):

| Regla | Por qué |
|-------|---------|
| `domain` no importa ninguna otra parte del paquete ni pyHanko, asn1crypto, cryptography, FastAPI, Starlette, uvicorn, requests, aiohttp ni sqlite3 | El dominio es Python puro: se prueba sin infraestructura y no cambia cuando cambia una biblioteca. |
| `application` sólo importa `domain` (y las mismas bibliotecas prohibidas) | Los casos de uso conocen a los adaptadores sólo por sus puertos. |
| `adapters.outbound` no importa `routers`, `dependencies`, `app`, `bootstrap`, `config`, `testbed` ni FastAPI | Un adaptador implementa un puerto y nada más: no sabe quién lo llama, cómo se configura la app ni qué PKI hay detrás. |
| `routers` y `dependencies` no importan `bootstrap`, `config`, `app` ni `testbed` (tampoco de forma indirecta) | Los endpoints de negocio conocen los casos de uso, no cómo se arman. |
| `testbed` no importa `domain`, `application`, `adapters`, `routers`, `dependencies`, `bootstrap`, `config` ni `app` | Es el mundo externo simulado: no depende de quien lo consume (ADR-0003). |
| Sólo `config.py` lee variables de entorno | Un solo lugar para saber qué se puede configurar. |

Las reglas de import-linter cuentan los imports indirectos: si `routers` importara `dependencies` y `dependencies` importara `bootstrap`, `routers` estaría viendo al testbed. Por eso `dependencies.py` lee `app.state.services` sin importar `bootstrap`.
