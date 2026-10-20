# Arquitectura

Este documento describe cómo está organizado el código, qué puede depender de qué y por qué. Las decisiones de fondo están en los [ADRs](../adr/README.md): la arquitectura hexagonal en [ADR-0001](../adr/0001-arquitectura-hexagonal.md), el certificado de dominio en [ADR-0002](../adr/0002-certificado-de-dominio-sobre-der.md) y el testbed en [ADR-0003](../adr/0003-testbed-fuera-del-nucleo.md). Los conceptos de firma digital están en [pades.md](../pades.md), y la estructura interna del PDF en [pdf.md](../pdf.md).

| Documento | Contenido |
|-----------|-----------|
| [dominio.md](dominio.md) | Lenguaje ubicuo, modelos, reglas y errores del dominio |
| [invariantes.md](invariantes.md) | Catálogo de reglas de negocio con id, motivo, dónde se aplican y qué test las cubre |
| [casos-de-uso.md](casos-de-uso.md) | Cada caso de uso: operaciones, errores, secuencias y presentación HTTP |
| [puertos.md](puertos.md) | El contrato de cada puerto de salida |
| [adaptadores.md](adaptadores.md) | Cada adaptador, de entrada y de salida: con qué biblioteca y qué resuelve |
| [pruebas.md](pruebas.md) | Cómo se prueba cada capa, los fakes, los goldens y las redes de seguridad |

## El hexágono

```
                 ┌──────────── adapters/inbound/http ───────────┐
                 │  endpoints FastAPI, presenters, errores HTTP │
                 └──────────────────────┬───────────────────────┘
                                        │ llama a los casos de uso
          ┌─────────────────────────────▼─────────────────────────────┐
          │ application/                                              │
          │   use_cases/: SignPdf · VerifySignatures ·                │
          │     AnalyzeDocument · ExtractCertificateChains ·          │
          │     InspectCertificates · CertificateSource               │
          │   ports.py: lo que los casos de uso necesitan de afuera   │
          │ ┌───────────────────────────────────────────────────────┐ │
          │ │ domain/  Python puro: certificados, firmas, cadenas,  │ │
          │ │ validación, documento, firma, fuente; reglas F, V, D, │ │
          │ │ C, S; errores                                         │ │
          │ └───────────────────────────────────────────────────────┘ │
          └─────────────────────────────┬─────────────────────────────┘
                                        │ puertos (Protocols)
                 ┌──────────────────────▼───────────────────────┐
                 │ adapters/outbound                            │
                 │  pyhanko/ · crypto/ · sqlite/ · http/ ·      │
                 │  seed_catalog · clock                        │
                 └──────────────────────────────────────────────┘

 bootstrap.py: crea los adaptadores y los conecta con los casos de uso (raíz de composición)
 testbed/: la PKI, el OCSP y la TSA de la PoC; sólo bootstrap.py y app.py lo conocen
```

Las dependencias apuntan hacia adentro: los adaptadores dependen de la aplicación y del dominio; la aplicación, sólo del dominio; el dominio, de nada. Las reglas exactas, y cómo se verifican, están en [Reglas de dependencias](#reglas-de-dependencias).

## Mapa

```
src/pades_lt_poc/
├── domain/                   Python puro: modelos, reglas y errores (dominio.md)
│   ├── certificates.py       Certificate (sobre el DER), ValidityStatus, CaKind, CertificateDetails
│   ├── signatures.py         las firmas de un PDF: SignedDocument, CmsSignature, Integrity, TimestampToken
│   ├── chains.py             armado de cadenas sin exigir confianza: reglas C-01 a C-03
│   ├── verification.py       validación: opciones, anclas, motivo de desconfianza, nivel PAdES (V-01 a V-10)
│   ├── document.py           el documento: protección, formulario, revisiones, contenido activo y hallazgos (D-01 a D-10)
│   ├── signing.py            firma: perfil, campo libre, PDFs cifrados (S-01 a S-04)
│   ├── source.py             la fuente de certificados: entradas, TrustSnapshot, reglas F-01 a F-06
│   └── errors.py             errores de negocio
├── application/              depende sólo del dominio
│   ├── ports.py              los puertos de salida (puertos.md)
│   └── use_cases/            un caso de uso por operación (casos-de-uso.md)
│       ├── sign_pdf.py               SignPdf (/sign)
│       ├── verify_signatures.py      VerifySignatures (/verify)
│       ├── analyze_document.py       AnalyzeDocument (/document)
│       ├── certificate_chains.py     ExtractCertificateChains (/certificates)
│       ├── inspect_certificates.py   InspectCertificates (/certificates/inspect)
│       └── certificate_source.py     CertificateSource (/store): ABM, carga inicial y snapshot
├── adapters/                 (adaptadores.md)
│   ├── inbound/http/         la API: un módulo de endpoints por área con sus presenters,
│   │                         dependencies.py (inyección) y ui.py (las páginas de /ui)
│   └── outbound/
│       ├── pyhanko/          SignatureValidator, SignedPdfReader, PdfInspector y PdfSigningEngine con pyHanko:
│       │                     validator, signer, signed_pdf_reader, document_inspector, policies,
│       │                     trust_paths, fetching (CRL/OCSP/AIA con conexión), crl_index, convert
│       ├── crypto/           CertificateCodec con cryptography: codec (parseo, emisor), details
│       ├── sqlite/           CertificateRepository en SQLite
│       ├── http/             IssuerFetcher (AIA) con requests
│       ├── seed_catalog.py   SeedCatalog con los archivos de seed/
│       └── clock.py          Clock con el reloj del sistema
├── testbed/                  el mundo externo simulado (ADR-0003): MiniPki, motor de la TSA y
│                             sus endpoints (/pki, /ocsp, /tsa)
├── config.py                 Settings: la configuración, leída una vez del entorno
├── bootstrap.py              raíz de composición: build(settings, clock, issuer_fetcher) -> Services
├── app.py                    create_app(settings, clock, issuer_fetcher): FastAPI, lifespan, endpoints y errores
├── seed/                     la carga inicial de la fuente (DER)
└── static/                   la UI (HTML, CSS y JS sin build)
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
               ├── AnalyzeDocument(PyHankoPdfInspector())
               ├── ExtractCertificateChains(PyHankoSignedPdfReader(codec), codec, source, issuer_fetcher)
               └── InspectCertificates(codec, source)
         app.state.services = Services          lo leen adapters/inbound/http/dependencies.py y el testbed
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

La configuración es un valor que se pasa: `create_app(Settings(...))` en los tests, `create_app()` (que llama a `from_env()`) en producción. Ningún módulo la lee al importarse, así que los tests no dependen del orden de los imports y se pueden tener dos configuraciones en un mismo proceso.

## Raíz de composición (`bootstrap.py`)

`build(settings, *, clock=None, issuer_fetcher=None)` es el **único** lugar que crea adaptadores y decide qué implementación recibe cada caso de uso. Devuelve un `Services` (dataclass inmutable) con todo lo creado; la app lo guarda en `app.state.services`. `Services.close()` libera lo que haya que liberar (la conexión SQLite). `clock` e `issuer_fetcher` son el reloj del sistema (`SystemClock`) y la descarga AIA por HTTP (`HttpIssuerFetcher()`) salvo que se pasen otros: los tests pasan un reloj que se puede fijar y una descarga AIA sin red.

Lo que es global o compartido se crea o se instala acá:

- **Índice de CRLs** (`adapters/outbound/pyhanko/crl_index.install()`): reemplaza una función de pyhanko-certvalidator, que no la recibe por parámetro, así que es global al proceso. Se instala una vez; llamarla de nuevo no tiene efecto adicional.
- **Caché de CRLs** (`CrlCache`): uno por app, que se pasa al `RevocationFetcherBackend` de cada verificación con conexión. Los tests lo vacían con `services.crl_cache.clear()`.
- **El testbed** (`Testbed`, ADR-0003): `build` le saca a la PKI los archivos del firmante para `PyHankoPdfSigner.from_files` y la raíz como ancla implícita de `VerifySignatures`. Ningún caso de uso ni adaptador lo conoce.

### Arranque con uvicorn

`app.py` no crea la app al importarse: uvicorn la construye con la factory.

```powershell
uv run pades-lt-poc                                         # main(): uvicorn.run(..., factory=True)
uv run uvicorn --factory pades_lt_poc.app:create_app        # a mano
```

El `Dockerfile` usa la misma forma (`CMD ["uvicorn", "--factory", "pades_lt_poc.app:create_app", ...]`).

## Reglas de dependencias

Se verifican en `tests/test_architecture.py` (import-linter, contratos en `[tool.importlinter]` de `pyproject.toml`; a mano, `uv run lint-imports`):

| Regla | Por qué |
|-------|---------|
| `domain` no importa ninguna otra parte del paquete ni pyHanko, asn1crypto, cryptography, FastAPI, Starlette, uvicorn, requests, aiohttp ni sqlite3 | El dominio es Python puro: se prueba sin infraestructura y no cambia cuando cambia una biblioteca. |
| `application` sólo importa `domain` (y las mismas bibliotecas prohibidas) | Los casos de uso conocen a los adaptadores sólo por sus puertos. |
| `adapters.outbound` no importa `adapters.inbound`, `app`, `bootstrap`, `config`, `testbed` ni FastAPI | Un adaptador de salida implementa un puerto y nada más: no sabe quién lo llama, cómo se configura la app ni qué PKI hay detrás. |
| `adapters.inbound` no importa `adapters.outbound`, `bootstrap`, `config`, `app` ni `testbed` | Los endpoints conocen los casos de uso y el dominio, no cómo se arman ni con qué bibliotecas. |
| `testbed` no importa `domain`, `application`, `adapters`, `bootstrap`, `config` ni `app` | Es el mundo externo simulado: no depende de quien lo consume (ADR-0003). |
| Sólo `config.py` lee variables de entorno | Un solo lugar para saber qué se puede configurar. |

Las reglas cuentan los imports indirectos: si `adapters.inbound` importara `bootstrap` (por ejemplo, para tipar `Services`), estaría viendo a todos los adaptadores de salida y al testbed. Por eso `adapters/inbound/http/dependencies.py` lee `app.state.services` sin importar `bootstrap`.

## Historia de la migración

La PoC empezó con `routers/` (HTTP) y `services/` (la lógica, con las bibliotecas adentro). Se migró en pasos, cada uno en su commit, con el contrato HTTP congelado por los tests de contrato:

| Paso | Contenido |
|------|-----------|
| 0 | Red de seguridad: tests de contrato (goldens), suite de PDFs como tests, reglas de dependencias, ADR-0001 |
| 1 | Configuración (`config.py`) y raíz de composición (`bootstrap.py`); `create_app` como factory |
| 2 | Dominio base (`Certificate`, errores) y el puerto `CertificateCodec` (ADR-0002) |
| 3 | Fuente de certificados: `CertificateSource`, repositorio SQLite, carga inicial, reloj |
| 4 | Extracción e inspección de certificados: cadenas en el dominio, lector de PDFs y AIA como puertos |
| 5 | Validación: reglas V-01 a V-10 en el dominio, `VerifySignatures`, pyHanko como adaptador |
| 6 | Firma: reglas S-01 a S-04 en el dominio, `SignPdf`, motor de firma como adaptador |
| 7 | Testbed (PKI, OCSP, TSA) fuera del núcleo (ADR-0003) |
| 8 | Endpoints como adaptador de entrada (`adapters/inbound/http`) y documentación final |

Dónde quedó cada cosa:

| Antes | Ahora |
|-------|-------|
| `services/__init__.py`: errores, `read_signed_pdf` | `domain/errors.py`; `adapters/outbound/pyhanko/signed_pdf_reader.py::open_signed_pdf` |
| `services/store.py`: `CertificateStore` | `domain/source.py` (reglas), `application/use_cases/certificate_source.py`, `adapters/outbound/sqlite/certificate_repository.py`, `adapters/outbound/seed_catalog.py` |
| `services/certificates.py`: `CertificateExtractor`, armado de cadenas, AIA | `domain/chains.py`, `application/use_cases/certificate_chains.py`, `adapters/outbound/pyhanko/signed_pdf_reader.py`, `adapters/outbound/http/issuer_fetcher.py`; parseo y `issued_by` en `adapters/outbound/crypto/codec.py` |
| `services/inspection.py`: `CertificateInspector` | `application/use_cases/inspect_certificates.py`, `adapters/outbound/crypto/details.py` |
| `services/verification.py`: `SignatureVerifier` y políticas | `domain/verification.py`, `application/use_cases/verify_signatures.py`, `adapters/outbound/pyhanko/validator.py` y `policies.py` |
| `services/trust_problems.py` | Resúmenes y sugerencias en `domain/verification.py::trust_problem`; caminos en `adapters/outbound/pyhanko/trust_paths.py` |
| `services/fetching.py`, `services/crl_index.py` | `adapters/outbound/pyhanko/fetching.py`, `crl_index.py` |
| `services/signing.py`: `PdfSigner` | `domain/signing.py`, `application/use_cases/sign_pdf.py`, `adapters/outbound/pyhanko/signer.py` |
| `services/timestamping.py`, `pki.py` | `testbed/tsa.py`, `testbed/pki.py` |
| `routers/pki.py`, `ocsp.py`, `tsa.py` | `testbed/http.py` |
| `routers/*.py`, `dependencies.py` | `adapters/inbound/http/`, con los presenters que arman el JSON |
