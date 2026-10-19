# Arquitectura

Este documento describe cómo está organizado el código, qué puede depender de qué y por qué. La decisión de fondo (arquitectura hexagonal, pyHanko como adaptador, contrato HTTP congelado) está en [ADR-0001](../adr/0001-arquitectura-hexagonal.md); los conceptos de firma digital, en [pades.md](../pades.md).

> **Migración en curso.** La estructura objetivo está descripta en el ADR-0001. Este documento refleja lo que **ya existe** y se actualiza en cada paso. Estado de los pasos:
>
> | Paso | Contenido | Estado |
> |------|-----------|--------|
> | 0 | Red de seguridad: tests de contrato, suite de PDFs, reglas de dependencias | Hecho |
> | 1 | Configuración y raíz de composición | Hecho |
> | 2 | Modelo de dominio base y `CertificateCodec` | Pendiente |
> | 3 | Fuente de certificados | Pendiente |
> | 4 | Certificados (extracción e inspección) | Pendiente |
> | 5 | Validación | Pendiente |
> | 6 | Firma | Pendiente |
> | 7 | Testbed (PKI, OCSP, TSA) fuera del núcleo | Pendiente |
> | 8 | Limpieza | Pendiente |

## Mapa actual

```
src/pades_lt_poc/
├── config.py       Settings: la configuración, leída una vez del entorno
├── bootstrap.py    raíz de composición: build(settings) -> Services
├── app.py          create_app(settings): FastAPI, lifespan, routers y manejo de errores
├── dependencies.py inyecta en los endpoints los servicios de app.state.services
├── pki.py          MiniPki: la PKI de prueba de una carpeta y una URL base
├── routers/        endpoints HTTP
└── services/       la lógica de cada operación, todavía con las bibliotecas adentro
```

Flujo de arranque:

```
create_app(settings)                       importar app.py no lee nada ni crea nada
   └── lifespan (al arrancar uvicorn o el TestClient)
         └── bootstrap.build(settings) ──► Services
               ├── MiniPki(settings.pki_dir, settings.public_base_url).ensure()
               ├── crl_index.install()            (global de pyhanko-certvalidator, una vez)
               ├── CertificateStore(settings.cert_store_db)
               ├── CrlCache()                     (uno por app)
               ├── load_tsa(pki), PdfSigner.from_pki(pki)
               ├── SignatureVerifier(store, [raíz de la PoC], fetchers con el CrlCache)
               └── CertificateExtractor(store), CertificateInspector(store)
         app.state.services = Services          lo leen las dependencias de dependencies.py
         ... al cerrar: services.close()        (cierra la conexión SQLite)
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

`build(settings)` es el **único** lugar que crea servicios y decide qué implementación recibe cada uno. Devuelve un `Services` (dataclass inmutable) con todo lo creado; la app lo guarda en `app.state.services` y los endpoints lo reciben por `dependencies.py`. `Services.close()` libera lo que haya que liberar (hoy, la conexión SQLite).

Lo que antes era estado global del proceso ahora se crea o se instala acá:

- **Índice de CRLs** (`services/crl_index.install()`): reemplaza una función de pyhanko-certvalidator, que no la recibe por parámetro, así que sigue siendo global al proceso. Se instala en `build`, no como efecto lateral de crear el verificador. Llamarla más de una vez no tiene efecto adicional.
- **Caché de CRLs** (`CrlCache`): era un singleton del módulo `fetching` (`CRL_CACHE`). Ahora hay uno por app, que se pasa al `RevocationFetcherBackend` de cada verificación con conexión. Los tests lo vacían con `services.crl_cache.clear()`.
- **La PKI de prueba** (`MiniPki`): antes eran funciones de módulo que leían `PKI_DIR` y `BASE_URL`; ahora es un objeto con su carpeta y su URL, y los servicios que la usan la reciben (`PdfSigner.from_pki(pki)`, `load_tsa(pki)`). El verificador ya no la conoce: recibe la raíz de la PoC como una lista de anclas implícitas.

### Arranque con uvicorn

Como `app.py` ya no crea la app al importarse, uvicorn la construye con la factory:

```powershell
uv run pades-lt-poc                                         # main(): uvicorn.run(..., factory=True)
uv run uvicorn --factory pades_lt_poc.app:create_app        # a mano
```

El `Dockerfile` usa la misma forma (`CMD ["uvicorn", "--factory", "pades_lt_poc.app:create_app", ...]`).

### En los tests

`tests/conftest.py` arma un `Settings` con una carpeta temporal y un puerto libre, crea la app con `create_app(SETTINGS)` y expone:

- `pki`: una `MiniPki` sobre la misma carpeta y URL que la de la app, para leer certificados y claves, revocar y armar CRLs y respuestas OCSP. Los tests la importan con `from conftest import pki`.
- La fixture `services`: los `Services` de la app (`services.store`, `services.verifier`, `services.crl_cache`, ...).

## Reglas de dependencias

Se verifican en `tests/test_architecture.py` (import-linter, contratos en `[tool.importlinter]` de `pyproject.toml`):

| Regla | Por qué |
|-------|---------|
| `services` y `pki` no importan `app`, `dependencies`, `routers`, FastAPI, Starlette ni uvicorn | La lógica no sabe que la llaman por HTTP. |
| `pki` no importa `services` | La PKI de prueba es el "mundo externo": no depende de quien la consume. |
| `services` y `pki` no importan `bootstrap` ni `config` | Reciben lo que necesitan por parámetro; quién los arma y de dónde sale la configuración es asunto de la raíz de composición. |
| Sólo `config.py` lee variables de entorno | Un solo lugar para saber qué se puede configurar. |

Cada paso de la migración agrega las reglas de las capas que crea.
