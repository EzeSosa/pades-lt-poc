# Pruebas

Cada capa se prueba con lo mínimo que necesita: el dominio sin nada, los casos de uso con fakes, los adaptadores contra la biblioteca real y la API completa por HTTP. Además hay redes de seguridad que fijan el contrato de la API, la suite de PDFs y las reglas de arquitectura.

```powershell
uv run pytest                      # todo (~1 min)
uv run pytest -m "not suite"       # sin la suite de PDFs (~30 s)
uv run pytest tests/test_domain_*  # sólo el dominio (instantáneo)
uv run lint-imports                # sólo las reglas de dependencias
```

## Por capa

| Capa | Cómo se prueba | Archivos |
|------|----------------|----------|
| Dominio | Puro: certificados y firmas armados a mano, sin PKI, sin PDFs, sin red. Cada regla (F, V, D, C, S) tiene su test, citado en [invariantes.md](invariantes.md). | `test_domain_certificates.py`, `test_domain_source.py`, `test_domain_chains.py`, `test_domain_verification.py`, `test_domain_document.py`, `test_domain_signing.py` |
| Casos de uso | Con fakes de los puertos (`tests/fakes.py` y los definidos en cada test): qué piden a los puertos, en qué orden y cómo arman el resultado. | `test_certificate_source.py`, `test_extract_chains.py`, `test_verify_signatures.py`, `test_analyze_document.py`, `test_domain_signing.py` (`SignPdf`) |
| Adaptadores de salida | Contra la biblioteca real. Un puerto con un fake tiene un test de contrato que corre contra los dos (`test_certificate_repository.py`: SQLite y memoria). | `test_codec.py`, `test_certificate_repository.py`, `test_issuer_fetcher.py`, `test_crl_index.py` |
| API (de punta a punta) | Por HTTP con el `TestClient`, con PDFs firmados en el test con la PKI de prueba. | `test_sign.py`, `test_verify.py`, `test_verify_online.py`, `test_document.py`, `test_certificates.py`, `test_inspection.py`, `test_store.py`, `test_ui.py` |

## La app de los tests (`tests/conftest.py`)

`conftest.py` crea una app con `create_app(SETTINGS, clock=CLOCK, issuer_fetcher=...)`:

- **`SETTINGS`**: PKI y fuente en una carpeta temporal (no tocan `./pki` ni `./certs.db`) y una URL base con un puerto libre.
- **`pki`**: una `MiniPki` (del testbed) sobre la misma carpeta y URL que la de la app, para leer certificados y claves, revocar y armar CRLs y respuestas OCSP. Los tests la importan con `from conftest import pki`.
- **`CLOCK`** (fixture `clock`): un `TestClock`, que da la hora real salvo dentro de `with clock.frozen_at(momento):`. Lo usa la vigencia que devuelven `/store` y `/certificates/inspect`.
- **AIA** (fixture `aia`): el `HttpIssuerFetcher` real, con un `get` que falla siempre ("sin red en los tests") salvo que el test ponga `aia.route = url -> bytes`. Ningún test sale a la red.

Fixtures:

| Fixture | Qué da |
|---------|--------|
| `client` | El `TestClient` (de sesión). Su lifespan genera la PKI. |
| `services` | Los `Services` de la app: `services.source`, `services.verify_signatures`, `services.crl_cache`, `services.testbed`, ... |
| `pki_server` | La misma app escuchando en el puerto de `SETTINGS`: `/sign` y el modo con conexión de `/verify` se piden a sí mismos la TSA, las CRL y el OCSP por HTTP. |
| `timestamper` | El motor de la TSA del testbed, para sellar PDFs en el test. |
| `pdf` | Un PDF mínimo sin firmar. |

Y funciones: `load_signer(chain)` (el firmante de la PKI de prueba, embebiendo sólo los certificados de `chain`), `sign(pdf, signer, timestamper)` y `doc_timestamp(pdf, timestamper)`.

## Fakes (`tests/fakes.py`)

| Fake | Puerto | Para qué |
|------|--------|----------|
| `InMemoryCertificateRepository` | `CertificateRepository` | Un dict bajo un lock; valida antes de escribir (atómico) y repite la restricción "sólo raíces confiables" de la base. Cuenta las lecturas (`reads`). |
| `FixedClock` | `Clock` | Una hora fija que se mueve con `advance()`. |
| `StaticSeedCatalog` | `SeedCatalog` | Una lista fija. |
| `FixedPdfInspector` | `PdfInspector` | Siempre los mismos hechos (por defecto, vacíos), o lanza el error que se le dé. Registra qué PDFs se inspeccionaron. |

Los de un solo test (`FakeReader`, `FakeFetcher`, `FakeValidator`, `FakeEngine`) están en el test que los usa.

## Redes de seguridad

| Red | Qué fija | Archivos |
|-----|----------|----------|
| **Contrato** | La respuesta JSON completa de cada endpoint en los casos clave, contra `tests/golden/`. Antes de comparar se normaliza lo que cambia en cada corrida: huellas, seriales, DER y key ids de la PKI de prueba (por nombres estables como `<sha256:signer>`), horas (también las fechas PDF de `/M`), UUIDs, ids, el puerto, el orden de lo descargado en paralelo, la vigencia de la carga inicial (depende del calendario) y, del análisis del documento, los offsets y tamaños en bytes, las claves VRI y el `/ModDate` (cambia sólo si pasó un segundo entre revisiones). | `test_contract.py`, `golden/*.json` |
| **Suite de PDFs** | Los 40 casos de `testdata/pdf-suite` contra `/sign` y `/verify`, con el canario que detecta estado compartido entre pedidos (marca `suite`). | `test_pdf_suite.py` |
| **Arquitectura** | Las reglas de dependencias entre capas (import-linter) y que sólo `config.py` lea el entorno. | `test_architecture.py` |
| **Documentación** | Que cada test y golden citado en `docs/arquitectura` exista. | `test_docs.py` |

Un cambio de contrato buscado se graba con `UPDATE_GOLDEN=1 uv run pytest tests/test_contract.py`, revisando el diff de `tests/golden/` antes de commitear.

## Cómo agregar una regla de negocio

1. Escribirla en el dominio, con un id nuevo en el docstring del módulo (`F-07`, `V-11`, ...).
2. Probarla con un test puro en `test_domain_*.py`.
3. Si la orquesta un caso de uso, probarlo con fakes.
4. Agregarla a [invariantes.md](invariantes.md) con su motivo, dónde se aplica y los tests (los verifica `test_docs.py`).
5. Si cambia una respuesta de la API, regenerar los goldens y revisar el diff.
