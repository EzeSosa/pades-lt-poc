# ADR-0001: Arquitectura hexagonal para las operaciones de negocio

**Estado**: Aceptado (2026-10-18)

## Contexto

La PoC hace cuatro operaciones de negocio: **firmar** un PDF en PAdES (`/sign`), **validar** sus firmas (`/verify`), extraer e inspeccionar **certificados** (`/certificates`, `/certificates/inspect`) y administrar la **fuente de certificados** en la que se apoya la validación (`/store`). Ya separa los endpoints HTTP (`routers/`) de la lógica (`services/`), pero dentro de `services/` las reglas que definen el resultado están mezcladas con las bibliotecas que hacen el trabajo:

- **Las reglas viven junto a pyHanko.** En `services/verification.py`, las mismas funciones arman los `ValidationContext` de pyHanko y deciden el nivel PAdES (`_pades_level`), si la fuente completó la cadena (`_from_store`), que con conexión el nivel no pasa de B-T y que con conexión sólo se valida a la hora actual. Para probar cualquiera de esas reglas hay que firmar un PDF real con la PKI de prueba.
- **Tres representaciones de certificado.** Circulan objetos de `cryptography.x509`, de `asn1crypto` y de pyHanko, y se convierten de una a otra donde hace falta (p. ej. `CertificateExtractor.extract` re-serializa los de la fuente para pasarlos a `asn1crypto`).
- **Dependencias circulares entre servicios.** `services/store.py` importa funciones privadas de `certificates.py` (`_issued_by`) y de `inspection.py` (`_is_ca`, `_load`), y esos dos importan el tipo `CertificateStore` bajo `TYPE_CHECKING` para evitar el ciclo.
- **El núcleo conoce a la PKI de prueba.** `PdfSigner.from_pki()` y `SignatureVerifier.from_pki()` leen claves y certificados de `pki.py`, y `store.DB_PATH` se calcula a partir de `pki.PKI_DIR`. Lo que en un sistema real es el mundo externo (la CA, el OCSP, la TSA) está en el mismo plano que la lógica que lo consume.
- **La configuración se lee al importar.** `pki.PKI_DIR`, `pki.BASE_URL` y `store.DB_PATH` salen de variables de entorno en tiempo de import, por eso `tests/conftest.py` las fija antes de importar la app.
- **Estado global implícito.** `crl_index.install()` reemplaza una función de pyhanko-certvalidator en todo el proceso, y `fetching.CRL_CACHE` es un singleton del módulo.
- **Sin modelo de dominio.** Los servicios devuelven `dict`s que ya son el JSON de la API. La forma de la respuesta y la regla de negocio no se pueden cambiar por separado.
- **Tests acoplados a privados.** Para aislar algo, los tests reemplazan funciones privadas con `monkeypatch` (`certificates._http_get`, `store._now`, `CertificateStore._reload`, `SignatureVerifier.trust_roots`), porque no hay puntos de inyección.

El riesgo concreto es que una actualización de pyHanko, un cambio de base de datos o un arreglo en un endpoint altere sin querer una regla de confianza, y que eso sólo se detecte si algún test de punta a punta mira justo ese campo.

## Decisión

Se migra la aplicación a una **arquitectura hexagonal** (puertos y adaptadores), de forma incremental y sin cambiar el contrato HTTP.

### Capas

| Capa | Paquete | Contiene | Puede depender de |
|------|---------|----------|-------------------|
| Dominio | `pades_lt_poc.domain` | Modelos (certificado, entrada de la fuente, resultado de validación, nivel PAdES), reglas e invariantes, errores de negocio. Python puro. | Sólo la biblioteca estándar |
| Aplicación | `pades_lt_poc.application` | Los casos de uso (firmar, verificar, extraer cadenas, inspeccionar, administrar la fuente) y los **puertos**: `typing.Protocol` que describen lo que el caso de uso necesita del exterior. | Dominio |
| Adaptadores de entrada | `pades_lt_poc.adapters.inbound` | FastAPI: routers, validación del request, presenters que convierten el dominio en el JSON actual, el mapeo de errores a status HTTP. La UI estática. | Aplicación, dominio |
| Adaptadores de salida | `pades_lt_poc.adapters.outbound` | Las implementaciones de los puertos: pyHanko (firma y validación), `cryptography` (parseo y verificación de certificados), SQLite (fuente), `requests`/aiohttp (AIA, CRL, OCSP). | Aplicación, dominio, bibliotecas externas |
| Testbed | `pades_lt_poc.testbed` | La mini PKI, el respondedor OCSP, la TSA y los endpoints para revocar: el "mundo externo" simulado de la PoC. | Bibliotecas externas |
| Raíz de composición | `pades_lt_poc.bootstrap`, `pades_lt_poc.config` | Lee la configuración una vez, crea los adaptadores y los inyecta en los casos de uso (en el lifespan de FastAPI). | Todo |

### Regla de dependencias

Las dependencias apuntan hacia adentro: **adaptadores → aplicación → dominio**. En particular:

1. El dominio no importa `pyhanko`, `pyhanko_certvalidator`, `asn1crypto`, `cryptography`, `fastapi`, `starlette`, `sqlite3`, `requests` ni `aiohttp`.
2. La aplicación no importa adaptadores ni bibliotecas de infraestructura: los conoce sólo por sus puertos.
3. Ningún módulo del núcleo (dominio, aplicación, adaptadores) importa `testbed`. Las credenciales del firmante y la raíz implícita de la PoC llegan por puertos, y la raíz de composición los conecta al testbed.

La regla se hace cumplir con [import-linter](https://import-linter.readthedocs.io/): los contratos están en `[tool.importlinter]` de `pyproject.toml` y los corre `tests/test_architecture.py`. Cada fase agrega los contratos de las capas que crea.

### pyHanko sigue siendo el motor

No se reimplementa criptografía. pyHanko firma, construye caminos de certificación, consulta revocación y analiza modificaciones, ahora como adaptador. Lo que pasa al dominio son las **decisiones**: qué anclas de confianza valen, qué algoritmos se aceptan y para quién, qué nivel PAdES se alcanza, cuándo un PDF deja de ser autosuficiente, qué se rechaza y con qué motivo. El adaptador traduce entre el dominio y los tipos de pyHanko en los dos sentidos, y ningún tipo de pyHanko cruza el puerto.

### Contrato HTTP congelado

Rutas, parámetros, status y cuerpos de respuesta no cambian durante la migración. Lo garantizan los tests de contrato (`tests/test_contract.py`, ver [Red de seguridad](#red-de-seguridad)). Un cambio de contrato, si se quiere, va en un cambio aparte de la migración y con su propio ADR.

### Sin framework de inyección de dependencias

Los puertos son `typing.Protocol`, los modelos son `dataclass(frozen=True)` y la composición se hace a mano en `bootstrap.py`. Para el tamaño de la PoC, un contenedor de DI agrega indirección sin aportar nada.

### Migración incremental

Se migra por operación de negocio, en este orden: configuración y raíz de composición, modelo de dominio base, fuente de certificados, certificados, validación, firma, y por último el testbed y la limpieza. La fuente va primero porque la validación y la extracción de certificados dependen de ella. Cada paso es un cambio que se puede mergear solo, con todos los tests en verde y el contrato intacto. Mientras dura la migración conviven `services/` y las capas nuevas; `services/` se borra en el último paso.

### Red de seguridad

Antes de mover código se agregan tres tipos de test, que deben pasar sin cambios en cada paso:

- **Contrato** (`tests/test_contract.py` + `tests/golden/`): la respuesta completa de cada endpoint en los casos clave (B-LT, B-LTA, sin DSS, hora declarada, con conexión, firmante revocado, cadena completada con la fuente, entradas libres de iText, rechazos, extracción con sello y DocTimeStamp, cadena incompleta, documento alterado, inspección, ciclo completo del ABM). Antes de comparar se normaliza lo que cambia en cada corrida: huellas, seriales, DER y key ids de la PKI de prueba (que se regenera), horas, UUIDs de los campos de DocTimeStamp, ids de la fuente y el puerto del server de prueba. El orden de lo descargado con conexión también se normaliza, porque las descargas son paralelas.
- **Aceptación** (`tests/test_pdf_suite.py`): los 40 casos de `testdata/pdf-suite` contra `/sign` y `/verify`, incluido el canario que detecta estado compartido entre pedidos.
- **Arquitectura** (`tests/test_architecture.py`): los contratos de import-linter.

## Alternativas descartadas

- **Dejar la estructura actual y sólo agregar tests.** Los tests de contrato protegen la forma de la respuesta, pero no permiten probar las reglas sin firmar PDFs reales ni separan el riesgo de actualizar pyHanko. Tampoco resuelve el ciclo entre servicios ni el acoplamiento a la PKI de prueba.
- **Arquitectura en capas clásica (controller → service → repository).** Ordena el acceso a datos, pero deja a pyHanko y a `cryptography` dentro de la capa de servicio, que es justamente donde están mezcladas las reglas. El problema de este código no es la base de datos sino las bibliotecas de firma.
- **Reescribir de cero en la estructura nueva.** Se perdería la historia de bugs ya resueltos (el `SimpleSigner` compartido, los timeouts de los fetchers, las CRLs grandes, las entradas libres de iText) que hoy están codificados y comentados en el código. La migración incremental los conserva y los tests de contrato verifican que sigan resueltos.
- **Un modelo de dominio que envuelva los objetos de `asn1crypto`.** Evita conversiones, pero ata el dominio a una biblioteca concreta. El certificado de dominio se construye sobre el DER (bytes) y los atributos que el negocio necesita; cada adaptador mantiene su propia vista parseada.

## Consecuencias

**Se gana:**

- Las reglas de negocio (anclas, SHA-1 heredado, niveles PAdES, autosuficiencia del PDF, reglas de la fuente) se prueban con tests unitarios puros, sin PKI ni red, en milisegundos.
- Actualizar pyHanko, cambiar SQLite por otra base o la descarga HTTP por otra biblioteca afecta a un solo adaptador, y los tests de contrato del puerto dicen si sigue cumpliendo.
- Los tests dejan de parchear funciones privadas: inyectan fakes por los puertos (un reloj fijo, un fetcher de AIA en memoria, un repositorio en memoria).
- La configuración se lee una vez, en un solo lugar, y deja de depender del orden de los imports.
- Se rompe el ciclo entre la fuente y los servicios de certificados.

**Cuesta:**

- Más archivos y un nivel de indirección: los casos de uso llaman a puertos en vez de a la biblioteca.
- Conversiones entre el modelo de dominio y los tipos de cada biblioteca. Se mitiga parseando una sola vez por pedido en cada adaptador.
- Durante la migración conviven dos estructuras (`services/` y las capas nuevas). El README indica en qué paso está cada operación.

**Queda pendiente:**

- Los goldens de la fuente incluyen `validity_status` de los certificados de la carga inicial, que es `valid` hasta el 2027-11-17 (vencimiento de la AC Raíz 2007 y de la AC ONTI). El puerto `Clock` del paso de la fuente permite fijar la hora en esos tests; hasta entonces, si vencen, los goldens se regeneran.
- Cada paso de la migración documenta en `docs/arquitectura/` su parte: dominio, invariantes, casos de uso, puertos y adaptadores.
