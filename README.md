# PoC PAdES B-LT con FastAPI + pyHanko

Firma PDFs en **PAdES B-LT** (opcionalmente **B-LTA**) usando una mini PKI de dos niveles, un respondedor OCSP y una TSA RFC 3161, todo servido por la misma app. Para validar usa además una **fuente de certificados** (raíces e intermedios en SQLite, con su ABM), y trae una UI web para inspeccionar PDFs firmados: la cadena de certificados de cada firma, un reporte de validación, el detalle de cada certificado y la administración de la fuente.

Para entender los conceptos (PKI, CRL, OCSP, TSA, CMS, DSS, niveles PAdES) y cómo se aplican en el código, ver [docs/pades.md](docs/pades.md).

## PKI

```
Root CA (autofirmada)                        publica /pki/root.crl
 └── Intermediate CA                         publica /pki/intermediate.crl + OCSP /ocsp
      ├── Firmante de Prueba                 KU digitalSignature, nonRepudiation
      ├── PoC Time Stamping Authority        EKU timeStamping (crítica)
      └── PoC OCSP Responder                 EKU OCSPSigning + id-pkix-ocsp-nocheck
```

- La **intermedia** se valida por la **CRL de la raíz**.
- El **firmante** y la **TSA** se validan por **OCSP**. Además tienen la CRL de la intermedia como respaldo.
- El respondedor OCSP es *delegado* (RFC 6960 §4.2.2.2), y `ocsp-nocheck` evita tener que validar su propia revocación.

La PKI se genera sola en `$PKI_DIR` (por defecto `./pki/`) la primera vez que arranca la app. Para regenerarla, borrá esa carpeta.

## Cómo se construye cada nivel

| Nivel  | Qué agrega                                          | En el código                                       |
|--------|-----------------------------------------------------|----------------------------------------------------|
| B-B    | CMS `ETSI.CAdES.detached` con atributos firmados    | `subfilter=SigSeedSubFilter.PADES`                 |
| B-T    | Sello de tiempo sobre la firma (TSA `/tsa`)         | `timestamper=HTTPTimeStamper(.../tsa)`             |
| B-LT   | DSS con la cadena completa + respuestas OCSP + CRLs | `embed_validation_info=True` + `ValidationContext` |
| B-LTA  | Document TimeStamp sobre todo lo anterior           | `use_pades_lta=True` (form `lta=true`)             |

Un PDF B-LT típico queda con el siguiente DSS: 5 certificados, 2 respuestas OCSP (firmante y TSA) y 1 CRL (la de la raíz, que cubre a la intermedia).

## Uso local

```powershell
uv sync
uv run pades-lt-poc                  # http://127.0.0.1:8000  (redirige a la UI; el Swagger está en /docs)
uv run python scripts/demo.py        # firma out/documento.pdf y lo verifica
uv run python scripts/demo.py --lta  # idem, en B-LTA
```

## Fuente de certificados

El validador no depende sólo de lo que trae cada PDF: tiene una **fuente de certificados**, una tabla SQLite con raíces e intermedios que se carga al arrancar y se administra por API (`/store/certificates`) o desde la UI (`/ui/fuente`).

- **Raíces confiables** (habilitadas y marcadas como confiables): son las anclas de confianza de `/verify`. Sólo una raíz puede serlo.
- **Intermedios** (habilitados): completan la cadena cuando el PDF no los trae. `/verify` igual valida, pero lo **avisa**: la firma informa qué eslabones salieron de la fuente (`completed_from_store`) y el nivel no pasa de B-T, porque el PDF ya no alcanza solo para validarse. `/certificates` los usa antes que AIA (`source: "store"`).
- **Raíz de la PoC**: es ancla de confianza implícita y no está en la tabla. Se regenera junto con la PKI, así que guardada quedaría desactualizada.
- **Carga inicial**: al crear la base se cargan las AC Raíz de Argentina 2007 y 2016 (confiables) y la AC ONTI (intermedia, emisora de CiDi), de `src/pades_lt_poc/seed/`. Corre una sola vez: lo que se borre queda borrado, y `POST /store/certificates/seed` (o **Restaurar carga inicial**) vuelve a agregar lo que falte.
- **SHA-1**: se acepta sólo en lo que firman las raíces confiables que nacieron con SHA-1 (hoy, la AC Raíz 2007). Se calcula a partir de la fuente, así que vale para cualquier raíz así que se agregue.
- **Altas**: desde el reporte de inspección de un certificado (botón **Agregar a la fuente**), así se ve qué es antes de confiar en él. Está en `/ui/certificado`, en la tab Inspección de `/ui/firmas` y en el detalle de `/ui/fuente`. Sólo se aceptan CAs.
- Cada cambio del ABM aplica enseguida, sin reiniciar.

La base vive en `$CERT_STORE_DB`, por defecto `certs.db` junto a la carpeta de la PKI (`./certs.db` en local, `/data/certs.db` en Docker, dentro del volumen). Para empezar de cero, borrá ese archivo. Las tablas, sus columnas y restricciones, y cómo consultarla con `sqlite3` están en [docs/pades.md](docs/pades.md#la-base-sqlite). El ABM no tiene autenticación, como el resto de la PoC.

## UI

Abrir <http://127.0.0.1:8000> lleva a la UI. Son tres pantallas, con una navegación arriba para pasar de una a otra en la misma pestaña:

- **`/ui/firmas`**: se sube el PDF firmado **una vez** y sus resultados quedan en tres tabs, así que moverse entre ellas no pierde nada. Al elegir el PDF se llama en paralelo a `POST /certificates` y `POST /verify`, y cada tab muestra un resumen en su etiqueta (cantidad de firmas, nivel PAdES, cantidad de certificados).
- **`/ui/certificado`**: un certificado que no viene en un PDF. Se sube un `.crt`/`.cer`/`.pem`/`.p7c` (o se suelta sobre la zona del archivo), o se pega su base64 o PEM, y muestra el mismo reporte que la tab Inspección. Si es una CA, se puede **agregar a la fuente** desde ahí (y, si es una raíz, elegir si se confía en ella).
- **`/ui/fuente`**: la administración de la [fuente de certificados](#fuente-de-certificados). Un resumen (raíces confiables, intermedios, deshabilitados), filtros por tipo y búsqueda, y por cada certificado: ver su detalle (el mismo reporte de inspección) y editar sus notas, habilitar o deshabilitar, confiar o dejar de confiar (raíces) y borrar. También **Restaurar carga inicial**. Las altas se hacen desde la inspección.

| Tab de `/ui/firmas` | Endpoint | Qué muestra |
|-----|----------|-------------|
| Certificados | `POST /certificates` | Una card por firma (incluidos los DocTimeStamp) con su cadena hoja → raíz y, aparte, la de la TSA que la selló. Cada certificado tiene botones para **ver su detalle** (en la tab Inspección), **descargar el `.crt`** (DER) y **copiar su base64** al portapapeles. Cada CA indica si ya está en la fuente; para agregarla, «Ver detalle». |
| Verificación | `POST /verify` | Un reporte: nivel PAdES alcanzado, contenido del DSS, uso de la fuente y modo de validación, y una card por firma con integridad, confianza (y si la cadena se completó con la fuente), cobertura, modificaciones, sello de tiempo y el detalle de pyHanko. Se puede **imprimir o guardar como PDF**. |
| Inspección | `POST /certificates/inspect` | El detalle de un certificado: sujeto y emisor (destacando el CUIL/CUIT de la PKI argentina), vigencia con los días que quedan, clave, huellas SHA-256 y SHA-1, y todas las extensiones legibles. Se elige entre los certificados del PDF (sin repetir), o desde «Ver detalle» en Certificados. Si es una CA que no está en la fuente, se puede **agregar a la fuente** desde acá. |

Cada tab expone las opciones de su endpoint (`fetch_missing`, `validation_time`, `diff_policy`); al cambiarlas se vuelve a pedir sólo esa tab, con el mismo PDF. La tab activa queda en la URL (`/ui/firmas#verificacion`). El link **API** abre el Swagger (`/docs`) en otra pestaña.

**Lo analizado se guarda en el navegador** (IndexedDB, que admite archivos enteros): el PDF con sus opciones, la tab y el certificado que se estaba inspeccionando, y en `/ui/certificado` el último certificado. Al volver a una pantalla, o al recargarla, el archivo reaparece elegido y se vuelve a analizar. **Quitar** (en firmas) y **Limpiar** (en certificado) lo borran. Nada sale del navegador salvo los pedidos a la propia API; sin almacenamiento disponible (p. ej. una ventana privada) la UI anda igual, sólo que no recuerda.

Tiene **tema claro y oscuro**: por defecto sigue al sistema, y el botón de arriba a la derecha lo fija (se recuerda en el navegador). El acento es el naranja de Claude. Al imprimir siempre sale en claro.

Es HTML estático, sin build ni dependencias, en `src/pades_lt_poc/static/`: una página por pantalla (`firmas.html`, `certificado.html`, `fuente.html`) con su script (`firmas.js`, `certificado.js`, `fuente.js`), `ui.css`, `ui.js` (helpers compartidos: API, tema, guardado, descarga y copia) y un script por tab (`certificates.js`, `verify.js`, `inspect.js`; el último también lo usan `/ui/certificado` y `/ui/fuente`). Para copiar al portapapeles el navegador exige un contexto seguro (HTTPS o `localhost`). Si la app se sirve por IP sin HTTPS, la página usa un método alternativo que puede no estar disponible en todos los navegadores.

## Tests

```powershell
uv run pytest
```

Los tests generan su propia PKI en una carpeta temporal (no tocan `./pki`) y firman los PDFs en el mismo proceso con la TSA de la app, así que no hace falta tener el server levantado.

## Docker

```powershell
docker compose up -d --build
uv run python scripts/demo.py        # el mismo cliente sirve contra el contenedor
docker compose down                  # conserva la PKI (volumen pki-data)
docker compose down -v               # borra la PKI; se regenera al próximo arranque
```

La imagen copia el código al construirse: después de cambiar algo, `docker compose up -d --build` reconstruye y recrea el contenedor (no hace falta bajarlo antes, y la PKI se conserva).

La PKI, con sus claves, y la fuente de certificados (`certs.db`) viven en el volumen `/data`. `PUBLIC_BASE_URL` queda **grabada en los certificados** (URLs de CRL, AIA y OCSP) al generarse la PKI, así que tiene que ser alcanzable desde el propio contenedor (la app se consulta a sí misma al firmar) y desde quien valide las firmas. Si la cambiás, regenerá la PKI con `down -v`.

## Estructura

```
src/pades_lt_poc/
├── app.py            crea la app: lifespan (PKI + servicios), routers y manejo de errores
├── dependencies.py   inyecta en los endpoints los servicios creados en el lifespan
├── pki.py            la mini PKI: certificados, CRLs, OCSP y revocación
├── routers/          endpoints HTTP, uno por área: validan la entrada y delegan
│   ├── pki.py  ocsp.py  tsa.py
│   ├── signing.py  verification.py  certificates.py  store.py
│   └── ui.py             sirve las páginas de /ui
├── services/         una clase por operación, sin nada de HTTP
│   ├── signing.py        PdfSigner            (/sign)
│   ├── verification.py   SignatureVerifier    (/verify) + políticas de algoritmos y de modificaciones
│   ├── certificates.py   CertificateExtractor (/certificates) + armado de cadenas y descarga AIA
│   ├── inspection.py     CertificateInspector (/certificates/inspect): detalle legible de un certificado
│   ├── store.py          CertificateStore     (/store): la fuente de certificados en SQLite
│   └── timestamping.py   motor de la TSA      (/tsa)
├── seed/             la carga inicial de la fuente (AC Raíz Argentina 2007 y 2016, AC ONTI)
└── static/           la UI: una página y un script por pantalla, ui.css, ui.js y un JS por tab (servidos en /ui/static)
```

Los servicios lanzan `UnprocessablePdf` cuando el PDF no se puede procesar y `UnprocessableCertificate` cuando lo recibido no es un certificado. La app devuelve los dos como `422`.

## Endpoints

- `GET  /pki/{root|intermediate}.crt`: certificados de las CAs en PEM. Importá `root.crt` como confiable en Adobe Reader para ver la firma en verde.
- `GET  /pki/{root|intermediate}.crl`: CRLs en DER, regeneradas en cada request (validez de 1 día).
- `POST /ocsp`, `GET /ocsp/{base64}`: respondedor OCSP (RFC 6960) para los certificados emitidos por la intermedia. Devuelve el nonce si el pedido lo trae.
- `POST /pki/revoke/{intermediate|signer|tsa}` y `POST /pki/unrevoke-all`: para probar los casos negativos.
- `POST /tsa`: TSA RFC 3161 (`application/timestamp-query` → `application/timestamp-reply`).
- `POST /sign`: recibe `pdf` (archivo), `reason`, `location` y `lta` (bool). Re-firmar un PDF ya firmado agrega `Firma2`, `Firma3`, etc.
- `POST /verify`: valida **offline** (sin descargar nada y con revocación `hard-fail`) con lo que viene en el PDF (CMS y DSS) y la [fuente de certificados](#fuente-de-certificados). Si pasa sin usar la fuente, la firma es LT. Confía en la raíz de la PoC y en las raíces confiables de la fuente, aceptando SHA-1 sólo en lo que firman las raíces que nacieron con SHA-1. Si alguna cadena se completó con intermedios de la fuente, la firma los lista en `completed_from_store` (también su sello de tiempo), `certificate_store.self_contained` da `false` con una nota, y el nivel no pasa de B-T. Valida a la hora actual; con `validation_time=claimed_signing_time` valida cada firma a la hora que ella misma declara (no probada), y la respuesta lo indica en `validation_time` y en el `validated_at` de cada firma. Cada firma trae en `modifications` el análisis de los cambios posteriores (si es sospechoso, `bottom_line` da `false`); con `diff_policy=allow_unallocated_free_entries` se toleran las entradas libres de objetos que nunca existieron, que iText genera a veces.
- `POST /certificates`: recibe `pdf` y, por cada firma (incluidos los DocTimeStamp) **criptográficamente válida**, devuelve la cadena hoja → raíz armada con los certificados del propio PDF (CMS + DSS). Si el PDF no trae algún emisor (es habitual que sólo embeba el del firmante), lo busca en la fuente de certificados y, si tampoco está, lo descarga de la URL **AIA caIssuers** del certificado; la descarga se desactiva con `fetch_missing=false`. Cada certificado trae `type` (`end_entity`, `intermediate`, `root`), `source` (`cms`, `dss`, `store` o `aia`), `in_store` (si está en la fuente), `self_signed` y `der_b64` (el `.crt` en DER, base64). Cada firma incluye también `signature_timestamp`, con la hora y la cadena de la TSA que la selló. No exige confianza: también extrae cadenas de PKIs ajenas.
- `POST /certificates/inspect`: recibe un archivo `crt` (DER, PEM o PKCS#7) **o** un campo `b64` (el base64 de un DER, como el `der_b64` de `/certificates`, o un PEM), uno solo de los dos. Devuelve en `certificates` el detalle de cada certificado: sujeto y emisor atributo por atributo, `validity` (con `status` `valid`/`expired`/`not_yet_valid` y `days_left`), `is_ca`, `self_signed`, algoritmo de firma, clave pública, huellas y `extensions` (cada una con `oid`, `name`, `critical` y sus `values` como texto), e `in_store`: si ya está en la fuente de certificados.
- `GET /store/certificates` (con `?kind=root|intermediate` opcional): la fuente, con un `summary`. Cada certificado trae `id`, `kind`, `trusted`, `enabled`, `origin` (`seed`, `manual` o `pdf`), `notes`, sujeto, emisor, vigencia y `der_b64`.
- `POST /store/certificates`: agrega una CA, o todas las de un PKCS#7. Recibe `crt` o `b64` (como `/certificates/inspect`), `trusted` (si es una raíz, si queda como ancla de confianza; por defecto sí), `notes` y `origin`. Rechaza lo que no sea CA (`422`); si ya estaba todo, `409`.
- `GET`, `PATCH` y `DELETE /store/certificates/{id}`: ver, cambiar `enabled`, `trusted` o `notes` (JSON), y borrar. Marcar como confiable un intermedio da `422`.
- `POST /store/certificates/seed`: vuelve a agregar lo que falte de la carga inicial.
- `GET /ui/firmas`, `GET /ui/certificado` y `GET /ui/fuente`: las pantallas de la [UI](#ui). `GET /` y `GET /ui` redirigen a `/ui/firmas`, y `GET /docs` es el Swagger.

Para verificar el respondedor OCSP con una implementación independiente:

```bash
openssl ocsp -issuer intermediate.crt.pem -cert signer.crt.pem \
  -url http://127.0.0.1:8000/ocsp -CAfile root.crt.pem
```

## Limitaciones (es una PoC)

- Las claves están sin cifrar en disco. No hay HSM ni PKCS#11, y la raíz está "online".
- La TSA usa `DummyTimeStamper` de pyHanko: toma el reloj del server y usa como política un OID de ejemplo.
- La revocación es un JSON (`revoked.json`), sin motivo de revocación ni *delta CRLs*.
- El respondedor OCSP sólo responde por el firmante y la TSA. Para cualquier otro serial devuelve `unauthorized`.
