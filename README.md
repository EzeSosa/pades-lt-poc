# PoC PAdES B-LT con FastAPI + pyHanko

Firma PDFs en **PAdES B-LT** (opcionalmente **B-LTA**) usando una mini PKI de dos niveles, un respondedor OCSP y una TSA RFC 3161, todo servido por la misma app. Trae además una UI web para inspeccionar PDFs firmados: la cadena de certificados de cada firma, un reporte de validación y el detalle de cada certificado.

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

## UI

Abrir <http://127.0.0.1:8000> lleva a la UI. Son dos pantallas, con una navegación arriba para pasar de una a otra en la misma pestaña:

- **`/ui/firmas`**: se sube el PDF firmado **una vez** y sus resultados quedan en tres tabs, así que moverse entre ellas no pierde nada. Al elegir el PDF se llama en paralelo a `POST /certificates` y `POST /verify`, y cada tab muestra un resumen en su etiqueta (cantidad de firmas, nivel PAdES, cantidad de certificados).
- **`/ui/certificado`**: un certificado que no viene en un PDF. Se sube un `.crt`/`.cer`/`.pem`/`.p7c` (o se suelta sobre la zona del archivo), o se pega su base64 o PEM, y muestra el mismo reporte que la tab Inspección.

| Tab de `/ui/firmas` | Endpoint | Qué muestra |
|-----|----------|-------------|
| Certificados | `POST /certificates` | Una card por firma (incluidos los DocTimeStamp) con su cadena hoja → raíz y, aparte, la de la TSA que la selló. Cada certificado tiene botones para **ver su detalle** (en la tab Inspección), **descargar el `.crt`** (DER) y **copiar su base64** al portapapeles. |
| Verificación | `POST /verify` | Un reporte: nivel PAdES alcanzado, contenido del DSS y modo de validación, y una card por firma con integridad, confianza, cobertura, modificaciones, sello de tiempo y el detalle de pyHanko. Se puede **imprimir o guardar como PDF**. |
| Inspección | `POST /certificates/inspect` | El detalle de un certificado: sujeto y emisor (destacando el CUIL/CUIT de la PKI argentina), vigencia con los días que quedan, clave, huellas SHA-256 y SHA-1, y todas las extensiones legibles. Se elige entre los certificados del PDF (sin repetir), o desde «Ver detalle» en Certificados. |

Cada tab expone las opciones de su endpoint (`fetch_missing`, `validation_time`, `diff_policy`); al cambiarlas se vuelve a pedir sólo esa tab, con el mismo PDF. La tab activa queda en la URL (`/ui/firmas#verificacion`). El link **API** abre el Swagger (`/docs`) en otra pestaña.

**Lo analizado se guarda en el navegador** (IndexedDB, que admite archivos enteros): el PDF con sus opciones, la tab y el certificado que se estaba inspeccionando, y en `/ui/certificado` el último certificado. Al volver a una pantalla, o al recargarla, el archivo reaparece elegido y se vuelve a analizar. **Quitar** (en firmas) y **Limpiar** (en certificado) lo borran. Nada sale del navegador salvo los pedidos a la propia API; sin almacenamiento disponible (p. ej. una ventana privada) la UI anda igual, sólo que no recuerda.

Tiene **tema claro y oscuro**: por defecto sigue al sistema, y el botón de arriba a la derecha lo fija (se recuerda en el navegador). El acento es el naranja de Claude. Al imprimir siempre sale en claro.

Es HTML estático, sin build ni dependencias, en `src/pades_lt_poc/static/`: una página por pantalla (`firmas.html`, `certificado.html`) con su script (`firmas.js`, `certificado.js`), `ui.css`, `ui.js` (helpers compartidos: tema, guardado, descarga y copia) y un script por tab (`certificates.js`, `verify.js`, `inspect.js`; el último también lo usa `/ui/certificado`). Para copiar al portapapeles el navegador exige un contexto seguro (HTTPS o `localhost`). Si la app se sirve por IP sin HTTPS, la página usa un método alternativo que puede no estar disponible en todos los navegadores.

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

La PKI, con sus claves, vive en el volumen `/data`. `PUBLIC_BASE_URL` queda **grabada en los certificados** (URLs de CRL, AIA y OCSP) al generarse la PKI, así que tiene que ser alcanzable desde el propio contenedor (la app se consulta a sí misma al firmar) y desde quien valide las firmas. Si la cambiás, regenerá la PKI con `down -v`.

## Estructura

```
src/pades_lt_poc/
├── app.py            crea la app: lifespan (PKI + servicios), routers y manejo de errores
├── dependencies.py   inyecta en los endpoints los servicios creados en el lifespan
├── pki.py            la mini PKI: certificados, CRLs, OCSP y revocación
├── routers/          endpoints HTTP, uno por área: validan la entrada y delegan
│   ├── pki.py  ocsp.py  tsa.py
│   ├── signing.py  verification.py  certificates.py
│   └── ui.py             sirve las páginas de /ui
├── services/         una clase por operación, sin nada de HTTP
│   ├── signing.py        PdfSigner            (/sign)
│   ├── verification.py   SignatureVerifier    (/verify) + políticas de algoritmos y de modificaciones
│   ├── certificates.py   CertificateExtractor (/certificates) + armado de cadenas y descarga AIA
│   ├── inspection.py     CertificateInspector (/certificates/inspect): detalle legible de un certificado
│   └── timestamping.py   motor de la TSA      (/tsa)
└── static/           la UI: firmas.html y certificado.html con sus scripts, ui.css, ui.js y un JS por tab (servidos en /ui/static)
```

Los servicios lanzan `UnprocessablePdf` cuando el PDF no se puede procesar y `UnprocessableCertificate` cuando lo recibido no es un certificado. La app devuelve los dos como `422`.

## Endpoints

- `GET  /pki/{root|intermediate}.crt`: certificados de las CAs en PEM. Importá `root.crt` como confiable en Adobe Reader para ver la firma en verde.
- `GET  /pki/{root|intermediate}.crl`: CRLs en DER, regeneradas en cada request (validez de 1 día).
- `POST /ocsp`, `GET /ocsp/{base64}`: respondedor OCSP (RFC 6960) para los certificados emitidos por la intermedia. Devuelve el nonce si el pedido lo trae.
- `POST /pki/revoke/{intermediate|signer|tsa}` y `POST /pki/unrevoke-all`: para probar los casos negativos.
- `POST /tsa`: TSA RFC 3161 (`application/timestamp-query` → `application/timestamp-reply`).
- `POST /sign`: recibe `pdf` (archivo), `reason`, `location` y `lta` (bool). Re-firmar un PDF ya firmado agrega `Firma2`, `Firma3`, etc.
- `POST /verify`: valida **offline** (sin descargar nada y con revocación `hard-fail`) usando sólo lo que viene en el DSS. Que pase esta validación demuestra que la firma es LT. Confía en la raíz de la PoC y en las de `src/pades_lt_poc/trust/` (las AC Raíz de Argentina de 2007 y 2016), aceptando SHA-1 sólo en lo que firma la raíz de 2007. Valida a la hora actual; con `validation_time=claimed_signing_time` valida cada firma a la hora que ella misma declara (no probada), y la respuesta lo indica en `validation_time` y en el `validated_at` de cada firma. Cada firma trae en `modifications` el análisis de los cambios posteriores (si es sospechoso, `bottom_line` da `false`); con `diff_policy=allow_unallocated_free_entries` se toleran las entradas libres de objetos que nunca existieron, que iText genera a veces.
- `POST /certificates`: recibe `pdf` y, por cada firma (incluidos los DocTimeStamp) **criptográficamente válida**, devuelve la cadena hoja → raíz armada con los certificados del propio PDF (CMS + DSS). Si el PDF no trae algún emisor (es habitual que sólo embeba el del firmante), lo descarga de la URL **AIA caIssuers** del certificado; se desactiva con `fetch_missing=false`. Cada certificado trae `type` (`end_entity`, `intermediate`, `root`), `source` (`cms`, `dss` o `aia`), `self_signed` y `der_b64` (el `.crt` en DER, base64). Cada firma incluye también `signature_timestamp`, con la hora y la cadena de la TSA que la selló. No exige confianza: también extrae cadenas de PKIs ajenas.
- `POST /certificates/inspect`: recibe un archivo `crt` (DER, PEM o PKCS#7) **o** un campo `b64` (el base64 de un DER, como el `der_b64` de `/certificates`, o un PEM), uno solo de los dos. Devuelve en `certificates` el detalle de cada certificado: sujeto y emisor atributo por atributo, `validity` (con `status` `valid`/`expired`/`not_yet_valid` y `days_left`), `is_ca`, `self_signed`, algoritmo de firma, clave pública, huellas y `extensions` (cada una con `oid`, `name`, `critical` y sus `values` como texto).
- `GET /ui/firmas` y `GET /ui/certificado`: las pantallas de la [UI](#ui). `GET /` y `GET /ui` redirigen a `/ui/firmas`, y `GET /docs` es el Swagger.

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
