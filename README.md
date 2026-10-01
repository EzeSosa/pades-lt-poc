# PoC PAdES B-LT con FastAPI + pyHanko

Firma PDFs en **PAdES B-LT** (opcionalmente **B-LTA**) usando una mini PKI de dos niveles, un respondedor OCSP y una TSA RFC 3161, todo servido por la misma app.

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
uv run pades-lt-poc                  # http://127.0.0.1:8000  (Swagger en /docs)
uv run python scripts/demo.py        # firma out/documento.pdf y lo verifica
uv run python scripts/demo.py --lta  # idem, en B-LTA
```

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

La PKI, con sus claves, vive en el volumen `/data`. `PUBLIC_BASE_URL` queda **grabada en los certificados** (URLs de CRL, AIA y OCSP) al generarse la PKI, así que tiene que ser alcanzable desde el propio contenedor (la app se consulta a sí misma al firmar) y desde quien valide las firmas. Si la cambiás, regenerá la PKI con `down -v`.

## Endpoints

- `GET  /pki/{root|intermediate}.crt`: certificados de las CAs en PEM. Importá `root.crt` como confiable en Adobe Reader para ver la firma en verde.
- `GET  /pki/{root|intermediate}.crl`: CRLs en DER, regeneradas en cada request (validez de 1 día).
- `POST /ocsp`, `GET /ocsp/{base64}`: respondedor OCSP (RFC 6960) para los certificados emitidos por la intermedia. Devuelve el nonce si el pedido lo trae.
- `POST /pki/revoke/{intermediate|signer|tsa}` y `POST /pki/unrevoke-all`: para probar los casos negativos.
- `POST /tsa`: TSA RFC 3161 (`application/timestamp-query` → `application/timestamp-reply`).
- `POST /sign`: recibe `pdf` (archivo), `reason`, `location` y `lta` (bool). Re-firmar un PDF ya firmado agrega `Firma2`, `Firma3`, etc.
- `POST /verify`: valida **offline** (sin descargar nada y con revocación `hard-fail`) usando sólo lo que viene en el DSS. Que pase esta validación demuestra que la firma es LT.
- `POST /certificates`: recibe `pdf` y, por cada firma (incluidos los DocTimeStamp) **criptográficamente válida**, devuelve la cadena hoja → raíz armada con los certificados del propio PDF (CMS + DSS). Si el PDF no trae algún emisor (es habitual que sólo embeba el del firmante), lo descarga de la URL **AIA caIssuers** del certificado; se desactiva con `fetch_missing=false`. Cada certificado trae `type` (`end_entity`, `intermediate`, `root`), `source` (`cms`, `dss` o `aia`), `self_signed` y `der_b64` (el `.crt` en DER, base64). Cada firma incluye también `signature_timestamp`, con la hora y la cadena de la TSA que la selló. No exige confianza: también extrae cadenas de PKIs ajenas.

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
