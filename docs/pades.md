# Firmas PAdES: conceptos y funcionamiento en esta API

Este documento explica cómo funciona una firma PAdES y define cada concepto que aparece en la PoC: desde la criptografía de base hasta la estructura interna del PDF firmado. Cada sección termina indicando **dónde aparece el concepto en el código**.

Índice:

1. [Visión general](#1-visión-general)
2. [Criptografía de base](#2-criptografía-de-base)
3. [Certificados X.509 y PKI](#3-certificados-x509-y-pki)
4. [Revocación: CRL y OCSP](#4-revocación-crl-y-ocsp)
5. [Sellos de tiempo (RFC 3161)](#5-sellos-de-tiempo-rfc-3161)
6. [Cómo se firma un PDF](#6-cómo-se-firma-un-pdf)
7. [CMS: el contenedor de la firma](#7-cms-el-contenedor-de-la-firma)
8. [PAdES y sus niveles](#8-pades-y-sus-niveles)
9. [Flujo de `/sign` paso a paso](#9-flujo-de-sign-paso-a-paso)
10. [Flujo de `/verify` e interpretación del resultado](#10-flujo-de-verify-e-interpretación-del-resultado)
11. [Casos negativos: revocación](#11-casos-negativos-revocación)
12. [Glosario](#12-glosario)
13. [Referencias normativas](#13-referencias-normativas)

---

## 1. Visión general

**PAdES** (*PDF Advanced Electronic Signatures*) es el estándar europeo (ETSI EN 319 142) que define cómo meter una firma electrónica avanzada dentro de un PDF para que pueda validarse **durante años**, incluso después de que venzan los certificados, cierre la CA o se apaguen los servidores de revocación.

Para lograrlo, una firma PAdES completa lleva adentro del PDF no sólo la firma en sí, sino también **las pruebas necesarias para validarla**:

| Pregunta del validador                          | Qué la responde                         | Nivel PAdES |
|-------------------------------------------------|-----------------------------------------|-------------|
| ¿Quién firmó y el documento cambió después?     | Firma CMS + certificado del firmante    | B-B         |
| ¿Cuándo existía esa firma?                      | Sello de tiempo de una TSA              | B-T         |
| ¿El certificado era válido y no estaba revocado? | Cadena + respuestas OCSP + CRLs (DSS)   | B-LT        |
| ¿Cómo sé que esas pruebas no se alteraron?      | Sello de tiempo sobre todo el documento | B-LTA       |

Esta PoC levanta **todas las piezas de infraestructura** en una sola app FastAPI:

```
                       ┌──────────────────────────── app FastAPI ────────────────────────────┐
  cliente ── PDF ──▶   │  POST /sign ──▶ pyHanko ──┬──▶ POST /tsa     (sello de tiempo)        │
                       │                           ├──▶ POST /ocsp    (estado de firmante/TSA) │
  cliente ◀─ PDF ──    │                           └──▶ GET  /pki/*.crl (estado de la intermedia)│
   firmado             │                                                                     │
                       │  POST /verify ──▶ pyHanko (offline, u online bajando CRL/OCSP)      │
                       └─────────────────────────────────────────────────────────────────────┘
```

Al firmar, la app **se consulta a sí misma** por HTTP como si la TSA, el OCSP y las CRLs fueran servicios externos. Por eso `PUBLIC_BASE_URL` tiene que ser alcanzable desde el propio proceso.

Además sirve una UI web (`/ui/firmas`, ver el [README](../README.md#ui)): se sube el PDF una vez y tres tabs muestran lo que devuelven `POST /certificates`, `POST /verify` y `POST /certificates/inspect`. Un certificado suelto se inspecciona aparte, en `/ui/certificado`, y la fuente de certificados se administra en `/ui/fuente`. Son páginas estáticas que llaman a esos endpoints desde el navegador y no agregan lógica: todo lo que muestran sale de las respuestas descriptas en la [sección 10](#10-flujo-de-verify-e-interpretación-del-resultado).

---

## 2. Criptografía de base

### Función hash (resumen criptográfico)

Función que convierte datos de cualquier tamaño en un valor de tamaño fijo (el *digest*). Es de un solo sentido y resistente a colisiones: cambiar un bit del documento cambia completamente el resumen. Se firma el hash, no el documento entero.

> En el código: `md_algorithm="sha256"` en [services/signing.py](../src/pades_lt_poc/services/signing.py). Todos los certificados, CRLs y respuestas OCSP también se firman con SHA-256.

### Criptografía asimétrica

Cada entidad tiene un **par de claves**: una **privada** (secreta, sólo la usa el dueño para firmar) y una **pública** (se distribuye, sirve para verificar). Lo que se firma con la privada sólo se verifica con la pública correspondiente.

> En el código: todas las claves son RSA de 3072 bits (`_new_key()` en [pki.py](../src/pades_lt_poc/pki.py)).

### Firma digital

Resultado de cifrar el hash de los datos con la clave privada. Verificarla implica recalcular el hash, descifrar la firma con la clave pública y comparar. Garantiza:

- **Integridad**: los datos no cambiaron.
- **Autenticidad**: los firmó quien tiene la clave privada.
- **No repudio**: el firmante no puede negar haber firmado (si la clave estuvo bajo su control exclusivo).

La firma digital por sí sola **no dice quién es el dueño de la clave**. Para eso existen los certificados.

---

## 3. Certificados X.509 y PKI

### Certificado X.509

Documento electrónico, firmado por una Autoridad Certificante, que **vincula una clave pública con una identidad**. Contiene, entre otros: sujeto (*subject*), emisor (*issuer*), número de serie, período de validez (`notBefore` / `notAfter`), clave pública y extensiones.

En la PoC todos los sujetos tienen la forma `C=AR, O=PoC PAdES, CN=<nombre>`.

### Autoridad Certificante (CA)

Entidad que emite y firma certificados, y que mantiene información sobre cuáles revocó.

- **CA raíz**: su certificado es **autofirmado** (emisor = sujeto). Nadie la avala; se confía en ella por decisión explícita.
- **CA intermedia**: su certificado lo firma la raíz. Emite los certificados finales. Permite que la raíz quede *offline* (en la PoC está online, ver Limitaciones del README).

### Certificado final (hoja, *end-entity*)

Certificado que no puede emitir otros certificados (`BasicConstraints ca=False`). En la PoC hay tres:

| Hoja                         | Para qué se usa                                    |
|------------------------------|----------------------------------------------------|
| Firmante de Prueba           | Firmar los PDFs                                    |
| PoC Time Stamping Authority  | Firmar los sellos de tiempo                        |
| PoC OCSP Responder           | Firmar las respuestas OCSP                         |

### PKI (Infraestructura de Clave Pública)

Conjunto de CAs, certificados, políticas y servicios de revocación. La de esta PoC:

```
PoC Root CA  (autofirmada, 10 años)             publica /pki/root.crl
 └── PoC Intermediate CA  (5 años)              publica /pki/intermediate.crl + OCSP en /ocsp
      ├── Firmante de Prueba            (2 años)
      ├── PoC Time Stamping Authority   (2 años)
      └── PoC OCSP Responder            (2 años)
```

Se genera sola la primera vez que arranca la app (`ensure_pki()`), y queda en `$PKI_DIR`.

### Cadena de certificación y ancla de confianza

La **cadena** (o *camino de certificación*) es la secuencia `hoja → intermedia → raíz` en la que cada certificado está firmado por el siguiente. El **ancla de confianza** (*trust anchor*) es el certificado en el que el validador confía por configuración, sin verificar a nadie más arriba.

**Validar un camino** (RFC 5280 §6) significa comprobar, para cada eslabón: la firma del emisor, las fechas de validez, las extensiones (que una CA sea realmente CA, que la clave tenga el uso correcto) y el estado de revocación.

> En el código: `PdfSigner.trust_root` es el ancla de confianza al firmar. Al verificar (`SignatureVerifier.trust_roots()`) se suman las raíces confiables de la **fuente de certificados** (`CertificateStore`, una tabla SQLite que se administra por `/store/certificates`); su carga inicial trae las dos *AC Raíz* de Argentina (2007 y 2016, ver [Rotación de la raíz](#rotación-de-la-raíz)), de `src/pades_lt_poc/seed/`. Para que Adobe Reader muestre la firma en verde, hay que importar `root.crt` como confiable.

### Rotación de la raíz

Que la raíz sea el ancla de confianza no la hace eterna. Su confianza no se deriva de otra firma (su autofirma es una convención de formato), sino de que alguien decidió **distribuirla e instalarla** como confiable. Y se rota, por varios motivos:

- **Vencimiento**: las raíces duran mucho (20 a 25 años), pero no para siempre. La *AC Raíz* de Argentina vigente al escribir esto es válida del **22/11/2007 al 17/11/2027**.
- **Algoritmos que envejecen**: una raíz de 2007 nació con SHA-1 y RSA. Rotarla es la única forma de migrar a SHA-256, a curvas elípticas o, más adelante, a algoritmos poscuánticos. Es lo que se ve en la PKI argentina: `cryptography` ya no verifica sus firmas SHA-1 (ver sección 4).
- **Riesgo acumulado sobre la clave**: cuantos más años en uso, más oportunidades de que se filtre.
- **Cambios de política u organización**: quién opera la PKI, qué perfiles usa o qué exige la normativa.

**Cómo se rota sin romper nada:**

1. Se genera la raíz nueva **con años de anticipación** y se distribuye a los almacenes de confianza (sistemas operativos, navegadores, Adobe, validadores).
2. **Certificación cruzada**: la raíz vieja firma un certificado para la clave de la nueva, y a veces también al revés (*oldWithNew* / *newWithOld*, RFC 4210). Así, durante la transición, quien sólo confía en una puede llegar a la otra.
3. Las CAs operativas (en el caso argentino, la de la ONTI) se **reemiten** bajo la raíz nueva, y los certificados nuevos salen bajo esa cadena.
4. La raíz vieja **se conserva** en los almacenes para seguir validando lo firmado con ella.

**Qué pasa con las firmas viejas**: el vencimiento de la raíz no invalida automáticamente lo firmado antes, si se cumplen dos condiciones:

- **El validador conserva la raíz vieja.** Para RFC 5280 un ancla de confianza es un nombre y una clave pública, y su vencimiento no forma parte de la validación del camino. Muchos validadores lo ignoran, aunque otros no.
- **Se puede probar que se firmó cuando todo era válido.** Eso lo dan el sello de tiempo (B-T) y su renovación (B-LTA). Sin sello, el validador evalúa la firma a la fecha actual, con la cadena ya vencida.

Es una razón más por la que una firma B-B, sin sello ni DSS, es frágil a largo plazo: cuando venza la raíz sólo se podrá validar si el validador acepta evaluarla en una fecha pasada que nadie certificó.

**El caso argentino**: hoy conviven dos raíces, y `/verify` confía en ambas (vienen en la carga inicial de la fuente de certificados):

| | *AC Raíz* (2007) | *AC Raíz de la República Argentina* (2016) |
|---|---|---|
| Vigencia | 22/11/2007 al 17/11/2027 | 30/06/2016 al 30/06/2036 |
| Firma | RSA 4096 con **SHA-1** | RSA 4096 con **SHA-512** |
| Clave | Distinta | Distinta (no hay certificación cruzada entre ellas) |
| CRL | `acraiz.cdp1.gov.ar/ca.crl` | `acraiz.cdp1.gov.ar/acraizra.crl` |
| Emite a | La CA de la ONTI (de ahí cuelgan CiDi y los tokens de la AC ONTI) | Certificadores licenciados como AC2-LAKAUT (firmantes de empresas y la TSA) |
| SHA-256 | `CC85ED49…5B3BD463` | `975C6635…1E9F8BA4` |

Ambas se descargaron de los enlaces de la [página oficial de la AC Raíz](https://www.argentina.gob.ar/jefatura/innovacion-ciencia-y-tecnologia/innovacion/firma-digital/ac-raiz) (`https://acraiz.gov.ar/ca.crt` y `.../acraizra.crt`). Un ancla de confianza nunca se toma del PDF que se está validando.

### Extensiones usadas en la PoC

| Extensión | Qué indica | Dónde se usa |
|-----------|------------|--------------|
| **BasicConstraints** | Si el certificado es de una CA y cuántos niveles puede tener debajo (`path_length`). | Raíz `ca=True, path_length=1`; intermedia `path_length=0` (sólo puede emitir hojas); hojas `ca=False`. |
| **KeyUsage (KU)** | Operaciones permitidas para la clave. | CAs: `keyCertSign` + `cRLSign`. Firmante: `digitalSignature` + `nonRepudiation` (`content_commitment` en `cryptography`). TSA y OCSP: `digitalSignature`. |
| **ExtendedKeyUsage (EKU)** | Propósito específico de la clave. | TSA: `timeStamping`, **única y crítica** (lo exige RFC 3161 §2.3). OCSP: `OCSPSigning`. |
| **SubjectKeyIdentifier / AuthorityKeyIdentifier** | Identificadores (hash de la clave pública) del sujeto y del emisor. Permiten encadenar certificados sin ambigüedad. | Todos los certificados; el AKI también va en las CRLs. |
| **CRL Distribution Points (CDP)** | URL donde descargar la CRL que cubre a este certificado. | Intermedia → `/pki/root.crl`; firmante y TSA → `/pki/intermediate.crl`. |
| **Authority Information Access (AIA)** | URLs del certificado del emisor (`caIssuers`) y del respondedor OCSP. | Intermedia: sólo `caIssuers`. Firmante y TSA: `caIssuers` + OCSP en `/ocsp`. |
| **id-pkix-ocsp-nocheck** | "No verifiques la revocación de este certificado". | Sólo en el respondedor OCSP (ver [OCSP](#ocsp-online-certificate-status-protocol)). |

**Crítica**: una extensión marcada como crítica que el validador no entienda hace que rechace el certificado.

> En el código: `_build_root`, `_build_intermediate` y `_build_leaf` en [pki.py](../src/pades_lt_poc/pki.py).

---

## 4. Revocación: CRL y OCSP

Un certificado puede dejar de ser confiable antes de su vencimiento (clave comprometida, cese de funciones, etc.). La CA lo **revoca** y publica esa información por uno o ambos mecanismos.

### CRL (Certificate Revocation List)

Lista firmada por la CA con los números de serie revocados y la fecha de revocación de cada uno. Campos clave:

- **thisUpdate / lastUpdate**: cuándo se emitió.
- **nextUpdate**: hasta cuándo se considera vigente. Pasada esa fecha, un validador estricto no la acepta.
- **CRLNumber**: número creciente que identifica la versión.

Cada entrada puede llevar además el **motivo** (`reasonCode`): clave comprometida, cese de actividad, reemplazo, etc.

**Cómo se lee**: la CRL responde *por omisión*. Si el serial **no aparece**, el certificado no estaba revocado a la fecha `thisUpdate`. Nunca lista los certificados válidos, sólo los revocados, y se descarga entera aunque interese uno solo.

Ventaja: se puede cachear y distribuir. Desventaja: crece con cada revocación y su frescura depende de `nextUpdate`.

> En el código: `build_crl()` en [pki.py](../src/pades_lt_poc/pki.py) genera una CRL **nueva en cada request**, con validez de 1 día y `CRLNumber` igual al timestamp Unix. Se sirve en DER (`application/pkix-crl`) en `GET /pki/{root|intermediate}.crl`.

### OCSP (Online Certificate Status Protocol)

Protocolo (RFC 6960) para preguntar el estado de **un** certificado puntual. El cliente manda un pedido con el `CertID` y el respondedor devuelve una respuesta firmada con uno de tres estados: `good`, `revoked` o `unknown`.

- **CertID**: identifica al certificado consultado mediante el algoritmo de hash, el `issuerNameHash`, el `issuerKeyHash` (hash de la clave pública del emisor) y el número de serie.
- **certStatus**: `good` (no está revocado), `revoked` (con fecha y motivo) o `unknown` (el respondedor no conoce ese certificado). Ojo: `good` **no significa "certificado válido"**, sólo "no figura como revocado". El vencimiento, la cadena y el uso permitido se verifican aparte.
- **producedAt**: cuándo se generó la respuesta.
- **thisUpdate / nextUpdate**: ventana de validez de la respuesta. En la PoC: desde 1 minuto antes hasta 12 horas después.
- **Nonce**: valor aleatorio que el cliente pone en el pedido y el respondedor devuelve, para evitar que alguien reenvíe (*replay*) una respuesta vieja. La PoC lo copia si viene.
- **Estado de respuesta**: además del estado del certificado, la respuesta tiene un estado global: `successful`, `malformedRequest`, `unauthorized`, etc. La PoC devuelve `malformedRequest` si no puede parsear el pedido y `unauthorized` si le preguntan por un certificado que no es el firmante ni la TSA, o si el `issuerKeyHash` no coincide con la intermedia.

**Respondedor delegado** (RFC 6960 §4.2.2.2): la respuesta OCSP no la firma la CA directamente sino un certificado emitido por ella con EKU `OCSPSigning`. El validador acepta la respuesta porque el certificado del respondedor fue emitido por la misma CA que el certificado consultado.

**`ocsp-nocheck`**: si el respondedor tuviera que validarse por OCSP, sería un círculo vicioso. Esta extensión le indica al validador que no consulte su revocación. La contrapartida es que el certificado del respondedor debería tener una vida corta.

> En el código: `ocsp_respond()` en [pki.py](../src/pades_lt_poc/pki.py). Endpoints `POST /ocsp` (cuerpo DER) y `GET /ocsp/{base64}` (RFC 6960 Apéndice A.1). Se puede contrastar con OpenSSL (ver README).

### Qué mecanismo cubre a cada certificado en la PoC

| Certificado     | Revocación verificada por                        |
|-----------------|--------------------------------------------------|
| Raíz            | No aplica: es el ancla de confianza.             |
| Intermedia      | CRL de la raíz.                                  |
| Firmante y TSA  | OCSP (la CRL de la intermedia queda de respaldo). |
| Respondedor OCSP | No se verifica (`ocsp-nocheck`).                |

Esto está hecho a propósito para que el DSS termine teniendo **ambos tipos** de información de revocación.

### Respuestas embebidas: evidencia que se autentica sola

Una CRL y una respuesta OCSP son **documentos firmados** por la CA (o por su respondedor delegado). Una vez descargados no hace falta volver a consultar a la CA: cualquiera puede comprobar después, **offline**, que la respuesta es auténtica y no fue alterada, porque su firma encadena hasta la raíz.

Funcionan como un **certificado de libre deuda**: la CA declara y firma "a tal fecha, este certificado no está revocado". Ese papel se archiva junto al documento y se puede presentar años después, aunque la CA haya apagado su servidor OCSP o ya no exista. Por eso se pueden guardar dentro del PDF:

- en el **DSS** (`/OCSPs` y `/CRLs`), en una actualización incremental posterior a la firma. Es lo que hace B-LT y lo que hace esta PoC.
- en el atributo firmado **`adbe-revocationInfoArchival`** del CMS: la forma más antigua que usaba Adobe. Como queda bajo la firma, hay que obtener la información **antes** de firmar.

Al validar, el verificador no consulta la red. Comprueba:

1. **Autenticidad**: la firma de la respuesta encadena a la CA (o a un respondedor delegado autorizado por ella).
2. **Correspondencia**: la respuesta es sobre **este** certificado (serial, y en OCSP también los hashes del emisor del `CertID`).
3. **Tiempo**: la respuesta es **posterior al momento de la firma** y dice que el certificado no estaba revocado.

El punto 3 necesita conocer **con certeza** el momento de la firma, y eso lo da el sello de tiempo (B-T). Sin sello, la respuesta prueba el estado a la fecha de la respuesta, pero no se puede atar a cuándo se firmó. Por eso B-LT exige B-T: los niveles son acumulativos.

### ¿Para qué una CRL si hay OCSP?

Es cierto que OCSP suele usarse primero y la CRL como *fallback* cuando el respondedor no responde. Pero en el DSS no se incluyen "por las dudas": B-LT exige información de revocación de **cada** certificado de la cadena salvo el ancla de confianza, y OCSP y CRL suelen cubrir **certificados distintos**:

- **Certificados finales** (firmante, TSA): los cubre el **OCSP** de la CA emisora. Es rápido y puntual, y hay muchos certificados por consultar.
- **CAs intermedias**: las cubre la **CRL de la raíz**. La raíz casi nunca opera un respondedor OCSP: suele estar *offline* y sólo se enciende para emitir CAs y firmar su CRL, que se publica con validez larga.

Así, una firma de una PKI típica de dos niveles termina con OCSP para la hoja **y** CRL para la intermedia. Es lo que pasa en la PoC (2 respuestas OCSP y 1 CRL, ver la tabla de arriba), y también en la PKI argentina: la AC Raíz publica CRL para las CAs que emite, y la CA de la ONTI ofrece OCSP y CRL para los certificados de usuario.

Para un **mismo** certificado alcanza con uno de los dos. Embeber ambos es redundante aunque no está prohibido: puede servir si se teme que algún validador rechace la respuesta OCSP (por ejemplo, por cómo está emitido el certificado del respondedor).

### ¿Quién firma cada respuesta?

- **CRL**: la firma la **misma CA que emitió los certificados que lista**. La CRL de la raíz la firma la raíz; la de la intermedia, la intermedia. (RFC 5280 admite *CRLs indirectas*, firmadas por otra entidad indicada en `cRLIssuer`, pero son raras.)
- **OCSP**: según RFC 6960 §4.2.2.2, la respuesta puede firmarla:
  1. la propia **CA emisora** del certificado consultado;
  2. un **respondedor delegado**: un certificado emitido por esa CA con EKU `OCSPSigning`, que suele venir embebido en la respuesta;
  3. un respondedor en el que el verificador confía por configuración local (poco común).

El esquema habitual es el delegado: la clave de la CA queda protegida y se usa poco (emitir certificados y firmar la CRL), mientras que el respondedor, que está en línea contestando miles de consultas, usa otra clave de vida corta. Si se comprometiera, el daño se limita a respuestas OCSP y la CA sólo tiene que emitir otro respondedor. Con `ocsp-nocheck` el verificador no consulta la revocación del propio respondedor.

#### Caso real: PKI de firma digital de Argentina

Consultado el 30/09/2026 con un certificado de Ciudadano Digital (CiDi, Córdoba), cuya cadena es CiDi → *Autoridad Certificante de Firma Digital* (ONTI) → *AC Raíz*:

| Certificado consultado | Mecanismo                                         | Firmado por                                                                                                                 | Observaciones                                                     |
|------------------------|---------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|
| CA de la ONTI          | CRL `http://acraiz.cdp1.gov.ar/ca.crl` (y `cdp2`) | AC Raíz (SHA-1)                                                                                                             | Validez de 6 meses, 3 revocados. La ONTI no tiene OCSP.           |
| Firmante CiDi          | OCSP `http://pki.jgm.gov.ar/ocsp`                 | Respondedor delegado `CN=ANPKIWFES001V.NACPKIN.AR`, emitido por la ONTI, con EKU `OCSPSigning` y `ocsp-nocheck`, embebido en la respuesta | Es el mismo esquema que el "PoC OCSP Responder" de esta PoC.       |
| Firmante CiDi          | CRL `http://pki.jgm.gov.ar/crl/FD.crl`            | CA de la ONTI                                                                                                               | Validez de 1 día, unas 240.000 entradas: de ahí que se prefiera OCSP. |

Los números confirman lo de la sección anterior: la raíz, *offline*, publica una CRL chica y de larga duración; la CA operativa publica una CRL enorme y diaria, y ofrece OCSP para no obligar a descargarla.

> **SHA-1**: la AC Raíz firma con SHA-1 tanto a la CA de la ONTI como a su CRL. `cryptography` no verifica SHA-1 (`verify_directly_issued_by` lanza `Unsupported signature algorithm` y `is_signature_valid()` devuelve `False`), aunque verificadas a mano las firmas son correctas. `/certificates` lo resuelve para armar la cadena (ver sección 10). `/verify` relaja la política de algoritmos débiles de pyHanko sólo para la clave de la AC Raíz (`LegacyRootsPolicy`): acepta SHA-1 en los certificados y CRLs que ella firma, y lo sigue rechazando en firmantes, TSAs y demás CAs. Un upgrade a LT de firmas de esta PKI necesitaría además incluir en el DSS el certificado del respondedor OCSP.

### Hard-fail y soft-fail

Política del validador cuando **no puede obtener** información de revocación:

- **soft-fail**: si no la consigue, asume que el certificado es válido.
- **hard-fail**: si no la consigue, la validación falla.

> En el código: tanto `/sign` como `/verify` usan `revocation_mode="hard-fail"`.

---

## 5. Sellos de tiempo (RFC 3161)

### El problema

La fecha que figura en la firma la pone el propio firmante (su reloj), así que no prueba nada. Además, el día que el certificado del firmante venza o se revoque, hay que poder demostrar que la firma se hizo **antes**.

### TSA (Time Stamping Authority)

Tercero de confianza que certifica que **un dato existía en un momento determinado**. No ve el dato, sólo su hash.

### Protocolo

1. El cliente calcula el hash del dato y arma un **TimeStampReq** con el `messageImprint` (algoritmo + hash) y, opcionalmente, un nonce y `certReq`. Content-Type: `application/timestamp-query`.
2. La TSA responde un **TimeStampResp** (`application/timestamp-reply`) que contiene un **TimeStampToken**: una estructura CMS firmada por la TSA cuyo contenido es un **TSTInfo**.
3. El **TSTInfo** incluye: el `messageImprint` recibido, la hora (`genTime`), un número de serie, el OID de la **política** de la TSA y el nonce si vino.

Validar un sello implica validar la firma de la TSA y su cadena (incluida la revocación), y comprobar que el `messageImprint` coincide con el hash del dato sellado.

### Usos en PAdES

| Tipo de sello | Qué se sella | Dónde queda | Nivel |
|---------------|--------------|-------------|-------|
| **Signature timestamp** | El valor de la firma del firmante | Atributo no firmado `signature-time-stamp-token` dentro del CMS | B-T |
| **Document timestamp** | Todo el PDF (incluido el DSS) | Un campo de firma propio, de tipo `/DocTimeStamp` | B-LTA |

> En el código: `POST /tsa` ([routers/tsa.py](../src/pades_lt_poc/routers/tsa.py)) expone el `DummyTimeStamper` de pyHanko (toma la hora del servidor y usa un OID de política de ejemplo). La firma lo consume con `HTTPTimeStamper(tsa_url)` como si fuera una TSA externa. Los tokens incluyen la cadena `tsa → intermedia → raíz`.

---

## 6. Cómo se firma un PDF

### Estructura de un PDF

Un PDF es una colección de **objetos** numerados (diccionarios, streams, arrays…), una **tabla de referencias cruzadas** (`xref`) que indica en qué byte empieza cada objeto, y un **trailer** que apunta al objeto raíz (el **catálogo**, `/Root`).

### Actualización incremental y revisiones

Modificar un PDF firmado reescribiéndolo rompería la firma. Por eso los cambios se agregan **al final del archivo**: nuevos objetos, una nueva `xref` y un nuevo trailer que apunta a la anterior. Los bytes previos quedan intactos. Cada bloque agregado es una **revisión**.

Una firma cubre una revisión concreta. Las revisiones posteriores pueden agregar cosas permitidas (otra firma, el DSS, un sello de documento) sin invalidar las anteriores.

El PDF B-LTA de ejemplo (`out/documento-pades-lta.pdf`) tiene **4 revisiones**:

```
Rev 1  PDF original
Rev 2  + campo Firma1 con la firma CMS (con su signature timestamp)       ← B-T
Rev 3  + DSS con certificados, respuestas OCSP y CRLs                     ← B-LT
       + campo de firma /DocTimeStamp, que cubre el archivo con ese DSS   ← B-LTA
Rev 4  + DSS actualizado: agrega la entrada VRI del /DocTimeStamp
```

Un PDF B-LT termina con el DSS de la revisión 3, sin sello de documento.

> En el código: `IncrementalPdfFileWriter` en `/sign`.

### Campo de firma y diccionario de firma

La firma vive en un **campo de formulario** (AcroForm) de tipo firma, cuyo valor (`/V`) es un **diccionario de firma**. Entradas relevantes:

| Entrada | Significado | Valor en la PoC |
|---------|-------------|-----------------|
| `/Type` | `/Sig` para firmas, `/DocTimeStamp` para sellos de documento. | `/Sig` o `/DocTimeStamp` |
| `/Filter` | *Handler* preferido para validar. | `/Adobe.PPKLite` |
| `/SubFilter` | Formato del contenido firmado. | `/ETSI.CAdES.detached` (firma) o `/ETSI.RFC3161` (sello de documento) |
| `/ByteRange` | Qué bytes del archivo cubre la firma. | ver abajo |
| `/Contents` | La firma CMS en hexadecimal. | ~13,8 KB en la firma de ejemplo |
| `/M` | Hora de firma declarada por el firmante (no confiable, ver B-T). | hora del servidor |
| `/Reason`, `/Location` | Motivo y lugar, informativos. | form `reason` y `location` |

`/SubFilter /ETSI.CAdES.detached` es **lo que distingue una firma PAdES** de una firma PDF "clásica" (`/adbe.pkcs7.detached`).

### ByteRange

El firmante no puede firmar el archivo entero porque la firma misma va adentro. Entonces se reserva un hueco para `/Contents` y se firma todo lo demás. El `/ByteRange` son dos pares `[inicio1 largo1 inicio2 largo2]`.

En la firma de ejemplo: `[0, 1087, 28715, 640]`

```
byte 0 ─────────── 1087 │ 1087 ──── <Contents hex> ──── 28715 │ 28715 ─────── 29355
     cubierto por firma │           NO cubierto               │ cubierto por firma
```

El hueco (27.628 caracteres hex) es exactamente el `/Contents`. El validador hashea los dos tramos y compara con el digest que está dentro del CMS.

### Cobertura (*coverage*)

Qué porción del archivo final cubre una firma, según pyHanko:

- `ENTIRE_FILE`: la firma cubre todo el archivo (es la última revisión).
- `ENTIRE_REVISION`: cubre su revisión completa, pero después se agregaron revisiones. Es lo esperable para `Firma1` en un B-LT o B-LTA, porque el DSS (y el sello de documento) vienen después.
- `CONTIGUOUS_BLOCK_FROM_START` / `UNCLEAR`: casos anómalos.

### Co-firma

Firmar un PDF ya firmado agrega **otro campo de firma** en una nueva revisión. Las firmas previas siguen siendo válidas porque sus bytes no se tocaron.

> En el código: `field_name = f"Firma{len(writer.prev.embedded_signatures) + 1}"` genera `Firma1`, `Firma2`, etc.

---

## 7. CMS: el contenedor de la firma

### CMS / PKCS#7 SignedData

**CMS** (*Cryptographic Message Syntax*, RFC 5652) es el formato binario (ASN.1/DER) que contiene la firma. Su estructura `SignedData` incluye:

- `encapContentInfo`: el contenido firmado. En modo **detached** va vacío: el contenido (los bytes del `/ByteRange`) está fuera del CMS.
- `certificates`: certificados que ayudan a construir la cadena. En la PoC: firmante, intermedia y raíz (3).
- `signerInfos`: por cada firmante, el algoritmo, los atributos firmados, la firma y los atributos no firmados.

**CAdES** (*CMS Advanced Electronic Signatures*, ETSI EN 319 122) es el perfil de CMS para firmas avanzadas. PAdES reutiliza CAdES dentro del PDF.

### Atributos firmados (*signed attributes*)

Van dentro de lo que se firma, así que quedan protegidos por la firma. En la firma de ejemplo:

| Atributo | Para qué sirve |
|----------|----------------|
| `content-type` | Tipo del contenido firmado (`data`). |
| `message-digest` | Hash SHA-256 de los bytes del `/ByteRange`. Es lo que vincula el CMS con el PDF. |
| `signing-certificate-v2` | Hash del certificado del firmante. Impide sustituirlo por otro certificado con la misma clave. **Obligatorio en PAdES.** |

**No** hay atributo `signing-time`: PAdES baseline lo prohíbe en el CMS y usa `/M` del diccionario de firma. La hora que cuenta es la del sello de tiempo.

### Atributos no firmados (*unsigned attributes*)

Se agregan después de firmar, sin invalidar la firma. En la PoC:

- `signature-time-stamp-token`: el TimeStampToken de la TSA sobre el valor de la firma. Es lo que convierte la firma en **B-T**.

---

## 8. PAdES y sus niveles

### Perfiles *baseline*

ETSI EN 319 142-1 define cuatro niveles acumulativos. Cada uno agrega pruebas al anterior:

| Nivel | Qué agrega | Qué problema resuelve | En el código |
|-------|------------|-----------------------|--------------|
| **B-B** (*Basic*) | Firma CMS con `SubFilter ETSI.CAdES.detached` y `signing-certificate-v2`. | Integridad y autoría. | `subfilter=SigSeedSubFilter.PADES` |
| **B-T** (*Timestamp*) | Signature timestamp de una TSA. | Prueba confiable de **cuándo** existía la firma. | `timestamper=HTTPTimeStamper(.../tsa)` |
| **B-LT** (*Long Term*) | DSS con todos los certificados y la información de revocación. | La firma se puede validar **sin conexión** y aunque la PKI ya no exista. | `embed_validation_info=True` + `validation_context` |
| **B-LTA** (*Long Term with Archive*) | Document timestamp sobre todo lo anterior. | Protege el DSS y permite **extender** la validez antes de que venzan el certificado de la TSA o los algoritmos. | `use_pades_lta=True` (form `lta=true`) |

### DSS (Document Security Store)

Diccionario `/DSS` en el catálogo del PDF, agregado en una revisión posterior a la firma. Es el "maletín de pruebas" de la validación a largo plazo:

| Entrada | Contenido | En el PDF de ejemplo |
|---------|-----------|----------------------|
| `/Certs` | Certificados necesarios para validar (DER). | 5: raíz, intermedia, firmante, TSA y respondedor OCSP |
| `/OCSPs` | Respuestas OCSP (DER). | 2: firmante y TSA |
| `/CRLs` | CRLs (DER). | 1: la de la raíz, que cubre a la intermedia |
| `/VRI` | *Validation Related Information*: índice por firma (clave = hash SHA-1 del `/Contents`) de qué certs/OCSP/CRL usa cada una. Opcional en PAdES baseline. | 2 entradas: `Firma1` y el `/DocTimeStamp` |

La CRL de la intermedia no aparece porque las respuestas OCSP ya cubren al firmante y a la TSA.

**Por qué va en el PDF y no en el CMS**: el DSS se escribe *después* de firmar porque hace falta validar también el sello de tiempo, que se obtiene al final. Ponerlo en el CMS obligaría a firmar de nuevo.

### Document timestamp (`/DocTimeStamp`)

Campo de firma especial con `/Type /DocTimeStamp` y `/SubFilter /ETSI.RFC3161`, cuyo `/Contents` es directamente un TimeStampToken (no hay firmante, sólo la TSA). Su `/ByteRange` cubre todo el archivo previo, incluido el DSS.

### Validación a largo plazo (LTV) y renovación

Con el tiempo pasan tres cosas que amenazan una firma: vence el certificado del firmante, vence (o se revoca) el certificado de la TSA, y los algoritmos criptográficos se debilitan.

- **B-LT** resuelve la primera: el sello de tiempo prueba que la firma existía cuando el certificado era válido, y el DSS trae la prueba de ese estado.
- **B-LTA** resuelve las otras dos: antes de que venza la TSA o se debilite SHA-256, se agrega un DSS actualizado (con la revocación de la TSA anterior) y un **nuevo** document timestamp con algoritmos vigentes. Cada sello protege a todos los anteriores. Así se puede encadenar indefinidamente.

La PoC agrega **un** document timestamp y después actualiza el DSS con su entrada VRI (el sello lo firma la misma TSA, así que sus certificados y su respuesta OCSP ya estaban). No implementa la **renovación periódica**: volver a sellar antes de que venzan la TSA o los algoritmos quedaría a cargo de un proceso de archivo.

---

## 9. Flujo de `/sign` paso a paso

`POST /sign` (multipart) recibe `pdf`, `reason`, `location` y `lta`, y devuelve el PDF firmado como `<nombre>-pades-lt.pdf`.

```
 cliente            /sign (pyHanko)                /tsa        /ocsp       /pki/root.crl
   │  PDF              │                              │            │              │
   │──────────────────▶│ 1. abre en modo incremental  │            │              │
   │                   │ 2. prepara Firma<N>, reserva │            │              │
   │                   │    /Contents y fija ByteRange│            │              │
   │                   │ 3. hashea ByteRange, arma    │            │              │
   │                   │    atributos firmados y firma│            │              │
   │                   │    con la clave del firmante │            │              │
   │                   │ 4. hash de la firma ────────▶│ TimeStampToken            │
   │                   │◀─────────────────────────────│            │              │
   │                   │    lo agrega como atributo no firmado     │              │
   │                   │    y escribe el CMS en /Contents   (rev 2, B-T)          │
   │                   │ 5. valida firmante y TSA ────────────────▶│ good         │
   │                   │    (hard-fail)                            │              │
   │                   │    valida la intermedia ─────────────────────────────────▶ CRL
   │                   │ 6. escribe /DSS con certs+OCSP+CRL        (rev 3, B-LT)  │
   │                   │ 7. [lta] document timestamp ─▶│ en la misma rev 3 (B-LTA)│
   │                   │    y actualiza el DSS con su VRI            (rev 4)      │
   │◀──────────────────│                              │            │              │
```

Detalles:

1. **Contexto de validación al firmar** (`ValidationContext(trust_roots=[root], allow_fetching=True, revocation_mode="hard-fail")`): pyHanko construye las cadenas del firmante y de la TSA, y **descarga** la revocación siguiendo las URLs de AIA (OCSP) y CDP (CRL) grabadas en los certificados. Si algo está revocado o no responde, la firma falla con **HTTP 422** y el motivo.
2. **Firmante**: `SimpleSigner` cargado al arrancar con la clave y el certificado del firmante más la cadena `intermedia, raíz`, que se embebe en el CMS.
3. **Valida antes de entregar**: gracias a `hard-fail`, `/sign` nunca devuelve un PDF con un firmante revocado.

---

## 10. Flujo de `/verify` e interpretación del resultado

`POST /verify` recibe un `pdf` y valida **offline**:

```python
ValidationContext(
    trust_roots=[root_poc, *raices_confiables_de_la_fuente],  # SignatureVerifier.trust_roots()
    other_certs=[*intermedios_de_la_fuente],                  # además de los del DSS
    allow_fetching=False,
    revocation_mode="hard-fail",
    algorithm_usage_policy=LegacyRootsPolicy([...]),  # SHA-1 sólo para las raíces que nacieron con SHA-1
    moment=...,  # ahora, o la hora declarada con validation_time=claimed_signing_time
)
```

cargado con el contenido del DSS del PDF. Sin descargas y con revocación obligatoria, **sólo pasa si toda la evidencia de revocación está dentro del PDF**. La fuente se lee en cada verificación, así que los cambios del ABM aplican enseguida.

### Con conexión (`revocation=online`)

Sin conexión, una firma sin sello de tiempo se valida a la hora actual con la revocación que trae el PDF, y esa revocación vence: la CRL de la AC ONTI, por ejemplo, dura un día. Pasado ese día la firma da "no confiable" aunque nada haya cambiado. Con `revocation=online`, `/verify` además **descarga** lo que haga falta de las URLs de cada certificado: CRLs (CRL Distribution Points), respuestas OCSP y emisores faltantes (AIA):

```python
ValidationContext(..., allow_fetching=True, fetchers=RevocationFetcherBackend(), time_tolerance=timedelta(minutes=2))
```

- **Sólo a la hora actual.** pyHanko no descarga para validar en el pasado (`moment` no se combina con `allow_fetching`): `validation_time=claimed_signing_time` con `online` da 422, y la UI fija el selector de hora en "Ahora".
- **El nivel no pasa de B-T.** Lo descargado dice si la firma es confiable *hoy*, no si el PDF alcanza solo. Para evaluar LT hay que validar sin conexión.
- **Qué se descargó** va en `revocation.fetched`: cada CRL (emisor y vigencia), cada respuesta OCSP (serie, estado y fecha) y cada emisor bajado por AIA. Un intermedio bajado por AIA no cuenta como `completed_from_store`.
- **Timeouts**: 10 s por OCSP o AIA y 60 s por CRL, porque la CRL de la AC ONTI pesa ~9 MB y tarda más de 10 s. Un timeout se trata como "no se pudo descargar" (`services/fetching.py`); en los fetchers de pyHanko tal cual, tira abajo toda la verificación.
- **Caché de CRLs**: una CRL descargada se guarda en memoria, por URL, hasta su `nextUpdate` (`CrlCache`, hasta 32). Antes de esa fecha la CA no publica otra, así que bajarla de nuevo no aporta nada. En el reporte, cada CRL dice si salió del caché (`from_cache`) y cuándo se descargó (`fetched_at`). Las respuestas OCSP no se cachean: son por certificado, chicas y rápidas.
- **Reloj**: las respuestas se emiten "ahora" según el reloj del servidor remoto. Con la tolerancia de 1 s de pyHanko, un par de segundos de desfasaje las vuelve "del futuro" (`OCSP response is too recent`), así que con conexión se toleran 2 minutos.

### CRLs grandes: índice de seriales

Para saber si un certificado está revocado, pyhanko-certvalidator recorre la lista de revocados de la CRL con asn1crypto, en Python, entrada por entrada (`validate_crl.find_cert_in_list`). Con la CRL de la AC ONTI (~9 MB, ~240 mil entradas) cada recorrido tarda ~2 s, y una verificación hace varios: uno por firma y por cada copia de la CRL (la del DSS y la descargada). Si el certificado no está revocado, que es lo común, el recorrido es completo. Medido con un PDF de CiDi: ~7 s de CPU sólo en eso.

`services/crl_index.py` reemplaza esa función (se instala al crear el `SignatureVerifier`, y sirve con y sin conexión). Arma con `cryptography`, cuyo parser es Rust, un índice de los seriales revocados de cada CRL (~0,15 s para la de la ONTI) y lo cachea por huella de la CRL (hasta 16). Es la misma idea que el parser por *stream* de DSS: no materializar cada entrada en objetos para buscar un serial.

- Serial ausente: se responde enseguida.
- Serial presente: se delega en la función original, que arma la fecha y el motivo y controla las extensiones críticas con su semántica exacta. Es el caso raro.
- CRL indirecta (alguna entrada con `certificateIssuer`) o que `cryptography` no lee: se delega siempre.

La descarga en sí no se puede evitar con un parser por *stream*: para verificar la firma de la CRL hace falta el `tbsCertList` completo. Eso lo resuelve el caché de CRLs.

Con los dos cambios, verificar con conexión un PDF de CiDi pasó de ~11,5 s a ~4,8 s la primera vez (casi todo es la descarga) y a ~0,5 s con la CRL en caché.

### Por qué no es confiable (`trust_problem`)

pyHanko resume una falla de confianza en una indicación AdES (`CERTIFICATE_CHAIN_GENERAL_FAILURE` y similares) y el mensaje real sólo va al log. Cuando una firma o su sello de tiempo no son confiables, `/verify` vuelve a validar cada camino candidato hasta una raíz (hasta 5) con el mismo `ValidationContext` y devuelve en `trust_problem`:

- `reason`: el motivo más informativo entre los caminos: `no_path` (falta una intermedia o la raíz), `revoked`, `stale_revocation` (la CRL u OCSP disponible venció), `missing_revocation`, `algorithm`, `not_yet_valid`, `expired` u `other`.
- `summary` y `hint`: el motivo en castellano y qué probar (agregar la intermedia a la fuente, validar con conexión, validar a la hora declarada).
- `paths`: cada camino probado, de la hoja a la raíz (nombre, vigencia y huella de cada eslabón), con su motivo y el mensaje de pyhanko-certvalidator. Sirve para ver, por ejemplo, que una CA renovada aparece dos veces con el mismo nombre y que uno de los caminos falla por la versión vencida.

### La fuente de certificados

Un validador real no confía en lo que el PDF dice de sí mismo: necesita sus propias **anclas de confianza**, y le conviene tener a mano los **intermedios** de las PKIs que valida, porque muchos firmadores no los embeben. Eso es la fuente (`CertificateStore`, en `services/store.py`):

- Una tabla SQLite (`certificates`) con raíces e intermedios: el DER, su SHA-256 (único), el tipo, si está habilitado, si es confiable (sólo raíces), de dónde salió (`seed`, `manual` o `pdf`), notas y fechas. Sólo admite CAs.
- Al arrancar se abre (y la primera vez se crea con la carga inicial) y se carga en memoria. Cada alta, baja o modificación la vuelve a cargar.
- La raíz de la PoC no está en la tabla: es ancla implícita, porque se regenera junto con la PKI.

**Por qué completar con la fuente no alcanza para B-LT.** Que un PDF sea LT significa que **él solo** permite validarlo años después. Si la cadena del firmante necesitó un intermedio que el PDF no trae, la validación es correcta para este validador, pero otro que no tenga ese intermedio no podría reproducirla. Por eso `/verify` lo distingue:

1. Arma la lista de certificados **embebidos** en el PDF: los del DSS, los del CMS de cada firma y los de sus sellos de tiempo.
2. Después de validar, recorre el camino que encontró pyHanko (`validation_path`) del firmante y de su TSA. Cada intermedio del camino que no está entre los embebidos salió de la fuente, y se informa en `completed_from_store`.
3. Si alguna firma usó la fuente, `certificate_store.self_contained` da `false`, con una nota, y el nivel no pasa de B-T.

#### La base SQLite

Es un solo archivo, `certs.db`, en `$CERT_STORE_DB` (por defecto junto a la carpeta de la PKI: `./certs.db` en local, `/data/certs.db` en Docker). Lo crea la app al arrancar si no existe, con el esquema de `services/store.py`. Tiene dos tablas.

**`certificates`**: una fila por raíz o intermedio.

| Columna | Tipo | Qué guarda |
|---------|------|------------|
| `id` | `INTEGER` | Clave primaria autoincremental. Es el `{id}` de `/store/certificates/{id}`. |
| `sha256` | `TEXT`, `UNIQUE` | Huella SHA-256 del DER, en hex. Identifica al certificado: no puede haber dos iguales. |
| `der` | `BLOB` | El certificado en DER: es lo único que usa el validador. El resto son datos para listar y filtrar sin parsearlo. |
| `kind` | `TEXT` | `root` (autofirmado, con su firma verificada) o `intermediate`. Se calcula al agregarlo. |
| `trusted` | `INTEGER` (0/1) | Si es ancla de confianza. Sólo puede valer 1 en una raíz. |
| `enabled` | `INTEGER` (0/1) | Si el validador lo usa. Uno deshabilitado sigue en la tabla (y cuenta para `in_store`), pero no aporta raíces ni intermedios. |
| `origin` | `TEXT` | De dónde salió: `seed` (carga inicial), `manual` (certificado suelto) o `pdf` (desde un PDF firmado). |
| `notes` | `TEXT` | Texto libre. Por defecto, vacío. |
| `subject`, `issuer` | `TEXT` | Sujeto y emisor en RFC 4514 (`CN=…,O=…,C=AR`). |
| `not_before`, `not_after` | `TEXT` | Vigencia, en ISO 8601 con zona horaria. |
| `created_at`, `updated_at` | `TEXT` | Alta y última modificación, en ISO 8601 UTC. |

Las restricciones viven en la base, además de en el código:

- `CHECK (kind IN ('root', 'intermediate'))` y `CHECK (origin IN ('seed', 'manual', 'pdf'))`.
- `CHECK (kind = 'root' OR trusted = 0)`: un intermedio nunca es ancla de confianza.
- `UNIQUE (sha256)`: un mismo certificado no se carga dos veces (la API responde `409`).
- Que sea una CA (BasicConstraints `CA=true`) lo controla el código al agregar, porque SQLite no parsea certificados.

**`meta`** (`key`, `value`): datos de la base. Hoy sólo `seeded_at`, la fecha en que se aplicó la carga inicial. Mientras esa fila exista, la carga inicial no se vuelve a aplicar, aunque se borren sus certificados. Si borrás la fila, se aplica al próximo arranque (sólo agrega lo que falte).

Para mirarla a mano (con la app parada o no: SQLite admite lectores concurrentes):

```bash
sqlite3 certs.db ".schema"
sqlite3 -header -column certs.db \
  "SELECT id, kind, trusted, enabled, origin, substr(subject, 1, 50) AS subject, not_after FROM certificates"
# Exportar un certificado a .crt (DER):
sqlite3 certs.db "SELECT writefile('onti.crt', der) FROM certificates WHERE subject LIKE '%Firma Digital%'"
```

Conviene modificarla por la API o la UI y no a mano: la app tiene la fuente cargada en memoria y sólo la recarga después de un cambio propio. Un cambio hecho con `sqlite3` se ve recién en el próximo arranque.

### Hora de validación (`validation_time`)

- **`now`** (por defecto): valida a la hora actual. Es lo correcto, pero una firma **sin sello de tiempo** deja de validar cuando vencen las CRLs que embebió, porque no hay una hora probada en la que esa revocación estuviera vigente.
- **`claimed_signing_time`** (explícito): valida cada firma a la hora que **ella misma declara** (atributo `signingTime` del CMS o `/M`), y acepta revocación emitida después de esa hora (`retroactive_revinfo`), porque el firmante la junta justamente después de firmar. Esa hora no está probada: el firmante pudo haberla elegido, y la revocación retroactiva no detecta una suspensión que se haya levantado después. Por eso la respuesta lo declara en `validation_time.warning`, y cada firma informa en `validated_at` qué hora se usó.

### Análisis de modificaciones (`diff_policy`)

Una firma cubre su revisión; lo que se agregó después (otras firmas, DSS, sellos) lo revisa la *diff policy* de pyHanko, que sólo acepta cambios de una lista blanca. Si encuentra algo fuera de ella, `bottom_line` da `false` aunque la firma esté intacta y sea confiable. El motivo sale en `modifications.suspicious`.

Con PDFs reales firmados con iText aparecen tres casos:

| Mensaje de pyHanko | Qué pasó | ¿Real? |
|---|---|---|
| `The refs {178 65534} were freed` | La revisión sube `/Size` y marca el número nuevo como `65535 f` (muerto) sin escribirlo nunca. | **No**: no existía, no se borra nada. Se tolera con `diff_policy=allow_unallocated_free_entries`. |
| `VRI key … was modified or deleted` | Al agregar LTV para otra firma, iText reescribe las entradas VRI existentes en objetos nuevos, con el mismo contenido. pyHanko compara la referencia, no el contenido. | **No**, pero no se tolera: habría que reimplementar `DSSCompareRule`. |
| `Dict keys differ: {…'/OutputIntents'} vs. {…}` | Una firma posterior agrega al catálogo un OutputIntent PDF/A (sRGB). Las claves se listan como (nueva, vieja). | **Sí**: cambio de bajo riesgo, pero afecta la interpretación del color. |

`allow_unallocated_free_entries` sólo acepta entradas libres con número de objeto `>=` al `/Size` de la revisión anterior. Liberar un objeto que existía sigue siendo sospechoso, y el resto del análisis es el de pyHanko por defecto. La respuesta lo declara en `diff_policy.note`.

### Respuesta

```json
{
  "validation_time": { "mode": "now", "warning": null },
  "diff_policy": { "mode": "default", "note": null },
  "pades_level": "PAdES B-LTA",
  "dss": { "Certs": 5, "OCSPs": 2, "CRLs": 1 },
  "certificate_store": { "trusted_roots": 3, "intermediates": 1, "self_contained": true, "note": null },
  "signatures": [
    {
      "field": "Firma1",
      "type": "Signature",
      "subfilter": "/ETSI.CAdES.detached",
      "signer": "Common Name: Firmante de Prueba, Organization: PoC PAdES, Country: AR",
      "bottom_line": true,
      "intact": true,
      "valid": true,
      "trusted": true,
      "coverage": "ENTIRE_REVISION",
      "completed_from_store": [],
      "modifications": { "level": "LTA_UPDATES", "docmdp_ok": true, "suspicious": null },
      "validated_at": { "time": "...", "source": "now" },
      "signature_timestamp": { "time": "...", "tsa": "...", "valid": true, "trusted": true, "completed_from_store": [] },
      "details": "..."
    },
    { "field": "Timestamp-…", "type": "DocTimeStamp" }
  ]
}
```

| Campo | Significado |
|-------|-------------|
| `intact` | El hash de los bytes del `/ByteRange` coincide con el `message-digest` del CMS: el documento no se alteró. |
| `valid` | La firma criptográfica del CMS verifica con la clave pública del certificado. |
| `trusted` | Se pudo construir y validar la cadena hasta la raíz confiable, **incluida la revocación** con la evidencia del DSS. |
| `completed_from_store` | Intermedios del camino que el PDF no trae y salieron de la fuente (`subject` y `sha256`). Vacío si el PDF alcanzó solo. |
| `certificate_store` | Cuántas raíces confiables (incluida la de la PoC) e intermedios aportó la fuente, si el PDF fue autosuficiente (`self_contained`) y, si no, una `note`. |
| `bottom_line` | Veredicto global de pyHanko: la firma es aceptable. |
| `coverage` | Ver [Cobertura](#cobertura-coverage). |
| `modifications` | Análisis de lo agregado después de la firma: nivel (`LTA_UPDATES`, `FORM_FILLING`, … u `OTHER` si es sospechoso), si respeta el DocMDP, y el motivo si es sospechoso. |
| `validated_at` | Hora a la que se validó la firma y de dónde sale: `now` o `claimed_signing_time` (si la firma no declara hora, cae en `now`). |
| `signature_timestamp` | Hora certificada por la TSA, quién la emitió y si ese sello es válido y confiable. |
| `details` | Informe completo en texto de pyHanko. |

### El reporte de la UI (tab Verificación)

La página traduce la respuesta a un reporte, sin recalcular nada:

- **Resumen**: `pades_level`, cuántas firmas dan `bottom_line`, los contadores de `dss` (o un aviso si no hay DSS: sin revocación ninguna firma es confiable), lo que aportó la fuente y los modos de `validation_time` y `diff_policy`. Si la respuesta trae `validation_time.warning`, `diff_policy.note` o `certificate_store.note`, los muestra como advertencias.
- Si una cadena se completó con la fuente, la fila de confianza (y la del sello de tiempo) lo marca con los intermedios que se usaron.
- **Una card por firma** con un veredicto (`bottom_line`) y una fila por campo de la tabla de arriba. `coverage` se muestra en verde tanto para `ENTIRE_FILE` como para `ENTIRE_REVISION`, porque lo segundo es lo normal en B-LT/B-LTA y lo agregado después lo juzga `modifications`. Un `modifications.suspicious` se muestra en rojo con el mensaje de pyHanko. Del firmante y de la TSA se destaca el *Common Name*.
- Los `/DocTimeStamp` tienen su propia card, que aclara que no se validan por separado (ver abajo).
- `details` va en un desplegable, que se omite al imprimir.

### Cómo se calcula `pades_level`

Es una heurística de la PoC, no un validador ETSI completo:

- **B-B**: hay firmas.
- **B-T**: todas las firmas tienen signature timestamp.
- **B-LT**: además hay DSS, todas las firmas dan `bottom_line` validando offline y ninguna necesitó la fuente para completar su cadena (`self_contained`).
- **B-LTA**: además hay al menos un `/DocTimeStamp`.

Limitaciones: los `/DocTimeStamp` se listan pero **no se validan**, y la validación usa `async_validate_pdf_signature` de pyHanko, no el algoritmo de validación en tiempo pasado de ETSI EN 319 102-1. Para una validación formal conviene contrastar con una herramienta independiente (por ejemplo, el validador DSS de la Comisión Europea).

### Extracción de certificados: `POST /certificates`

Devuelve, por cada firma y cada `/DocTimeStamp`, la cadena de certificados **tal como viene en el PDF**. A diferencia de `/verify`, **no mira la confianza ni la revocación**: sólo exige que la firma sea **criptográficamente válida**. Así también sirve para inspeccionar PDFs firmados con PKIs ajenas.

1. **Chequeo criptográfico** (`intact` y `valid`, ver tabla de arriba). En un `/Sig`, el `message-digest` tiene que coincidir con el hash del ByteRange. En un `/DocTimeStamp`, los atributos firmados cubren el TSTInfo, y el `messageImprint` del TSTInfo tiene que coincidir con el hash del ByteRange. Si falla, la firma se informa con `crypto_valid: false`, un `error` y `certificates: null`.
2. **Armado de la cadena**: parte del certificado firmante y busca al emisor de cada eslabón entre los certificados del CMS, del DSS y de la fuente de certificados (habilitados). Un candidato es el emisor sólo si su sujeto coincide con el emisor del eslabón **y** su clave pública verifica la firma de ese certificado (no alcanza con que coincida el nombre). Se detiene en un certificado autofirmado. `chain_complete` indica si se llegó a uno.
   - **Completar por AIA**: muchos firmadores (por ejemplo Ciudadano Digital de Córdoba) embeben **sólo** el certificado del firmante, sin intermedia, raíz ni DSS. Si falta un emisor y `fetch_missing` es `true` (el valor por defecto), se descarga desde la URL **AIA caIssuers** del eslabón (`http://…/ca.crt`, en DER, PEM o PKCS#7) y se repite con el certificado descargado hasta llegar a la raíz. Las descargas tienen timeout y caché por request. Si alguna falla, el detalle queda en `aia_errors` y la cadena se corta ahí.
   - **SHA-1**: `cryptography` se niega a verificar firmas SHA-1, pero PKIs reales las siguen usando (la AC Raíz de Argentina firma con SHA-1 a la CA de la ONTI). Como acá sólo se arma la cadena y no se evalúa política, en ese caso la firma RSA/ECDSA se verifica a mano.
3. **Clasificación** de cada certificado:
   - `end_entity`: el que firmó (posición 0).
   - `root`: autofirmado, es decir emisor = sujeto y firmado con su propia clave.
   - `intermediate`: cualquier otro eslabón.
   - `self_signed` se informa aparte, para cubrir el caso de un firmante con certificado autofirmado (`end_entity` y `self_signed: true`).
4. **`source`**: de dónde salió cada certificado: `cms` (embebido en la firma o en el token), `dss`, `store` (la fuente) o `aia` (descargado). Si un certificado está en varios lugares, gana el primero de esa lista: AIA se usa sólo si no estaba en ningún otro lado. Aparte, **`in_store`** dice si el certificado está en la fuente (habilitado o no), venga de donde venga. La UI lo muestra en la cadena.
5. **`der_b64`**: el certificado en DER codificado en base64 (sólo la parte pública). Decodificado se guarda como `.crt`/`.cer`. Con encabezados `-----BEGIN CERTIFICATE-----` es un PEM.

6. **Signature timestamp**: cada firma (`/Sig`) válida trae además `signature_timestamp`, con la hora certificada (`time`) y la cadena de la TSA que la selló. El token se chequea igual que un DocTimeStamp, con una diferencia: su `messageImprint` tiene que coincidir con el hash del **valor de la firma** (lo que sella la TSA en B-T), no con el ByteRange. Si no coincide, el error es `"el sello no corresponde a esta firma"`. La cadena se arma con los certificados del token, completados con los del CMS de la firma y los del DSS. Vale `null` si la firma no tiene sello (B-B) o si la firma misma no es válida.

Forma de la respuesta:

```json
{
  "signatures": [
    {
      "field": "Firma1", "type": "Signature",
      "crypto_valid": true, "intact": true, "valid": true, "chain_complete": true,
      "certificates": [ { "type": "end_entity", "source": "cms", "self_signed": false, "der_b64": "MIIF…", "...": "..." }, "…" ],
      "signature_timestamp": {
        "time": "2026-09-30T23:29:45+00:00",
        "crypto_valid": true, "intact": true, "valid": true, "chain_complete": true,
        "certificates": [ "TSA (end_entity)", "intermedia", "raíz" ]
      }
    },
    { "field": "Timestamp-…", "type": "DocTimeStamp", "crypto_valid": true, "certificates": [ "…" ] }
  ]
}
```

En la tab Certificados de la UI cada firma es una card con su cadena, con la del `signature_timestamp` en un desplegable aparte. La card marca la cadena como completa, incompleta (`chain_complete: false`) o completada por AIA (algún `source: "aia"`), y muestra los `aia_errors`. Cada certificado tiene tres botones, que trabajan sólo con `der_b64`:

- **Ver detalle** pasa a la tab Inspección con ese certificado elegido, y manda su `der_b64` a `/certificates/inspect`. En esa tab, un selector lista todos los certificados del PDF sin repetir (la intermedia suele estar en varias cadenas).
- **Descargar .crt** lo decodifica y lo descarga como `<CN>.crt` (DER, `application/pkix-cert`).
- **Copiar base64** lo copia tal cual al portapapeles.

### Detalle de un certificado: `POST /certificates/inspect`

Recibe un certificado y lo describe campo por campo. Sirve para mirar los certificados que salen de `/certificates`, los que publica una CA por AIA o cualquier `.crt` suelto. No evalúa confianza ni revocación: sólo lee lo que dice el certificado.

- **Entrada**: un archivo `crt` en DER, PEM o PKCS#7 (`.p7c`/`.p7b`, que puede traer varios), **o** un campo `b64` con el base64 de un DER (con o sin saltos de línea) o un PEM. Se reusa `_parse_certs`, el mismo parser de las descargas AIA. Si no es nada de eso, `422`.
- **Sujeto y emisor**: atributo por atributo, en el orden del DER, con su OID. En la PKI argentina el CUIL/CUIT del titular va en `serialNumber` (`"CUIT 30680604572"`), y la tab Inspección de la UI lo destaca.
- **`validity`**: `not_before`, `not_after`, `status` (`valid`, `expired`, `not_yet_valid`) y `days_left` respecto de la hora actual.
- **`in_store`**: si el certificado ya está en la fuente de certificados. El reporte de inspección de la UI lo usa para ofrecer **Agregar a la fuente** a las CAs que no están: es el único lugar de la UI donde se dan altas, para que siempre se vea qué es el certificado antes de agregarlo.
- **`is_ca`** (de BasicConstraints) y **`self_signed`** (con la misma verificación de firma que el armado de cadenas, así que acepta SHA-1).
- **`extensions`**: cada una con `oid`, `name`, `critical` y `values`, una lista de líneas de texto. Se interpretan KU, EKU, BasicConstraints, AIA, CDP, políticas (cada CPS y aviso en su propia línea), SAN, SKI/AKI y OCSP no-check. Las que `cryptography` no conoce se decodifican si son un ASN.1 simple (texto, entero u octet string) y si no van en hex. Las de Microsoft AD CS que traen las CAs de la PKI argentina (`msCertificateTemplateName`, `msCAVersion`, `msPreviousCACertHash`) se nombran.

---

## 11. Casos negativos: revocación

La revocación se guarda en `revoked.json` (`{serial_hex: {issuer, time}}`) y se refleja al instante en las CRLs y en OCSP.

| Acción | Efecto al firmar |
|--------|------------------|
| `POST /pki/revoke/signer` | OCSP devuelve `revoked` para el firmante → `/sign` responde 422. |
| `POST /pki/revoke/tsa` | OCSP devuelve `revoked` para la TSA → el sello no es confiable → 422. |
| `POST /pki/revoke/intermediate` | La CRL de la raíz lista a la intermedia → toda la cadena cae → 422. |
| `POST /pki/unrevoke-all` | Vuelve todo a `good`. |

El respondedor OCSP no se puede revocar desde la API: por `ocsp-nocheck` los validadores no lo consultarían igual.

Un PDF firmado **antes** de revocar sigue validando en `/verify`, porque el DSS guarda la evidencia de que en ese momento todo estaba en `good`. Ese es justamente el propósito de B-LT.

---

## 12. Glosario

| Término | Definición breve |
|---------|------------------|
| **AdES** | *Advanced Electronic Signature*. Familia de formatos ETSI: CAdES (CMS), XAdES (XML), PAdES (PDF), JAdES (JSON). |
| **AIA** | Extensión con las URLs del certificado del emisor y del respondedor OCSP. |
| **Ancla de confianza** | Certificado en el que el validador confía por configuración. Aquí, la raíz. |
| **ASN.1 / DER** | Lenguaje para describir estructuras binarias y su codificación canónica. Certificados, CRLs, OCSP y CMS usan DER. PEM es DER en base64 con encabezados. |
| **ByteRange** | Rangos de bytes del PDF cubiertos por una firma. |
| **CA** | Autoridad Certificante: emite y revoca certificados. |
| **CAdES** | Perfil de CMS para firmas avanzadas. Lo que va en `/Contents` de una firma PAdES. |
| **CDP** | Extensión con la URL de la CRL que cubre al certificado. |
| **CertID** | Identificador de un certificado en un pedido OCSP (hashes del emisor + serial). |
| **CMS / PKCS#7** | Formato de contenedor de firmas (RFC 5652). |
| **Co-firma** | Varias firmas independientes sobre el mismo PDF, en revisiones sucesivas. |
| **CRL** | Lista firmada de certificados revocados. |
| **Detached** | Firma cuyo contenido firmado está fuera del contenedor CMS. |
| **DocTimeStamp** | Sello de tiempo sobre el documento entero, en su propio campo de firma. Base de B-LTA. |
| **DSS** | *Document Security Store*: diccionario del PDF con certificados, OCSPs y CRLs para LTV. |
| **EKU** | *Extended Key Usage*: propósito específico de una clave. |
| **Hard-fail** | Política que rechaza si no hay información de revocación. |
| **Hoja** | Certificado final, no-CA. |
| **Incremental update** | Modificación de un PDF agregando bytes al final, sin tocar los anteriores. |
| **KU** | *Key Usage*: operaciones criptográficas permitidas para la clave. |
| **LTV** | *Long-Term Validation*: poder validar una firma años después. |
| **messageImprint** | Algoritmo + hash del dato que se manda a sellar a la TSA. |
| **Nonce** | Valor aleatorio contra ataques de repetición (OCSP y TSA). |
| **OCSP** | Protocolo de consulta en línea del estado de un certificado. |
| **ocsp-nocheck** | Extensión que exime al respondedor OCSP de verificar su propia revocación. |
| **PAdES** | Firmas electrónicas avanzadas en PDF (ETSI EN 319 142). |
| **PKI** | Infraestructura de clave pública: CAs, certificados, políticas y servicios de revocación. |
| **Respondedor delegado** | Certificado con EKU `OCSPSigning` que firma respuestas OCSP en nombre de la CA. |
| **Revisión** | Cada bloque de actualización incremental de un PDF. |
| **Signed attributes** | Atributos del CMS protegidos por la firma. |
| **signing-certificate-v2** | Atributo firmado con el hash del certificado del firmante. |
| **SubFilter** | Formato de la firma en el diccionario PDF: `ETSI.CAdES.detached`, `ETSI.RFC3161`, etc. |
| **TSA** | Autoridad de sellado de tiempo. |
| **TSTInfo** | Contenido firmado de un sello de tiempo: hash, hora, serial, política. |
| **Unsigned attributes** | Atributos del CMS agregados después de firmar (por ejemplo, el signature timestamp). |
| **VRI** | Índice opcional del DSS que asocia cada firma con su evidencia de validación. |

---

## 13. Referencias normativas

- **ETSI EN 319 142-1**: PAdES, perfiles baseline (B-B, B-T, B-LT, B-LTA).
- **ETSI EN 319 122-1**: CAdES, firmas CMS avanzadas.
- **ETSI EN 319 102-1**: procedimientos de creación y validación de AdES.
- **ISO 32000-2**: PDF 2.0 (firmas, DSS, DocTimeStamp).
- **RFC 5280**: certificados X.509, CRLs y validación de caminos.
- **RFC 5652**: CMS.
- **RFC 5035**: atributo `signing-certificate-v2` (ESS).
- **RFC 6960**: OCSP.
- **RFC 3161**: protocolo de sellado de tiempo (TSP).
- **pyHanko**: <https://docs.pyhanko.eu/>
