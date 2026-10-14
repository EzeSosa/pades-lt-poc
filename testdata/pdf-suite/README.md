# Suite de PDFs para APIs de firma

PDFs de prueba para atajar errores en servicios de firma digital (PAdES) antes de que lleguen a
producción. Cada archivo reproduce una situación que aparece con documentos reales: estructuras que
generan distintas herramientas, archivos imperfectos, cifrado, certificación, formularios, firmas
previas y entradas inválidas.

La suite no depende de esta PoC: sirve para cualquier API que reciba un PDF y devuelva el PDF firmado,
o que verifique firmas.

## Contenido

- `manifest.json`: un registro por caso, con el archivo, qué prueba, qué se espera y cómo subirlo.
  Pensado para que un runner lo recorra (ver `scripts/run_pdf_suite.py`).
- Una carpeta por categoría con los PDFs.
- Este README, generado junto con el manifest por `scripts/make_pdf_suite.py`. Para cambiar un caso,
  editá el generador y volvé a correrlo: no edites este archivo a mano.

## Cómo leer lo esperado

Columna **Firma**, lo que tiene que hacer el endpoint de firma con ese archivo:

- `ok`: devuelve un PDF firmado. Además, la firma nueva valida íntegra y las firmas previas siguen
  íntegras.
- `reject`: responde 4xx con un mensaje que explique el motivo.
- `ok_or_reject`: cualquiera de las dos es aceptable, según la política del sistema.

En **todos** los casos es un error: un 5xx, un timeout, o un PDF firmado que después no valida o no
abre en Acrobat. También lo es que un caso deje al servicio roto para los pedidos siguientes: el
runner vuelve a firmar E01 después de cada respuesta que no sea 200 para detectarlo (estado
compartido entre pedidos, como un firmante reusado que queda a medio configurar).

## Cómo correrla

```powershell
uv run python scripts/make_pdf_suite.py                     # regenera PDFs, manifest y este README
uv run python scripts/run_pdf_suite.py --base-url http://127.0.0.1:8000
uv run python scripts/run_pdf_suite.py --only S01,F05       # algunos casos
```

Los PDFs firmados quedan en `out/pdf-suite/` para abrirlos en Acrobat. Para otra API, el runner es
lo único que cambia: los PDFs y el manifest no dependen de esta PoC.

Los casos de `firmados/` (y S03, S04, F05) traen firmas de una **PKI de prueba ajena**, generada por el
script en cada corrida. Ningún validador debería confiar en ella: esos casos prueban integridad,
co-firma y algoritmos, no confianza. Que la verificación diga "no confiable" es lo correcto.

Los casos I04 a I06 reusan `E01-base.pdf` y cambian lo que se envía: el nombre del archivo o los
campos del formulario (ver `upload` en el manifest).

## Qué revisar a mano

El runner automatiza la respuesta HTTP y la verificación por API. Hay cosas que conviene mirar con
otras herramientas al menos una vez por versión:

- Abrir los PDFs firmados en **Adobe Acrobat Reader** y revisar el panel de firmas: es el validador
  que van a usar los destinatarios.
- Validar C06 firmado con **veraPDF** (conformidad PDF/A).
- Validar con el **validador DSS de la Comisión Europea** para comparar el nivel PAdES informado.
- Medir el tiempo de C01 y C04 con la configuración de producción (proxy y límites de subida incluidos).

## Casos

### Variantes válidas de la estructura del archivo (`estructura`)

| Caso | Archivo | Firma | Qué reproduce | Qué se espera |
|---|---|---|---|---|
| **E01** Documento mínimo correcto | `estructura/E01-base.pdf` | `ok` | Línea de base: PDF 1.7 de una página, xref clásica y Helvetica sin embeber. | Se firma. Si este falla, el resto de la suite no dice nada. |
| **E02** Versión de cabecera 1.4 | `estructura/E02-pdf-1.4.pdf` | `ok` | Documentos viejos o generados por herramientas antiguas. Algunos firmantes suben la versión de cabecera reescribiendo el archivo, lo que invalida firmas previas. | Se firma por actualización incremental, sin reescribir los bytes originales. |
| **E03** Versión de cabecera 2.0 | `estructura/E03-pdf-2.0.pdf` | `ok` | PDF 2.0 (ISO 32000-2). Librerías viejas lo rechazan por la versión aunque la estructura sea la misma. | Se firma. Si se rechaza, que sea con un mensaje claro y no con un 500. |
| **E04** Cross-reference stream y object streams | `estructura/E04-xref-stream.pdf` | `ok` | Lo que generan Word, LibreOffice, Chrome y la mayoría de las herramientas modernas: sin tabla xref de texto, con objetos comprimidos dentro de object streams. | Se firma. La revisión agregada puede usar xref stream o tabla, pero la firma previa al archivo tiene que seguir intacta. |
| **E05** Varias revisiones incrementales previas | `estructura/E05-revisiones-incrementales.pdf` | `ok` | El archivo ya tiene tres revisiones (/Prev encadenados). Pasa con documentos editados varias veces o rellenados en Acrobat antes de firmar. | Se firma. El ByteRange de la nueva firma cubre todo el archivo, incluidas las revisiones previas. |
| **E06** Fines de línea CRLF | `estructura/E06-fin-de-linea-crlf.pdf` | `ok` | Archivos generados en Windows o que pasaron por una conversión de texto. Los parsers que buscan `\n` a mano calculan mal offsets. | Se firma. |
| **E07** Sin fin de línea después de %%EOF | `estructura/E07-sin-eol-final.pdf` | `ok` | El archivo termina justo en `%%EOF`. Un firmante que concatena la revisión nueva sin agregar un fin de línea deja `%%EOF1 0 obj`, que algunos lectores no aceptan. | Se firma, y la revisión nueva empieza en una línea propia. |

### Archivos imperfectos que circulan en la práctica (`tolerancia`)

| Caso | Archivo | Firma | Qué reproduce | Qué se espera |
|---|---|---|---|---|
| **T01** Bytes después de %%EOF | `tolerancia/T01-bytes-despues-de-eof.pdf` | `ok_or_reject` | Relleno con ceros o espacios al final, típico de sistemas de correo, escáneres y almacenamiento que redondea a bloques. | Se firma, o se rechaza con 422. Si se firma, el resultado tiene que validar en Acrobat: el relleno queda dentro del ByteRange. |
| **T02** Bytes antes de la cabecera %PDF | `tolerancia/T02-bytes-antes-de-cabecera.pdf` | `ok_or_reject` | Archivos con basura al principio (cabeceras MIME o de otro formato). Los offsets de la xref quedan corridos respecto del inicio del archivo. | Se rechaza con 422, o se firma de forma que el resultado valide. No se acepta un 500 ni un PDF firmado que después no abre. |
| **T03** Offsets de la xref incorrectos | `tolerancia/T03-xref-desplazada.pdf` | `ok_or_reject` | La tabla xref apunta 7 bytes antes de cada objeto, como pasa cuando alguien edita el PDF como texto. Los lectores la reconstruyen; una firma incremental sobre una xref rota puede validar en una herramienta y no en otra. | Se rechaza con 422, o se firma sólo si la revisión original queda intacta. Nunca un 500. |

### Páginas, tamaño y metadatos (`contenido`)

| Caso | Archivo | Firma | Qué reproduce | Qué se espera |
|---|---|---|---|---|
| **C01** 300 páginas | `contenido/C01-300-paginas.pdf` | `ok` | Expedientes largos. Detecta timeouts y procesos que recorren todas las páginas sin necesidad. | Se firma en un tiempo razonable (medirlo). |
| **C02** Páginas rotadas y de tamaños distintos | `contenido/C02-paginas-rotadas-y-tamanos-mixtos.pdf` | `ok` | A4, oficio y A3 apaisada, con /Rotate 90 y 270. Las firmas visibles calculan mal la posición o quedan giradas. | Se firma. Si la firma es visible, el sello queda derecho y dentro de la página. |
| **C03** MediaBox y Resources heredados | `contenido/C03-atributos-heredados.pdf` | `ok` | Las páginas no tienen /MediaBox ni /Resources propios: los heredan del nodo /Pages. Un estampador que lee sólo la página no encuentra el tamaño ni las fuentes. | Se firma. |
| **C04** Archivo de unos 25 MB | `contenido/C04-25-mb.pdf` | `ok_or_reject` | Límites de subida (proxy, framework, gateway) y lecturas completas en memoria. El contenido es una imagen sin comprimir, que git guarda comprimida. | Se firma, o se rechaza con 413 y un mensaje claro si supera el límite documentado. |
| **C05** Metadatos Unicode y XMP | `contenido/C05-metadatos-unicode.pdf` | `ok` | Título, autor y asunto en UTF-16BE con acentos, eñes y caracteres fuera de Latin-1, más un paquete XMP. Rompe a quien loguea o propaga metadatos asumiendo ASCII. | Se firma y los metadatos se conservan. |
| **C06** Declara PDF/A-2B | `contenido/C06-declara-pdfa-2b.pdf` | `ok` | El XMP declara PDF/A-2B (pdfaid). Archivo exigido en muchos organismos. Una firma visible con fuente sin embeber, o una revisión que reescribe el archivo, rompe la conformidad. El archivo sólo la declara: verificar el resultado con veraPDF. | Se firma por actualización incremental y el resultado sigue declarando PDF/A. |
| **C07** Archivo adjunto embebido | `contenido/C07-adjunto.pdf` | `ok` | Un XML adjunto (EmbeddedFiles), como en las facturas o en PDF/A-3. La firma tiene que cubrirlo. | Se firma y el adjunto se conserva. |
| **C08** Página sin /Contents ni /Resources | `contenido/C08-pagina-vacia-sin-contents.pdf` | `ok` | Página en blanco válida que no tiene stream de contenido. El código que asume que /Contents existe falla al estampar. | Se firma. |

### Cifrado y certificación (DocMDP) (`seguridad`)

| Caso | Archivo | Firma | Qué reproduce | Qué se espera |
|---|---|---|---|---|
| **S01** Cifrado con clave de apertura | `seguridad/S01-cifrado-con-clave-de-apertura.pdf` | `reject` | Hace falta la clave para abrirlo (contraseña de usuario `usuario`, de propietario `propietario`). Sin clave no se puede firmar. | Se rechaza con 422 y un mensaje que diga que el PDF está protegido. Nunca un 500. |
| **S02** Cifrado sólo con clave de propietario | `seguridad/S02-cifrado-sin-clave-de-apertura.pdf` | `ok_or_reject` | Abre sin contraseña pero está cifrado y tiene permisos restringidos. Es muy común. Firmarlo exige escribir la revisión cifrada con la clave de propietario. | Se rechaza con 422 explicando la protección, o se firma respetando los permisos. Nunca un 500 ni una revisión sin cifrar mezclada con una cifrada. |
| **S03** Certificado con DocMDP P=1 | `seguridad/S03-certificado-p1.pdf` | `reject` | Firma de certificación que no permite ningún cambio. Cualquier firma nueva invalida la certificación. | Se rechaza con 422 explicando que el documento está certificado sin cambios permitidos. |
| **S04** Certificado con DocMDP P=2 | `seguridad/S04-certificado-p2.pdf` | `ok` | Firma de certificación que permite completar formularios y firmar. Es el flujo de un trámite que un organismo certifica y el ciudadano firma. | Se firma y la certificación sigue válida (cambio permitido). |

### AcroForm y campos de firma existentes (`formularios`)

| Caso | Archivo | Firma | Qué reproduce | Qué se espera |
|---|---|---|---|---|
| **F01** Formulario con campos completados | `formularios/F01-acroform.pdf` | `ok` | AcroForm con texto y casilla, con apariencias. Una firma tiene que agregarse al /Fields sin perder los campos existentes. | Se firma y los campos conservan sus valores. |
| **F02** Formulario con NeedAppearances true | `formularios/F02-need-appearances.pdf` | `ok` | El visor regenera las apariencias al abrir. Acrobat puede marcar el documento como modificado después de la firma. | Se firma. Idealmente el firmante genera las apariencias y quita NeedAppearances antes de firmar. |
| **F03** Campo de firma vacío preexistente | `formularios/F03-campo-de-firma-vacio.pdf` | `ok` | El documento trae un campo de firma `Firma1` sin firmar, preparado por quien emitió el trámite. | Se firma, ya sea en ese campo o en uno nuevo, sin errores por nombre duplicado. |
| **F04** Campo de texto con el nombre que el firmante elegiría | `formularios/F04-campo-de-texto-llamado-firma1.pdf` | `ok` | Un campo de texto se llama `Firma1`. El firmante que arma el nombre como `Firma{n+1}` choca con un campo que no es de firma. | Se firma con un nombre de campo libre. Nunca un 500. |
| **F05** Una firma existente en el campo Firma2 | `formularios/F05-firma-existente-llamada-firma2.pdf` | `ok` | Hay una sola firma, pero su campo se llama `Firma2`. El firmante que cuenta firmas para elegir el nombre (`Firma{n+1}`) intenta usar un campo ya firmado. | Se co-firma con otro nombre de campo y la firma previa sigue intacta. |

### PDFs que ya traen firmas (`firmados`)

| Caso | Archivo | Firma | Qué reproduce | Qué se espera |
|---|---|---|---|---|
| **P01** Firma PAdES previa de otra PKI | `firmados/P01-firma-previa-pades.pdf` | `ok` | Co-firma: el documento ya trae una firma PAdES con sello de tiempo, de una CA que el validador no conoce. | Se firma y la firma previa queda intacta. La verificación la informa íntegra pero no confiable. |
| **P02** Firma previa ECDSA P-256 | `firmados/P02-firma-previa-ecdsa.pdf` | `ok` | Algoritmo de clave distinto de RSA. Validadores que asumen RSA fallan al leer la clave o el algoritmo de firma. | Se firma y la verificación interpreta la firma ECDSA. |
| **P03** Firma previa adbe.pkcs7.detached | `firmados/P03-firma-previa-pkcs7-detached.pdf` | `ok` | Subfiltro no PAdES, el más común en firmas viejas y de algunos productos. La verificación tiene que aceptarlo y no reportarlo como nivel PAdES. | Se firma. La verificación informa el subfiltro. |
| **P04** Firma previa con digest SHA-512 | `firmados/P04-firma-previa-sha512.pdf` | `ok` | Digest distinto del habitual SHA-256. | Se firma. La verificación la valida. |
| **P05** Dos firmas previas | `firmados/P05-dos-firmas-previas.pdf` | `ok` | Circuito de varios firmantes. La tercera firma no puede alterar las dos anteriores. | Se firma y las tres firmas quedan íntegras. |
| **P06** Contenido de página cambiado después de firmar | `firmados/P06-contenido-modificado-tras-firmar.pdf` | `ok_or_reject` | Una revisión posterior a la firma reemplaza el texto de la página. La firma sigue siendo criptográficamente correcta para su revisión, pero el documento que se ve ya no es el firmado. | La verificación informa la modificación (no da la firma por buena para el documento completo). Firmarlo de nuevo no debe ocultar el problema. |
| **P07** Bytes firmados alterados | `firmados/P07-bytes-firmados-alterados.pdf` | `ok_or_reject` | Se cambió texto dentro del rango firmado sin tocar la estructura (mismo largo), como una corrupción en tránsito o una edición directa. El hash ya no coincide. | La verificación informa la firma como no íntegra. |

### Entradas inválidas y parámetros de la API (`entrada`)

| Caso | Archivo | Firma | Qué reproduce | Qué se espera |
|---|---|---|---|---|
| **I01** Archivo vacío | `entrada/I01-vacio.pdf` | `reject` | 0 bytes, como cuando el cliente sube antes de terminar de leer el archivo. | Se rechaza con 4xx y un mensaje claro. |
| **I02** Otro formato con extensión .pdf | `entrada/I02-no-es-pdf.pdf` | `reject` | Un PNG renombrado. Validar por extensión o content-type no alcanza. | Se rechaza con 4xx. |
| **I03** PDF truncado | `entrada/I03-truncado.pdf` | `ok_or_reject` | Descarga o subida cortada a la mitad: sin xref ni %%EOF. | Se rechaza con 4xx, o se firma sólo si el resultado valida. Nunca un 500. |
| **I04** Nombre de archivo con caracteres no ASCII | `estructura/E01-base.pdf` | `ok` | El nombre del archivo subido viaja al header Content-Disposition de la respuesta. Con caracteres fuera de Latin-1 el header no se puede codificar si no se usa `filename*` (RFC 6266). Se sube como `Resolución Nº 123 – año 2026 ✓.pdf`. | Se firma y la respuesta trae un nombre de descarga correcto. |
| **I05** Nombre de archivo con comillas y extensión en mayúsculas | `estructura/E01-base.pdf` | `ok` | Comillas dentro del nombre rompen un `filename="..."` armado a mano; `.PDF` en mayúsculas no coincide con un `removesuffix('.pdf')`. Se sube como `Nota "urgente".PDF`. | Se firma y el nombre de descarga es válido y termina en .pdf una sola vez. |
| **I06** Motivo y lugar con Unicode | `estructura/E01-base.pdf` | `ok` | Los campos /Reason y /Location se escriben como strings PDF: con caracteres fuera de PDFDocEncoding hay que usar UTF-16BE. Campos: `reason=Aprobación — Dirección de Ñandúes 📄`, `location=San Martín de los Andes, AR`. | Se firma y el motivo se lee igual en Acrobat. |
