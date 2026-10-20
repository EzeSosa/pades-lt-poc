# El formato PDF: estructura interna, firma y análisis del documento

Este documento explica qué es un PDF por dentro y cómo se le agrega una firma digital sin romperlo: desde la sintaxis de los objetos hasta la actualización incremental, los formularios, el cifrado, la certificación y los ataques conocidos contra las firmas PDF. Termina con lo que la API analiza de cada documento en `POST /document` y por qué.

Complementa a [pades.md](pades.md), que cubre la criptografía, la PKI, la revocación, los sellos de tiempo, CMS y los niveles PAdES. Acá el foco es el **archivo**.

Los ejemplos de bytes son de un PDF real: `E01-base.pdf` de la [suite de pruebas](../testdata/pdf-suite/README.md), firmado por la PoC en B-LTA con motivo `Conformidad` y lugar `Buenos Aires, AR`.

Índice:

1. [Qué es un PDF](#1-qué-es-un-pdf)
2. [Sintaxis: los objetos](#2-sintaxis-los-objetos)
3. [Estructura física del archivo](#3-estructura-física-del-archivo)
4. [Estructura lógica del documento](#4-estructura-lógica-del-documento)
5. [Actualización incremental y revisiones](#5-actualización-incremental-y-revisiones)
6. [Formularios interactivos (AcroForm y XFA)](#6-formularios-interactivos-acroform-y-xfa)
7. [Contenido activo: acciones, JavaScript, adjuntos y capas](#7-contenido-activo-acciones-javascript-adjuntos-y-capas)
8. [Protección: cifrado, permisos, certificación y bloqueos](#8-protección-cifrado-permisos-certificación-y-bloqueos)
9. [La firma digital dentro del PDF](#9-la-firma-digital-dentro-del-pdf)
10. [Cómo se firma de forma incremental, paso a paso](#10-cómo-se-firma-de-forma-incremental-paso-a-paso)
11. [Qué se puede cambiar después de firmar](#11-qué-se-puede-cambiar-después-de-firmar)
12. [Ataques conocidos contra las firmas PDF](#12-ataques-conocidos-contra-las-firmas-pdf)
13. [El análisis del documento en esta API](#13-el-análisis-del-documento-en-esta-api)
14. [Glosario](#14-glosario)
15. [Referencias](#15-referencias)

---

## 1. Qué es un PDF

**PDF** (*Portable Document Format*) es un formato de documento de **página fija**: describe exactamente qué se dibuja en cada página (texto con sus fuentes, gráficos vectoriales, imágenes) de forma independiente del programa, el sistema operativo y la impresora. A diferencia de un formato de edición (un `.docx`), no guarda "párrafos que se reacomodan": guarda el resultado ya compuesto.

- Lo creó Adobe en 1993, derivado de PostScript. Desde 2008 es un estándar abierto de ISO: **ISO 32000-1** (PDF 1.7) y **ISO 32000-2** (PDF 2.0, de 2017, revisado en 2020).
- Hay **subconjuntos** para usos específicos: **PDF/A** (ISO 19005, archivo a largo plazo: todo embebido, sin cifrado ni JavaScript), **PDF/UA** (ISO 14289, accesibilidad), **PDF/X** (imprenta).
- La **firma digital** está en el propio estándar (ISO 32000, §12.8), y **PAdES** (ETSI EN 319 142) la perfila para firmas electrónicas avanzadas y cualificadas en Europa y en muchos otros países, incluida la Argentina.

Un PDF es, en el fondo, una **base de datos de objetos** con un índice al final. Esa organización es la que permite firmarlo: se pueden agregar objetos nuevos sin tocar los bytes de los anteriores.

> En el código: el lector de PDFs es el de pyHanko (`pyhanko.pdf_utils.reader.PdfFileReader`), usado en `adapters/outbound/pyhanko/`.

---

## 2. Sintaxis: los objetos

Un PDF se escribe con ocho tipos de objetos, en una sintaxis de texto (salvo el contenido de los streams, que puede ser binario):

| Tipo | Ejemplo | Para qué |
|------|---------|----------|
| Booleano | `true`, `false` | Banderas (`/NeedAppearances true`). |
| Número | `42`, `-3.5` | Enteros y reales: coordenadas, tamaños, offsets. |
| String | `(Conformidad)`, `<4869>` | Texto o bytes. Literal entre paréntesis o hexadecimal entre `<>`. El `/Contents` de una firma es un string hexadecimal. |
| Nombre | `/Type`, `/Sig` | Identificadores. Las claves de los diccionarios siempre son nombres. |
| Array | `[0 0 595 842]` | Listas heterogéneas. |
| Diccionario | `<< /Type /Page /Count 1 >>` | Pares clave-valor: es la forma de casi todo en un PDF. |
| Stream | `<< /Length 101 >> stream ... endstream` | Un diccionario seguido de bytes: contenido de páginas, imágenes, fuentes, XMP, adjuntos. |
| Null | `null` | La ausencia de valor. |

### Objetos indirectos y referencias

Un objeto puede escribirse **directo** (dentro de otro) o **indirecto**: con un número y una generación, para poder referenciarlo desde cualquier lado.

```
4 0 obj                                ← objeto indirecto número 4, generación 0
<< /Type /Page /Parent 2 0 R ... >>    ← "2 0 R" es una referencia al objeto 2
endobj
```

La **generación** casi siempre es 0. Sólo aumenta cuando un número de objeto se libera y se reutiliza (ver [§5](#5-actualización-incremental-y-revisiones)).

### Streams y filtros

Los bytes de un stream suelen estar **comprimidos** o codificados. El diccionario lo dice en `/Filter`: `/FlateDecode` (zlib, el más común), `/DCTDecode` (JPEG), `/JPXDecode` (JPEG 2000), `/ASCIIHexDecode`, entre otros. `/Length` dice cuántos bytes ocupa. En el ejemplo, el contenido de la página va sin comprimir para que se lea:

```
5 0 obj
<< /Length 101 >>
stream
BT /F1 14 Tf 72 720 Td 18 TL
(Documento base de la suite) '
(PDF 1.7, xref clasica, una pagina.) '
ET
endstream
endobj
```

---

## 3. Estructura física del archivo

Un PDF tiene cuatro partes, en este orden:

```
%PDF-1.7                     ← 1. cabecera: la versión
%âãÏÓ                           (y bytes > 127 para que se lo trate como binario)
1 0 obj ... endobj           ← 2. cuerpo: los objetos indirectos
2 0 obj ... endobj
...
xref                         ← 3. tabla de referencias cruzadas
0 6
0000000000 65535 f
0000000015 00000 n           ← el objeto 1 empieza en el byte 15
0000000064 00000 n           ← el objeto 2, en el 64
0000000121 00000 n
0000000218 00000 n
0000000344 00000 n
trailer                      ← 4. trailer: dónde está el catálogo
<< /Size 6 /Root 1 0 R >>
startxref
496                          ← la xref empieza en el byte 496
%%EOF
```

- La **xref** tiene una entrada de 20 bytes por objeto: el offset (10 dígitos), la generación (5) y `n` (en uso) o `f` (libre). La entrada 0 siempre es libre, con generación 65535: es la cabeza de la lista de objetos libres.
- El **trailer** apunta al **catálogo** (`/Root`) y opcionalmente a `/Info` (metadatos), `/ID` (identificador del archivo) y `/Encrypt` (cifrado).
- `startxref` dice dónde empieza la xref, y `%%EOF` marca el fin.

### Cómo lo lee un lector

Un lector **no** lee el PDF de principio a fin: va al final, busca `startxref`, salta a la xref, lee el trailer y desde ahí resuelve sólo los objetos que necesita. Por eso un PDF de 300 páginas abre en milisegundos, y por eso lo que está **después** del último `%%EOF` es invisible para un lector correcto (pero puede no serlo para uno tolerante).

### Cross-reference streams y object streams (PDF 1.5)

Desde PDF 1.5 la xref puede ser un **stream** comprimido (`/Type /XRef`) en lugar de una tabla de texto, y los objetos pequeños pueden ir agrupados y comprimidos dentro de **object streams** (`/Type /ObjStm`). Es lo que generan Word, LibreOffice y Chrome. Ocupa mucho menos, pero ya no se puede leer el archivo como texto.

Un archivo **híbrido** tiene las dos cosas a la vez: una tabla clásica para lectores viejos y una referencia (`/XRefStm`) a un xref stream para los nuevos. Es una fuente de ambigüedad: dos lectores pueden ver objetos distintos.

### Linearización

Un PDF **linealizado** (*Fast Web View*) reordena los objetos para que la primera página se pueda mostrar antes de descargar el archivo entero, y lo declara en un diccionario `/Linearized` en el primer objeto. Cualquier actualización incremental (una firma) deja la linealización sin efecto, sin otra consecuencia.

> En el código: el análisis informa el tipo de xref de cada revisión (`table`, `stream`, `hybrid`), si hay object streams, si está linealizado y los bytes después del último `%%EOF` (`structure`, `revisions[].xref` de `/document`).

---

## 4. Estructura lógica del documento

Los objetos forman un **árbol** cuya raíz es el catálogo:

```
trailer
 ├── /Root → Catálogo (/Type /Catalog)
 │    ├── /Pages → Árbol de páginas (/Type /Pages)
 │    │    └── /Kids → Página (/Type /Page)
 │    │         ├── /MediaBox    tamaño de la página
 │    │         ├── /Contents    stream(s) con los operadores de dibujo
 │    │         ├── /Resources   fuentes, imágenes y XObjects que usa el contenido
 │    │         └── /Annots      anotaciones: links, comentarios, widgets de formulario
 │    ├── /AcroForm      el formulario interactivo (§6)
 │    ├── /Names         árboles de nombres: adjuntos, JavaScript, destinos
 │    ├── /OpenAction    acción al abrir (§7)
 │    ├── /OCProperties  capas (contenido opcional, §7)
 │    ├── /Metadata      metadatos XMP (incluida la declaración PDF/A)
 │    ├── /Perms         permisos de firma: DocMDP, UR3 (§8)
 │    ├── /DSS           Document Security Store (PAdES B-LT, ver pades.md)
 │    └── /Extensions    extensiones de desarrollador (p. ej. /ESIC para PAdES)
 └── /Info → Metadatos clásicos (/Producer, /Creator, /CreationDate, /ModDate)
```

### El contenido de una página

El stream `/Contents` es un programa con **operadores** en notación postfija (primero los operandos, después el operador). El del ejemplo:

| Operadores | Significado |
|------------|-------------|
| `BT` … `ET` | Empieza y termina un objeto de texto. |
| `/F1 14 Tf` | Usa la fuente `/F1` de `/Resources`, a 14 puntos. |
| `72 720 Td` | Mueve el cursor a (72, 720): una pulgada desde la izquierda, cerca del borde superior (el origen es abajo a la izquierda). |
| `18 TL` | Interlineado de 18 puntos. |
| `(…) '` | Pasa a la línea siguiente y muestra el texto. |

Hay operadores para trazos (`m`, `l`, `re`, `S`, `f`), color, imágenes y XObjects (`Do`), y para el estado gráfico (`q`, `Q`, `cm`). Lo importante para la firma: **lo que se ve es lo que dicen estos streams y sus recursos**. Si cambian, el documento visible cambia.

### Anotaciones y apariencias

Una **anotación** es algo dibujado *sobre* la página que no es parte de su contenido: un link, un comentario, un sello de goma, un resaltado, o un **widget** (la parte visible de un campo de formulario, incluida una firma visible). Cada anotación tiene un rectángulo (`/Rect`) y, normalmente, un **appearance stream** (`/AP`): un pequeño contenido de página que dice cómo dibujarla.

### Metadatos: `/Info` y XMP

Hay dos lugares: el diccionario `/Info` del trailer (clásico, obsoleto en PDF 2.0) y un stream XMP (`/Metadata` del catálogo, XML/RDF). La declaración de conformidad PDF/A vive en el XMP (`pdfaid:part` y `pdfaid:conformance`).

---

## 5. Actualización incremental y revisiones

Para modificar un PDF no hace falta reescribirlo: se puede **agregar al final** una sección con los objetos nuevos o cambiados, una xref que sólo los lista a ellos y un trailer que apunta a la xref anterior con `/Prev`. Los bytes originales quedan intactos. Cada sección agregada es una **revisión**.

La revisión 2 del ejemplo (la que agrega la firma) termina así:

```
xref
0 2                                  ← subsección: objetos 0 y 1
0000000000 65535 f
0000000679 00000 n                   ← el objeto 1 (el catálogo) se reemplaza: ahora está en el byte 679
4 1                                  ← subsección: el objeto 4 (la página)
0000000837 00000 n
7 4                                  ← subsección: los objetos 7 a 10, nuevos
0000000983 00000 n                       7: el /AcroForm
0000001034 00000 n                       8: el campo de firma con su widget
0000001149 00000 n                       9: el diccionario de firma
0000029044 00000 n                      10: el /Info
trailer
<< /Size 11 /Root 1 0 R /Info 10 0 R /ID [<eb5d…> <8fb1…>] /Prev 496 >>
startxref
29146
%%EOF
```

El lector lee primero la xref más nueva; lo que no encuentra ahí lo busca siguiendo `/Prev` hacia atrás. Así, el objeto 1 se lee de su versión nueva (con `/AcroForm`) y el 5 (el contenido de la página, que no cambió) de la original.

Una revisión puede hacer tres cosas con un objeto:

| Qué | Cómo | Ejemplo |
|-----|------|---------|
| **Agregarlo** | Un número nuevo, que no existía. | El diccionario de firma. |
| **Reemplazarlo** | El mismo número, con un offset nuevo. | El catálogo, para sumar `/AcroForm`. |
| **Liberarlo** | Una entrada `f` en la xref, con la generación incrementada. | Borrar un objeto. iText a veces marca así números que nunca escribió. |

El PDF B-LTA del ejemplo tiene cuatro revisiones, que terminan en los bytes 679, 29461, 56088 y 56791:

```
Rev 1  el documento original                                   (679 bytes)
Rev 2  + campo Firma1, su widget, el diccionario de firma       ← cubierta por Firma1
Rev 3  + DSS (certificados, OCSP, CRL) + el /DocTimeStamp       ← cubierta por el sello de documento
Rev 4  + DSS actualizado (VRI del sello)                        ← sin firmar: sólo mantenimiento
```

Esto es lo que hace posible firmar: **una firma cubre los bytes de su revisión**, y lo que se agrega después no los toca. Pero también es lo que hay que vigilar: una revisión posterior puede cambiar lo que se ve sin invalidar criptográficamente la firma (ver [§11](#11-qué-se-puede-cambiar-después-de-firmar) y [§12](#12-ataques-conocidos-contra-las-firmas-pdf)).

> En el código: `adapters/outbound/pyhanko/document_inspector.py::_revisions` recorre cada revisión con la vista histórica de pyHanko (`get_historical_resolver`) y clasifica cada objeto escrito o liberado por su rol en el documento (`document.revisions[].changes`).

---

## 6. Formularios interactivos (AcroForm y XFA)

### AcroForm

El formulario estándar de PDF vive en `/AcroForm` del catálogo. Su `/Fields` lista los **campos**, que forman un árbol: un campo puede tener hijos (`/Kids`) y su nombre completo es la concatenación de los nombres con puntos (`datos.persona.dni`). Lo que no define un campo lo hereda de su padre (tipo, valor, flags).

Cada campo terminal tiene uno o más **widgets**: anotaciones en una página donde se dibuja. Si el campo tiene un solo widget, campo y widget pueden ser el mismo diccionario.

| `/FT` | Tipo | Valor (`/V`) |
|-------|------|--------------|
| `/Tx` | Texto | Un string. |
| `/Btn` | Casilla, opción (radio) o botón, según los flags | El nombre del estado (`/Si`, `/Off`). |
| `/Ch` | Lista o combo | El o los valores elegidos. |
| `/Sig` | **Firma** | El **diccionario de firma** (§9). Un campo de firma sin `/V` está vacío, listo para firmar. |

Los **flags** (`/Ff`) incluyen sólo lectura (bit 1), obligatorio (bit 2) y, para botones, radio (bit 16) y botón (bit 17).

### Apariencias y `NeedAppearances`

Lo que se **ve** de un campo es el appearance stream de su widget, no su valor. Si el formulario tiene `/NeedAppearances true`, el visor **regenera** las apariencias a partir de los valores al abrir el documento. Para un documento firmado es un problema: lo que se muestra puede no ser lo que se firmó, y Acrobat puede marcarlo como modificado. pyHanko genera las apariencias y saca `NeedAppearances` al firmar.

### Acciones de campo

Un campo puede tener **acciones adicionales** (`/AA`): calcular su valor (`/C`), formatearlo (`/F`), validarlo (`/V`), reaccionar al teclado (`/K`). Normalmente son JavaScript.

### XFA

**XFA** (*XML Forms Architecture*) es un formato de formularios de Adobe que viaja dentro del PDF como un XML (`/AcroForm /XFA`). Un visor que lo interpreta (Acrobat) dibuja el formulario desde el XML, y en los formularios XFA "dinámicos" las páginas del PDF son sólo un mensaje para visores que no lo soportan. Está **obsoleto en PDF 2.0**, y PAdES no lo cubre: la firma protege los bytes del XML, pero no hay garantía de que dos visores muestren lo mismo.

> En el código: `form` de `/document` (campos con tipo, valor, flags y acciones; `need_appearances`, `xfa`) y las reglas D-06 en `domain/document.py`.

---

## 7. Contenido activo: acciones, JavaScript, adjuntos y capas

### Acciones

Una **acción** es un diccionario con `/S` (el tipo) que el visor ejecuta ante un evento: al abrir el documento (`/OpenAction`), ante eventos del documento o de una página (`/AA`), al hacer clic en un link o un botón (`/A`), o desde un campo. Las acciones se pueden encadenar con `/Next`.

| Tipo | Qué hace | Riesgo para un documento firmado |
|------|----------|----------------------------------|
| `JavaScript` | Ejecuta un script (Acrobat JavaScript). | Puede cambiar valores, mostrar u ocultar campos, abrir diálogos: cambia lo que se ve sin tocar los bytes firmados. |
| `Launch` | Abre un archivo o un programa. | Alto: ejecuta algo fuera del visor. |
| `SetOCGState`, `Hide` | Prende o apaga capas, muestra u oculta anotaciones. | Cambia lo que se ve. |
| `ImportData`, `Rendition` | Importa datos de formulario, reproduce multimedia. | Cambia lo que se ve. |
| `URI`, `GoTo`, `GoToR`, `SubmitForm` | Abre una URL, navega, envía el formulario. | Bajo: navegan o envían, no cambian el documento. |

El JavaScript a nivel de documento también puede estar en el árbol de nombres `/Names /JavaScript`, y se ejecuta al abrir.

### Archivos adjuntos

Los adjuntos van en `/Names /EmbeddedFiles` (o como anotaciones `/FileAttachment`): un *file specification* (`/Filespec`) con el nombre y un stream `/EmbeddedFile` con los bytes, su tipo MIME (`/Subtype`) y su tamaño (`/Params /Size`). Es lo que usan las facturas electrónicas híbridas (ZUGFeRD/Factur-X) y PDF/A-3. La firma cubre sus bytes, pero no lo que muestre el adjunto al abrirlo con otro programa.

### Capas (contenido opcional)

Las **capas** (*Optional Content Groups*, `/OCProperties`) permiten mostrar u ocultar partes del contenido. La configuración por defecto (`/D`) dice cuáles arrancan apagadas (`/OFF`). Una capa oculta es **contenido firmado que no se ve**, y que un visor, una impresión o una acción pueden mostrar.

> En el código: `active_content` de `/document` y las reglas D-07.

---

## 8. Protección: cifrado, permisos, certificación y bloqueos

"Proteger" un PDF puede significar cuatro cosas muy distintas:

| Mecanismo | Dónde | Qué protege | Qué **no** protege |
|-----------|-------|-------------|--------------------|
| Cifrado | `/Encrypt` del trailer | La confidencialidad: sin la clave no se lee el contenido. | La integridad: no detecta cambios (salvo con el MAC de PDF 2.0). |
| Permisos | `/P` de `/Encrypt` | Nada: son una indicación para el visor. | Quien tiene la clave de propietario, o un programa que los ignore, puede todo. |
| Certificación (DocMDP) | La primera firma y `/Perms /DocMDP` | Qué cambios se aceptan después de certificar. | Lo que el validador no compruebe. |
| Bloqueo de campos (FieldMDP) | `/Lock` del campo de firma | Qué campos no pueden cambiar una vez firmado. | Los demás campos. |

### Cifrado

El cifrado de PDF cifra los **strings y los streams** con una clave simétrica. La **estructura** (los números de objeto, la xref, los nombres, los números) queda en claro, y el `/Contents` de cada firma **nunca** se cifra (ISO 32000-2, §7.6.2), así que la firma se puede validar con la estructura y el CMS a la vista.

Hay dos *handlers*:

- **`/Standard`** (contraseñas): una **contraseña de usuario** (para abrir) y una **de propietario** (para cambiar permisos). Si la de usuario es vacía, cualquiera lo abre; es lo más común ("PDF protegido" que abre sin pedir nada pero no deja imprimir).
- **`/Adobe.PubSec`** (certificados): la clave va cifrada para cada destinatario con su certificado (CMS EnvelopedData). Sólo lo abre quien tiene la clave privada.

| `/V` | `/R` | Algoritmo | Estado |
|------|------|-----------|--------|
| 1 | 2 | RC4 de 40 bits | Roto. |
| 2 | 3 | RC4 de hasta 128 bits | Débil, obsoleto en PDF 2.0. |
| 4 | 4 | RC4 o AES-128 (*crypt filters*: `/V2` o `/AESV2`) | AES-128 aceptable; RC4 no. |
| 5 | 6 | AES-256 (`/AESV3`) | El de PDF 2.0. (La R5 fue una extensión de Adobe con un defecto; se reemplazó por la R6.) |

PDF 2.0 sumó en **ISO/TS 32004** un **MAC** para que el cifrado también detecte manipulaciones (AES-CBC sin autenticar deja inyectar contenido sin conocer la clave).

### Permisos (`/P`)

Un entero de 32 bits; los bits se cuentan desde 1 y un bit apagado **prohíbe** la operación:

| Bit | Permite |
|-----|---------|
| 3 | Imprimir (en baja calidad si el bit 12 está apagado). |
| 4 | Modificar el contenido por otros medios que los de los bits 6, 9 y 11. |
| 5 | Copiar o extraer texto e imágenes. |
| 6 | Agregar o modificar anotaciones y, con el bit 4, completar y crear campos. |
| 9 | Completar campos existentes, **incluidos los de firma**, aunque el bit 6 esté apagado. |
| 10 | Extraer contenido para accesibilidad (obsoleto en PDF 2.0: siempre se permite). |
| 11 | Insertar, rotar o borrar páginas, y armar marcadores y miniaturas. |
| 12 | Imprimir en alta calidad. |

Para poder **firmar** hace falta el bit 9, o los bits 4 y 6.

### Certificación (DocMDP)

Una **firma de certificación** (o "firma de autor") es la primera firma de un documento, y además de firmar declara **qué cambios se aceptan** después. Su diccionario de firma tiene un `/Reference` con la transformación `/DocMDP` y un parámetro `P`, y el catálogo la apunta desde `/Perms /DocMDP`:

| P | Cambios permitidos después de certificar |
|---|------------------------------------------|
| 1 | Ninguno. Cualquier cambio, incluida otra firma, invalida la certificación. |
| 2 | Completar formularios, firmar campos de firma existentes y crear sellos de documento. (Es el valor por defecto.) |
| 3 | Lo de P=2, más agregar, modificar y borrar anotaciones. |

ISO 32000 exige que la certificación sea **la primera firma** del documento; una certificación posterior no vale. Es el flujo de un trámite que un organismo certifica (P=2) y el ciudadano completa y firma.

### Bloqueo de campos (FieldMDP)

Un campo de firma puede declarar en `/Lock` que, una vez firmado, ciertos campos quedan bloqueados: `/Action /All` (todos), `/Include` (los de `/Fields`) o `/Exclude` (todos menos los de `/Fields`). La firma lleva una transformación `/FieldMDP`.

### Derechos de uso (UR3)

`/Perms /UR3` es una firma de Adobe que **habilita funciones** en Adobe Reader (guardar formularios completados, comentar). No es una firma de autor ni dice nada del contenido, y cualquier modificación la invalida (Reader deja de ofrecer esas funciones), sin afectar las firmas del documento.

> En el código: `protection` de `/document` y las reglas D-01 a D-04. Un PDF que pide contraseña para abrirse se rechaza con 422 (D-03), en `/document`, en `/verify` y en `/sign` (S-01).

---

## 9. La firma digital dentro del PDF

Una firma en un PDF son **tres piezas** enlazadas:

```
Catálogo
 └── /AcroForm
      └── /Fields [ … ]
           └── Campo de firma (/FT /Sig, /T (Firma1))   ← también es el widget: /Subtype /Widget, /Rect, /P
                └── /V → Diccionario de firma (/Type /Sig)
                          ├── /Filter, /SubFilter
                          ├── /ByteRange [0 1170 28798 663]
                          ├── /Contents <3082…>         ← el CMS, en hexadecimal
                          └── /M, /Reason, /Location, …
```

El diccionario de firma de la revisión 2 del ejemplo (el `/Contents` recortado):

```
9 0 obj
<<
/Contents <308223F506092A864886F70D010702A0…0000000000>
/ByteRange [0 1170 28798 663]
/Type /Sig
/Filter /Adobe.PPKLite
/SubFilter /ETSI.CAdES.detached
/M (D:20261020195119-03'00')
/Location (Buenos Aires, AR)
/Reason (Conformidad)
>>
endobj
```

| Entrada | Significado |
|---------|-------------|
| `/Type` | `/Sig` para una firma; `/DocTimeStamp` para un sello de tiempo de documento. |
| `/Filter` | El *handler* preferido para validarla (`/Adobe.PPKLite`, casi siempre). |
| `/SubFilter` | El formato del contenido de `/Contents` (ver abajo). |
| `/ByteRange` | Qué bytes del archivo cubre la firma: dos tramos `[inicio1 largo1 inicio2 largo2]`. |
| `/Contents` | La firma: un CMS (o un TimeStampToken) en hexadecimal, rellenado con ceros hasta el espacio reservado. |
| `/M` | La hora de firma que declara el firmante (no probada: la que cuenta es la del sello de tiempo). |
| `/Reason`, `/Location`, `/ContactInfo`, `/Name` | Informativos. |
| `/Reference` | Las transformaciones: `/DocMDP` (certificación), `/FieldMDP` (bloqueo), `/UR3`. |
| `/Prop_Build` | Qué programa firmó (`/App /Name`). |
| `/Cert` | Sólo con `/adbe.x509.rsa_sha1`: el certificado, porque no hay CMS. |

| `/SubFilter` | Contenido | Estado |
|--------------|-----------|--------|
| `/adbe.pkcs7.detached` | CMS *detached* sobre los bytes del ByteRange. | La firma PDF "clásica", vigente; no es PAdES. |
| `/ETSI.CAdES.detached` | CMS con el perfil CAdES (con `signing-certificate-v2`). | **PAdES** (PDF 2.0, ETSI EN 319 142). |
| `/ETSI.RFC3161` | Un TimeStampToken RFC 3161 sobre el ByteRange. | Sello de documento (PAdES B-LTA). |
| `/adbe.pkcs7.sha1` | CMS que firma un SHA-1 del documento. | Obsoleto en PDF 2.0. |
| `/adbe.x509.rsa_sha1` | Una firma RSA PKCS#1 sin CMS. | Obsoleto en PDF 2.0. |

### ByteRange y `/Contents`

La firma no puede cubrir el archivo entero, porque va **adentro** del archivo. Entonces se reserva un hueco para `/Contents` y se firma todo lo demás de la revisión:

```
byte 0 ────────────────── 1170 │ 1170 ───── <3082…0000> ───── 28798 │ 28798 ─────────── 29461
     /ByteRange tramo 1        │       /Contents (no cubierto)      │  /ByteRange tramo 2  ↑
     cubierto por la firma     │       27.628 caracteres hex        │  cubierto            %%EOF de la rev 2
```

Un ByteRange **regular** cumple cuatro condiciones, y un validador debería exigirlas todas:

1. Tiene cuatro números y empieza en 0.
2. El hueco entre los dos tramos es **exactamente** el string hexadecimal `<…>` de `/Contents`, con sus delimitadores.
3. El segundo tramo termina justo después del `%%EOF` de la revisión: la firma cubre **su revisión completa**, no un bloque arbitrario.
4. El CMS, al decodificarlo, mide menos que el espacio reservado; el resto son ceros (en el ejemplo, 9.209 de 13.813 bytes).

### Firma visible e invisible

El widget de la firma puede tener un rectángulo con área (firma **visible**: un sello con el nombre, la fecha o una imagen) o un rectángulo vacío (firma **invisible**, como las de la PoC). La apariencia de una firma visible es un dibujo **más**, no una prueba: lo que prueba la firma es el CMS. Un visor muestra "firma válida" en su panel de firmas, no en el sello.

> En el código: `signature_dictionaries` de `/document` (una card por firma en la tab Documento de la UI), reglas D-08.

---

## 10. Cómo se firma de forma incremental, paso a paso

Lo que hace pyHanko (y cualquier firmante correcto) en `/sign`:

1. **Abrir el PDF** y leer su última revisión. Si está cifrado, autenticarse (la PoC rechaza los cifrados, regla S-01).
2. **Armar la revisión nueva** en memoria, sin tocar los bytes originales:
   - el **campo de firma** con su widget (y agregarlo a `/AcroForm /Fields` y a `/Annots` de la página);
   - el **diccionario de firma** con `/Contents` como un hueco de ceros del tamaño estimado del CMS (`<0000…0000>`) y un `/ByteRange` provisorio con espacio de sobra (`[0 0 0 0]` seguido de espacios);
   - las versiones nuevas del catálogo (si hace falta sumar `/AcroForm` o `/Extensions`) y de la página.
3. **Escribir la revisión** al final del archivo: los objetos, la xref (sólo con los objetos nuevos o cambiados), el trailer con `/Prev` y el `%%EOF`.
4. **Calcular el ByteRange real**: la posición del `<` y del `>` de `/Contents` y el largo total, y **sobrescribir** el ByteRange provisorio en su lugar. Por eso se reservó espacio: el largo del archivo no cambia y ningún offset se corre (en el ejemplo, el ByteRange tiene espacios al final).
5. **Hashear los dos tramos** (SHA-256 en la PoC). Ese hash es el que se firma.
6. **Armar el CMS** con los atributos firmados (entre ellos `message-digest`, el hash del paso 5, y `signing-certificate-v2`), **firmarlo** con la clave privada y, para B-T, pedir el **sello de tiempo** sobre el valor de la firma y agregarlo como atributo no firmado ([pades.md §7](pades.md#7-cms-el-contenedor-de-la-firma)).
7. **Escribir el CMS en hexadecimal** dentro del hueco de `/Contents`, rellenando con ceros. Si no entra, hay que volver a empezar con un hueco más grande.
8. Para **B-LT** y **B-LTA**, agregar más revisiones: una con el **DSS** (certificados, OCSP, CRLs) y, para B-LTA, un **sello de documento** (`/DocTimeStamp`), que es otra firma con el mismo procedimiento cuyo `/Contents` es un TimeStampToken.

Al **validar** se hace el camino inverso: tomar los bytes del ByteRange, hashearlos, comparar con el `message-digest` del CMS (integridad), verificar la firma del CMS con el certificado (validez) y construir la cadena hasta un ancla con su revocación (confianza). Después queda la parte que es específica de PDF: **revisar lo que se agregó después** de la revisión firmada.

> En el código: `adapters/outbound/pyhanko/signer.py` (firma) y `validator.py` (validación); `IncrementalPdfFileWriter` de pyHanko escribe la revisión.

---

## 11. Qué se puede cambiar después de firmar

Una firma garantiza que **su revisión** no cambió. Que el **documento** que se ve siga siendo el firmado depende de qué agregan las revisiones posteriores. Hay cambios legítimos y esperables:

- otra firma (co-firma), en una revisión nueva;
- el DSS y los sellos de documento (PAdES B-LT y B-LTA);
- completar campos de formulario o agregar anotaciones, si el DocMDP lo permite;
- actualizar metadatos.

Y cambios que alteran lo que se ve: reemplazar el contenido de una página, agregar o quitar páginas, cambiar fuentes o imágenes, agregar acciones que se ejecutan al abrir, prender o apagar capas.

pyHanko lo evalúa con su **análisis de diferencias** (*diff analysis*): compara cada revisión posterior con la firmada y acepta sólo los cambios de una lista blanca. El resultado es el nivel de modificación de la firma (`modifications.level` en `/verify`): `NONE`, `LTA_UPDATES`, `FORM_FILLING`, `ANNOTATIONS` u `OTHER` (sospechoso), y si respeta el DocMDP. Si es sospechoso, la firma no pasa (`bottom_line: false`); ver [pades.md](pades.md#análisis-de-modificaciones-diff_policy).

La API agrega además un análisis **por revisión** que no da un veredicto sino una explicación: qué objetos escribió cada revisión, qué son y qué tan riesgoso es (ver [§13](#13-el-análisis-del-documento-en-esta-api)). Así, cuando pyHanko dice "sospechoso", se ve **qué** cambió.

---

## 12. Ataques conocidos contra las firmas PDF

Investigadores de la Ruhr-Universität Bochum mostraron entre 2019 y 2021 que la mayoría de los visores aceptaban documentos manipulados como firmados. Los ataques explotan justamente la estructura descrita arriba:

| Ataque | Idea | Qué lo detecta |
|--------|------|----------------|
| **USF** (*Universal Signature Forgery*) | Un diccionario de firma roto (sin `/Contents`, ByteRange vacío o nulo) que el visor no valida pero igual muestra como firmado. | Validar que haya CMS y ByteRange regular; un error no es "válido". |
| **ISA** (*Incremental Saving Attack*) | Agregar una revisión que cambia el contenido; el visor no avisa o lo presenta como un cambio permitido. | Analizar las revisiones posteriores a la firma. |
| **SWA** (*Signature Wrapping Attack*) | Mover el segundo tramo del ByteRange y meter contenido nuevo en el "hueco" o después, de modo que lo firmado siga intacto pero el lector lea otra cosa. | Exigir que el hueco sea exactamente `/Contents` y que el ByteRange termine en el `%%EOF` de su revisión. |
| **Shadow attacks**: *hide*, *replace*, *hide-and-replace* | El documento firmado ya trae contenido "en la sombra" (un objeto sin usar, una capa oculta, una fuente alternativa); una revisión posterior **inocente para el diff** (p. ej. una referencia o el valor de un campo) lo hace visible. | Clasificar los cambios por su efecto sobre lo que se ve, no sólo por su tipo; desconfiar de capas ocultas y de cambios en recursos. |
| **EAA** y **SSA** (contra certificación) | En un documento certificado P=2 o P=3, agregar anotaciones (EAA) o un campo de firma con una apariencia (SSA) que tapan el contenido, usando cambios "permitidos". | Mostrar qué anotaciones y campos se agregaron después de certificar. |

No hay una regla que los detenga a todos; la defensa es **no confiar sólo en "la firma es válida"** y mirar qué pasó en el documento después de firmar. Es lo que hacen pyHanko (diff analysis estricto, rechazo de xref híbridas en revisiones posteriores a una firma) y el análisis de esta API.

---

## 13. El análisis del documento en esta API

`POST /document` recibe un PDF (firmado o no) y devuelve el análisis del documento. **No valida firmas** ni cambia su veredicto (`bottom_line` y `pades_level` los decide `/verify`): explica y agrega lo que la validación no mira.

La arquitectura es la de siempre ([docs/arquitectura](arquitectura/README.md)): el caso de uso `AnalyzeDocument` usa el puerto `PdfInspector` (implementado con pyHanko en `adapters/outbound/pyhanko/document_inspector.py`) **lee los hechos** sin opinar, y el dominio (`domain/document.py::analyze`) decide qué significan, con las reglas D-01 a D-10 de [invariantes.md](arquitectura/invariantes.md#documento-d).

### Hallazgos

Cada hallazgo tiene un `code` estable, una `severity`, un `area` y un `message`, y se ordenan de más a menos grave:

| Severidad | Significado | Ejemplos (`code`) |
|-----------|-------------|-------------------|
| `critical` | Lo que se ve, o lo que se firmó, pudo cambiar: no alcanza con que la firma sea válida. | `content_changed_after_signing`, `page_count_changed`, `irregular_byte_range`, `byte_range_not_revision`, `certification_not_first`, `executable_actions` (con Launch) |
| `warning` | Conviene revisarlo: lo que se ve puede no ser exactamente lo firmado. | `annotations_or_fields_after_signing`, `need_appearances`, `xfa`, `executable_actions`, `hidden_layers`, `weak_encryption`, `signing_not_permitted`, `trailing_bytes`, `hybrid_xref`, `unreadable` |
| `info` | Para saber. | `encrypted`, `restricted_permissions`, `certified`, `field_lock`, `usage_rights`, `empty_signature_fields`, `field_actions`, `embedded_files`, `navigation_actions`, `unsigned_last_revision`, `trailing_padding`, `linearized`, `subfilter:adbe.pkcs7.detached` |

### Cómo se juzga cada revisión (D-05)

Las revisiones anteriores o iguales a la primera firma son el documento firmado: no se juzgan. Para cada revisión posterior, cada objeto escrito o liberado se clasifica por su **rol** en el documento (no por su tipo: un stream es "contenido de página" porque una página lo usa en `/Contents`), y la revisión toma el riesgo de su cambio más grave:

| Objeto | Riesgo |
|--------|--------|
| Contenido de página, recursos (fuentes, imágenes, XObjects), árbol de páginas, una página nueva o con cambios fuera de `/Annots`, acciones | `critical` |
| Claves del catálogo que deciden qué se ve: `/Pages`, `/OpenAction`, `/AA`, `/OCProperties` | `critical` |
| Anotaciones, campos de formulario, adjuntos, otras claves del catálogo (`/Names`, `/OutputIntents`…), `/AcroForm` fuera de `/Fields` (p. ej. `NeedAppearances`) | `warning` |
| Firmas y sus widgets, una página que sólo cambia `/Annots`, el DSS, metadatos, `/AcroForm /Fields`, objetos internos (object streams, entradas libres de objetos que nunca existieron) | `info` |

La clasificación es **conservadora a propósito**: es una explicación para una persona, no un validador. pyHanko sigue siendo el que decide si la firma pasa.

### Lo que no se pudo leer (D-10)

El análisis lee cada sección por separado (estructura, protección, formulario, contenido activo, revisiones, diccionarios de firma). Si una falla con un PDF raro, las demás se leen igual y el problema aparece como un hallazgo `unreadable`. Lo único que corta es un PDF que no se puede abrir: dañado o con contraseña (422, regla D-03).

### Respuesta

Un PDF firmado en B-LTA por la PoC (recortado):

```json
{
  "summary": { "info": 1, "warning": 0, "critical": 0 },
  "findings": [
    { "code": "unsigned_last_revision", "severity": "info", "area": "content",
      "message": "La última revisión (4) no está firmada: agrega sólo material de mantenimiento (DSS, firmas, metadatos), que no cambia lo que se ve." }
  ],
  "structure": { "version": "1.7", "pages": 1, "revisions": 4, "hybrid_xref": false, "object_streams": false,
                 "pdfa": null, "producer": "pyHanko 0.37.0", "trailing_bytes": 0, "extensions": ["ESIC 1"], "…": "…" },
  "protection": { "encryption": null, "certification": null, "field_locks": [], "usage_rights": false },
  "form": { "need_appearances": false, "xfa": false,
            "fields": [ { "name": "Firma1", "type": "signature", "signed": true, "…": "…" } ] },
  "active_content": { "actions": [], "embedded_files": [], "optional_content": null },
  "revisions": [
    { "number": 2, "end_offset": 29461, "xref": "table", "signed_by": ["Firma1"], "after_signature": false, "severity": "info",
      "changes": [
        { "object": "1 0", "kind": "catalog", "change": "modified", "keys": ["/AcroForm", "/Extensions"], "…": "…" },
        { "object": "3 0", "kind": "page", "change": "modified", "page": 1, "keys": ["/Annots"], "…": "…" },
        { "object": "9 0", "kind": "signature", "change": "added", "…": "…" }
      ] },
    "…"
  ],
  "signature_dictionaries": [
    { "field": "Firma1", "type": "/Sig", "subfilter": "/ETSI.CAdES.detached",
      "byte_range": [0, 1170, 28798, 663], "byte_range_regular": true, "covers_revision": true, "revision": 2,
      "contents": { "capacity": 13813, "used": 9209 }, "signing_time": "D:20261020195119-03'00'",
      "reason": "Conformidad", "location": "Buenos Aires, AR", "visible": false, "page": 1, "…": "…" }
  ]
}
```

| Campo | Significado |
|-------|-------------|
| `summary` | Cuántos hallazgos hay de cada severidad. |
| `findings` | Los hallazgos, de más a menos grave. |
| `structure` | Versión efectiva (la mayor entre la cabecera y `/Version` del catálogo), páginas, revisiones, xref híbrida, object streams, linealización, etiquetado, PDF/A declarado, productor, bytes después del último `%%EOF` y extensiones. |
| `protection` | Cifrado (algoritmo, bits, revisión del handler y permisos decodificados), certificación (P, su significado y si es la primera firma), bloqueos FieldMDP y derechos de uso. |
| `form` | `null` si no hay formulario. Cada campo con su nombre completo, tipo, valor (recortado a 200 caracteres), sólo lectura, obligatorio, si está firmado (campos de firma) y si tiene acciones. |
| `active_content` | Acciones (tipo y dónde están), adjuntos (nombre, tamaño y tipo MIME) y capas (cuántas y cuántas ocultas). |
| `revisions` | Cada revisión: dónde termina, tipo de xref, cuántos objetos escribe, páginas, qué firmas la cierran, si es posterior a la primera firma, su riesgo y cada objeto (`kind`, `change`: `added`, `modified` o `freed`, página, `/Subtype` y claves cambiadas, con su camino si están anidadas: `/AcroForm/NeedAppearances`). |
| `signature_dictionaries` | Cada firma y sello de documento tal como está en el PDF: ByteRange y si es regular y cubre su revisión, espacio de `/Contents` reservado y usado, `/M`, motivo, lugar, programa, transformaciones, visibilidad y página. |

### En la UI

La tab **Documento** de `/ui/firmas` pide `POST /document` en paralelo con las demás. Muestra un resumen (hallazgos, versión y páginas, revisiones, protección, formulario y contenido activo), una card con los hallazgos, otra con la estructura y la protección (con los permisos uno por uno), otra con el formulario y el contenido activo, una por cada diccionario de firma y una con cada revisión y sus objetos. La etiqueta de la tab dice lo más grave que hay (`2 críticos`, `1 aviso` u `OK`). Está en `static/document.js`.

### Casos de la suite

Con la [suite de PDFs](../testdata/pdf-suite/README.md) se ve cada regla en acción: P06 (`content_changed_after_signing`, crítico), S03 y S04 (`certified`, P=1 y P=2), S02 (`encrypted`, AES-256), S01 (422 por contraseña de apertura), F03 (`empty_signature_fields`), C07 (`embedded_files`), T01 (`trailing_padding`), P03 (`subfilter:adbe.pkcs7.detached`). Los que no traen firmas también se analizan: `/document` no las exige (p. ej. F02, `need_appearances`).

---

## 14. Glosario

| Término | Definición |
|---------|------------|
| **Anotación** | Algo dibujado sobre una página que no es parte de su contenido: link, comentario, sello, widget. |
| **Appearance stream** (`/AP`) | El dibujo de una anotación o de un widget. |
| **ByteRange** | Los dos tramos de bytes que cubre una firma; el hueco entre ellos es `/Contents`. |
| **Catálogo** (`/Root`) | La raíz del árbol de objetos del documento. |
| **Certificación** (DocMDP) | Primera firma de un documento que fija qué cambios se aceptan después (P=1, 2 o 3). |
| **Contenido opcional** (capas) | Partes del contenido que se pueden mostrar u ocultar (`/OCProperties`). |
| **Diccionario de firma** | El `/V` de un campo de firma: `/ByteRange`, `/Contents`, `/SubFilter`, `/M`… |
| **FieldMDP** | Bloqueo de campos que se activa al firmar un campo de firma (`/Lock`). |
| **Linearización** | Reordenamiento para mostrar la primera página antes de terminar la descarga. |
| **NeedAppearances** | Pide al visor que regenere las apariencias de los campos al abrir. |
| **Object stream** | Un stream que contiene objetos comprimidos (PDF 1.5). |
| **Objeto indirecto** | Un objeto con número y generación, referenciable con `n g R`. |
| **Revisión** | Cada sección agregada por actualización incremental: objetos, xref, trailer y `%%EOF`. |
| **Stream** | Un diccionario seguido de bytes (contenido, imágenes, fuentes, XMP). |
| **SubFilter** | El formato del contenido de una firma (`/ETSI.CAdES.detached`, `/adbe.pkcs7.detached`…). |
| **Trailer** | El diccionario al final de cada revisión que apunta al catálogo y a la revisión anterior. |
| **UR3** | Derechos de uso de Adobe Reader: una firma de Adobe que habilita funciones, no de autor. |
| **Widget** | La anotación donde se dibuja un campo de formulario. |
| **XFA** | Formularios de Adobe en XML dentro del PDF; obsoletos en PDF 2.0. |
| **XMP** | Metadatos en XML/RDF (`/Metadata`), donde va la declaración PDF/A. |
| **Xref** | La tabla (o stream) que dice en qué byte empieza cada objeto. |

---

## 15. Referencias

| Documento | Qué cubre |
|-----------|-----------|
| ISO 32000-1:2008 | PDF 1.7 (disponible gratis de Adobe como "PDF Reference, sixth edition" y "ISO 32000-1"). |
| ISO 32000-2:2020 | PDF 2.0: sintaxis (§7), cifrado (§7.6), contenido (§8–9), formularios (§12.7), firmas digitales (§12.8). |
| ISO/TS 32004:2024 | Protección de integridad (MAC) en documentos cifrados. |
| ISO 19005 (partes 1 a 4) | PDF/A. |
| ETSI EN 319 142-1 | PAdES: perfiles baseline (B-B, B-T, B-LT, B-LTA). |
| Mladenov, Mainka, Meyer zu Selhausen, Grothe, Schwenk. *1 Trillion Dollar Refund: How To Spoof PDF Signatures*. ACM CCS 2019 | USF, ISA y SWA. |
| Mainka, Mladenov, Rohlmann. *Shadow Attacks: Hiding and Replacing Content in Signed PDFs*. NDSS 2021 | Shadow attacks. |
| Mainka, Mladenov, Rohlmann, Schwenk. *Breaking the Specification: PDF Certification*. IEEE S&P 2021 | EAA y SSA contra documentos certificados. |
| [pdf-insecurity.org](https://pdf-insecurity.org) | Resumen de los ataques y de qué visores eran vulnerables. |
| [Documentación de pyHanko](https://docs.pyhanko.eu) | Lector, firma, validación y análisis de diferencias. |
