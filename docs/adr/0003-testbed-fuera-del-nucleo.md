# ADR-0003: La PKI, el OCSP y la TSA de la PoC son un testbed fuera del núcleo

**Estado**: Aceptado (2026-10-18)

## Contexto

Para firmar y validar sin depender de terceros, la PoC trae su propia mini PKI (`pki.py`: raíz, intermedia, firmante, TSA y respondedor OCSP, con sus CRLs y revocación manual), un motor de TSA (`services/timestamping.py`) y los endpoints que los publican (`routers/pki.py`, `ocsp.py`, `tsa.py`). La app se consulta a sí misma por HTTP al firmar, como si fueran servicios externos.

Hasta el paso 6 de la migración, esa PKI estaba en el mismo plano que la lógica de negocio:

- El firmante (`PdfSigner.from_pki`) y el verificador (`SignatureVerifier.from_pki`) leían sus claves y certificados de `pki.py`.
- La ubicación de la base de la fuente se calculaba a partir de `pki.PKI_DIR`.
- Los routers de la PKI, el OCSP y la TSA compartían `dependencies.py` con los de negocio.

En un sistema real nada de esto existe: la CA, el OCSP y la TSA son de un tercero, y el firmante usa una identidad (un token, un HSM, un archivo) que no sabe cómo se emitió. Mezclarlos hace difícil ver qué parte de la PoC es el producto y cuál es el andamiaje, y ata el producto a una PKI que se regenera en cada instalación.

## Decisión

La PKI, el motor de la TSA y sus endpoints forman el paquete `pades_lt_poc.testbed`:

| Módulo | Contenido |
|--------|-----------|
| `testbed/__init__.py` | `Testbed(pki, tsa_engine)` y `Testbed.create(directorio, url_base)`. |
| `testbed/pki.py` | `MiniPki`: certificados, claves, CRLs, OCSP y revocación. |
| `testbed/tsa.py` | `load_tsa(pki)`: el `DummyTimeStamper` de pyHanko con el certificado de la TSA. |
| `testbed/http.py` | `create_router(get_testbed)`: `/pki`, `/ocsp` y `/tsa`. Recibe una función que saca el testbed del pedido, así no depende de cómo lo guarda la app. |

Reglas, verificadas con import-linter:

1. **El núcleo no conoce al testbed.** Ni el dominio, ni la aplicación, ni los adaptadores, ni los endpoints de negocio (`routers/`, `dependencies.py`) lo importan, tampoco de forma indirecta. Por eso `dependencies.py` no importa `bootstrap`.
2. **El testbed no conoce al núcleo.** No importa el dominio, la aplicación, los adaptadores ni los endpoints de negocio: es el mundo externo, y no depende de quien lo consume.
3. **Sólo la raíz de composición los conecta.** `bootstrap.build` crea el testbed y le saca lo que el núcleo necesita, como configuración:
   - la identidad del firmante (archivos de clave, certificado y cadena) para `PyHankoPdfSigner.from_files`;
   - la raíz de la PoC, como ancla implícita de `VerifySignatures` (V-01);
   - el motor de la TSA, que publican los endpoints del testbed.

   `app.py` monta los endpoints del testbed con `create_router`.

## Alternativas descartadas

- **Dejar la PKI donde estaba y sólo inyectarla.** Sacaba el acoplamiento del código, pero no de la estructura: el paquete seguiría mezclando producto y andamiaje.
- **Sacar el testbed a otro proceso o paquete.** Sería lo más realista, pero la PoC perdería su propiedad más útil: levantar una sola app que firma y valida de punta a punta. Separarlo en un paquete con reglas de dependencias logra lo mismo en la estructura sin cambiar cómo se usa.
- **Un puerto `TrustAnchors` / `SigningCredentials` en la aplicación.** El firmante y las anclas implícitas son configuración fija de la instancia, no algo que un caso de uso consulte. Pasarlos al construir los adaptadores y los casos de uso es más simple y deja el mismo desacople.

## Consecuencias

- Para usar otra identidad de firma (un PKCS#12, un HSM), sólo cambia `bootstrap.build`: el caso de uso `SignPdf` y el puerto `PdfSigningEngine` no se tocan. Lo mismo para usar una TSA externa: hoy la URL sale del pedido (`<base_url>/tsa`).
- Los tests siguen usando la PKI del testbed (`tests/conftest.py` la importa de `pades_lt_poc.testbed.pki`) para firmar PDFs de prueba, revocar y armar CRLs y respuestas OCSP.
- La API no cambia: `/pki`, `/ocsp` y `/tsa` siguen en las mismas rutas.
