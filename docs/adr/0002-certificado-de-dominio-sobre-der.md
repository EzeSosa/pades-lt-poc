# ADR-0002: El certificado de dominio se construye sobre el DER

**Estado**: Aceptado (2026-10-18)

## Contexto

Las cuatro operaciones de negocio giran alrededor de certificados X.509, y hoy circulan tres representaciones:

- `cryptography.x509.Certificate`: parseo de DER/PEM/PKCS#7, extensiones legibles, verificación de quién emitió a quién (`/certificates`, `/certificates/inspect`, la fuente).
- `asn1crypto.x509.Certificate`: lo que pyHanko y pyhanko-certvalidator reciben como anclas de confianza, intermedios y certificados del DSS (`/verify`, `/sign`).
- Los objetos que devuelve pyHanko al validar (`ValidationPath`, el `signing_cert` de cada estado), que también son de `asn1crypto`.

Cada servicio convierte entre ellas donde le hace falta. Por ejemplo, `CertificateExtractor.extract` serializa a DER los certificados de la fuente (`cryptography`) para volver a cargarlos con `asn1crypto`, y la fuente guarda los dos tipos en su snapshot. Las reglas de negocio que miran certificados (sólo CAs en la fuente, sólo raíces confiables, vigencia, de dónde salió cada eslabón) quedan escritas contra la API de una u otra biblioteca.

El dominio (ADR-0001) no puede depender de ninguna de las dos.

## Decisión

El dominio tiene su propio `Certificate` (`domain/certificates.py`), un `dataclass(frozen=True)` con:

- **`der`**: los bytes del certificado. Es su **identidad**: dos certificados son el mismo si y sólo si su DER es el mismo. Igualdad y hash miran sólo este campo.
- **Los datos que usan las reglas**, ya calculados: huellas SHA-256 y SHA-1, sujeto y emisor (RFC 4514), número de serie, vigencia (con zona horaria), si es CA (`basicConstraints`) y si es autofirmado (verificado con su propia clave, no sólo por nombre).
- **Comportamiento puro** sobre esos datos: `validity_status(now)`, `days_left(now)`, `ca_kind` (raíz, intermedio o ninguno).

Lo construye el puerto `CertificateCodec` (`application/ports.py`), cuya implementación sobre `cryptography` es `CryptographyCertificateCodec` (`adapters/outbound/crypto/codec.py`). El dominio nunca parsea ASN.1 ni verifica firmas: si una regla necesita saber si un certificado firmó a otro, se lo pregunta al codec (`issued_by`).

Cada adaptador que necesita la representación de su biblioteca la obtiene del DER (`x509.load_der_x509_certificate(cert.der)`, `asn1crypto.x509.Certificate.load(cert.der)`) y, si la usa varias veces en un pedido, la conserva él mismo.

## Alternativas descartadas

- **Envolver `asn1crypto.x509.Certificate`** (o el de `cryptography`) en el dominio. Ahorra conversiones, pero ata el dominio a una biblioteca, y la regla de dependencias del ADR-0001 dejaría de cumplirse.
- **Un certificado de dominio "perezoso"** que guarda el DER y parsea al pedir cada atributo. Necesita una biblioteca de ASN.1 dentro del dominio, o un parser propio, que es justamente lo que no hay que escribir.
- **Usar sólo la huella SHA-256 como identidad**. Es lo que hace la fuente (columna `sha256` única). Pero un `Certificate` con su DER sirve también para pasarlo a los adaptadores sin volver a buscarlo. La huella sigue siendo la clave de la fuente: es función del DER, así que son equivalentes.

## Consecuencias

- Las reglas sobre certificados se prueban con `Certificate`s armados a mano, sin PKI (`tests/test_domain_certificates.py`).
- Parsear tiene un costo: el codec calcula todos los campos aunque una regla use uno solo, incluida la verificación de la autofirma. Para los volúmenes de la PoC (una cadena por firma, decenas de certificados en la fuente) es despreciable.
- Un mismo certificado puede tener a la vez su versión de dominio y la de una biblioteca dentro de un adaptador. El DER es la fuente de verdad, así que no pueden desincronizarse.
- La `ValidityStatus` y la `CaKind` usan los mismos valores que la API (`valid`/`expired`/`not_yet_valid`, `root`/`intermediate`), así que los presenters no necesitan traducirlas.
