# Adaptadores

Los adaptadores conectan la aplicación con el exterior. Los **de salida** (`adapters/outbound/`) implementan los [puertos](puertos.md) con una biblioteca concreta. Los **de entrada** (por ahora, los `routers/` de FastAPI) traducen un pedido externo a un caso de uso.

Un adaptador de salida no conoce HTTP, ni la raíz de composición, ni el código que todavía no se migró (`services/`, `pki.py`). Lo verifica el contrato "Los adaptadores de salida no conocen HTTP, la composición ni el código sin migrar" de import-linter.

> Este documento crece con la migración. Hoy tiene el codec de certificados (paso 2).

## `adapters/outbound/crypto/codec.py`: certificados con `cryptography`

Implementa [`CertificateCodec`](puertos.md#certificatecodec) con la clase `CryptographyCertificateCodec`.

### Cómo parsea

`parse` prueba los formatos en orden y se queda con el primero que funciona: DER, PEM (uno o varios), PKCS#7 DER y PKCS#7 PEM (`parse_certs`). Si ninguno funciona, quita los espacios y saltos de línea, decodifica como base64 estricto y vuelve a probar (`load_certs`). Si tampoco funciona, lanza `UnprocessableCertificate`.

Cada certificado se convierte al de dominio con `to_domain`: huellas sobre el DER, sujeto y emisor en RFC 4514 (`Name.rfc4514_string()`), vigencia en UTC (`not_valid_*_utc`), `is_ca` desde `basicConstraints` y `self_signed` verificando la firma con su propia clave.

### SHA-1: verificación a mano

`cryptography` se niega a verificar firmas SHA-1: `verify_directly_issued_by` lanza `ValueError("Unsupported signature algorithm")`. Pero la AC Raíz de Argentina 2007 firma con SHA-1 a la AC ONTI, emisora de los certificados de CiDi, y sin esa verificación no se puede armar la cadena ni saber que la raíz es autofirmada.

`issued_by` captura ese error puntual y verifica a mano (`_verify_legacy`): compara el emisor de `cert` con el sujeto de `issuer` y verifica la firma sobre el `tbsCertificate` con la clave del emisor, con PKCS#1 v1.5 (RSA) o ECDSA y el hash que declara el certificado. Cualquier otro error (clave de otro tipo, firma inválida) da `False`.

Esto no relaja ninguna política de validación: sólo responde quién firmó a quién. La validación de firmas sigue rechazando SHA-1 salvo para lo que firman las raíces confiables que nacieron con SHA-1 (ver [pades.md](../pades.md#caso-real-pki-de-firma-digital-de-argentina)).

### Funciones sobre `cryptography.x509.Certificate`

Mientras se migran la extracción de cadenas y la inspección (paso 4), el módulo expone también funciones sobre objetos de `cryptography`, que usan `services/certificates.py` y `services/inspection.py`:

| Función | Qué hace | La usa |
|---------|----------|--------|
| `parse_certs(data)` | DER, PEM o PKCS#7; `ValueError` si no es ninguno. Sin base64: es lo que se publica en AIA. | Descarga AIA (`AiaFetcher`) |
| `load_certs(data)` | `parse_certs` más base64; `UnprocessableCertificate`. | Inspección |
| `issued_by(cert, issuer)` | La verificación de emisor, con el caso SHA-1. | Armado de cadenas, inspección |
| `is_ca(cert)` | `basicConstraints` `cA`. | Inspección |
| `to_domain(cert)` | `cryptography` → `Certificate`. | El propio codec |

Cuando esos servicios pasen a casos de uso, estas funciones quedan como detalle interno del adaptador.

Tests: `tests/test_codec.py`.
