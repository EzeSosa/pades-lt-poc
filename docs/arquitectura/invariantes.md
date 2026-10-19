# Invariantes

Las reglas de negocio que la arquitectura protege, con un id estable. El id se cita en el código (docstrings y comentarios) y en los tests, así que se puede ir en los dos sentidos: de una regla a dónde se aplica y quién la prueba, y de un `F-02` en el código a su explicación.

Cada regla tiene un **estado de migración**:

- **Dominio**: la regla vive en `domain/` y tiene tests puros, sin PKI ni red.
- **Caso de uso**: la regla la orquesta un caso de uso de `application/`, probado con fakes.
- **Sin migrar**: la regla sigue en `services/`, mezclada con la biblioteca que hace el trabajo. La cubren los tests de los endpoints y los de contrato. Pasa al dominio en el paso que se indica.

## Fuente de certificados (F)

| Id | Regla | Por qué | Dónde | Tests | Estado |
|----|-------|---------|-------|-------|--------|
| F-01 | La fuente sólo guarda CAs; si alguno de los recibidos no lo es, no se agrega ninguno. | La fuente provee anclas e intermedios: una hoja no sirve para ninguna de las dos cosas, y aceptar parte de un PKCS#7 dejaría un estado difícil de explicar. | `domain/source.py::new_entries` | `test_domain_source.py::test_f01_*`, `test_certificate_source.py::test_f01_*` | Dominio |
| F-02 | Sólo una raíz puede ser ancla de confianza. Al agregar, un intermedio queda no confiable sin error; al cambiar, pedirlo es un error. | Confiar en un intermedio validaría cadenas sin llegar a una raíz. Al agregar se tolera porque un PKCS#7 trae raíz e intermedios juntos con un solo `trusted`. | `domain/source.py::new_entries`, `check_changes`; `CHECK` en SQLite | `test_domain_source.py::test_f02_*`, `test_certificate_source.py::test_f02_*`, `test_certificate_repository.py::test_rejects_trusted_intermediate_atomically` | Dominio |
| F-03 | Si todos los recibidos ya estaban, es un error con sus ids; si estaban algunos, se agregan los demás. | Un alta que no agrega nada casi siempre es un error de quien la hace, y el id le dice dónde está lo que buscaba. | `CertificateSource.add` | `test_certificate_source.py::test_f03_duplicates`, `test_store.py::test_add_pkcs7_and_duplicates` | Caso de uso |
| F-04 | La carga inicial se aplica una sola vez, junto con su marca y en la misma transacción; restaurarla sólo agrega lo que falta. | Si se aplicara en cada arranque, borrar una AC de la carga inicial no tendría efecto. Si la marca no fuera con la carga, una caída a mitad de camino dejaría la fuente incompleta para siempre. | `CertificateSource.initialize`, `restore_seed`; `CertificateRepository.apply_initial_load` | `test_certificate_source.py::test_initial_load*`, `test_certificate_repository.py::test_*initial_load*` | Caso de uso |
| F-05 | Un cambio aplica enseguida; una verificación ve raíces e intermedios de un mismo estado. | El ABM es para usarse sin reiniciar. Leer raíces de un estado e intermedios de otro podría dar un resultado que no corresponde a ningún estado real de la fuente. | `CertificateSource._reload`, `TrustSnapshot` | `test_certificate_source.py::test_update_applies_immediately`, `test_store.py::test_disable_and_untrust_take_effect_immediately` | Caso de uso |
| F-06 | Para confiar y completar cadenas cuenta sólo lo habilitado; para decir si ya está, todo. | Deshabilitar es la forma de dejar de usar algo sin perderlo; la UI igual tiene que saber que está, para no ofrecer agregarlo de nuevo. | `TrustSnapshot.from_entries` | `test_domain_source.py::test_f06_*` | Dominio |

## Validación (V)

| Id | Regla | Por qué | Dónde | Tests | Estado |
|----|-------|---------|-------|-------|--------|
| V-01 | Las anclas son la raíz de la PoC (implícita) más las raíces confiables y habilitadas de la fuente. | La raíz de la PoC se regenera con la PKI: guardada en la fuente quedaría desactualizada. | `SignatureVerifier.trust_roots` | `test_verify.py::test_verify_trusts_poc_root_and_both_ac_raiz`, `test_verify_uses_trust_roots` | Sin migrar (paso 5) |
| V-02 | SHA-1 se acepta sólo en lo que firman las claves de raíces confiables que nacieron con SHA-1. | La AC Raíz 2007 firma con SHA-1 a la AC ONTI y a su CRL; relajarlo para todos aceptaría firmas débiles de cualquiera. | `LegacyRootsPolicy`, `SignatureVerifier.algorithm_policy` | `test_verify.py::test_sha1_*` | Sin migrar (paso 5) |
| V-03 | La revocación siempre es obligatoria (hard-fail): sin revocación, no es confiable. | Una firma de un certificado revocado no puede salir confiable porque no se pudo consultar. | `_ContextFactory.at` | `test_verify.py::test_validates_now_by_default`, `test_verify_online.py::test_offline_is_the_default_and_suggests_online` | Sin migrar (paso 5) |
| V-04 | Con conexión sólo se valida a la hora actual. | pyHanko no descarga revocación para validar en el pasado, y la que descargaría es de hoy. | `SignatureVerifier.verify` | golden `verify_online_in_the_past` | Sin migrar (paso 5) |
| V-05 | Con conexión, o si la cadena se completó con la fuente, el nivel no pasa de B-T. | LT significa que el PDF alcanza solo para validarse. Lo descargado o lo que puso la fuente no está en el PDF. | `_pades_level`, `SignatureVerifier.verify` | golden `verify_online`, `verify_completed_from_store` | Sin migrar (paso 5) |
| V-06 | `completed_from_store` lista los intermedios del camino (sin hoja ni raíz) que no vienen en el PDF y sí en la fuente, y sólo si la firma es confiable. | Si la validación falla, pyHanko igual devuelve un camino, y no se puede decir que la fuente lo completó. | `_from_store` | `test_store.py::test_verify_completes_from_store_and_says_so`, `test_failed_validation_does_not_credit_store` | Sin migrar (paso 5) |
| V-07 | Nivel: B-B; B-T si todas las firmas tienen sello; B-LT si además hay DSS, el PDF es autosuficiente y todas validan; B-LTA si además hay un DocTimeStamp. | Es la definición de los niveles baseline de PAdES aplicada a lo que se puede verificar. | `_pades_level` | goldens `verify_*` | Sin migrar (paso 5) |
| V-08 | Con la hora declarada se acepta revocación posterior a esa hora y se avisa que no está probada. | La revocación embebida se obtuvo después de firmar; sin aceptarla, ninguna firma sin sello validaría en el pasado. | `_ContextFactory.at`, `CLAIMED_TIME_WARNING` | `test_verify.py::test_claimed_signing_time_is_explicit_and_reported` | Sin migrar (paso 5) |
| V-09 | `trust_problem` aparece sólo cuando la firma (o su sello) no es confiable. | El diagnóstico revalida cada camino: es caro y sólo tiene sentido si hay algo que explicar. | `_verify_signature` | goldens `verify_*` | Sin migrar (paso 5) |
| V-10 | Un PDF sin firmas es una entrada inválida (422). | No hay nada que verificar ni extraer. | `adapters/outbound/pyhanko/signed_pdf_reader.py::open_signed_pdf` | golden `verify_no_signatures`, `test_certificates.py::test_pdf_without_signatures` | Sin migrar (paso 5) |

## Certificados (C)

| Id | Regla | Por qué | Dónde | Tests | Estado |
|----|-------|---------|-------|-------|--------|
| C-01 | Primero se verifica la integridad criptográfica; la cadena se arma sólo si verifica. No se exige confianza. | Una firma alterada no tiene un firmante confiable que mostrar. Exigir confianza impediría ver la cadena de PKIs ajenas. | `domain/chains.py::chain_for`; el sello sólo si la firma verifica, en `ExtractCertificateChains` | `test_domain_chains.py::test_chain_is_not_built_if_the_signature_does_not_verify`, `test_extract_chains.py::test_no_timestamp_chain_if_the_signature_does_not_verify`, `test_certificates.py::test_tampered_*`, `test_self_signed_signer_from_untrusted_pki` | Dominio |
| C-02 | Orígenes en orden cms > dss > store > aia; el firmante primero; ante duplicados gana el primer origen. | Se informa lo más cercano al PDF: si el PDF ya trae un certificado, no importa que también esté en la fuente. | `domain/chains.py::candidate_pool`, `build_chain` | `test_domain_chains.py::test_pool_puts_signer_first_and_keeps_first_origin`, `test_build_chain_*`, `test_certificates.py::test_pdf_certs_take_precedence_over_aia`, `test_store.py::test_certificates_completes_chain_from_store` | Dominio |
| C-03 | AIA sólo con `fetch_missing`, sólo por http(s) y con caché por pedido. | Descargar es lento y sale a la red: se pide explícitamente y no se repite para firma y sello. | `domain/chains.py::http_ca_issuer_urls`; caché y `fetch_missing` en `ExtractCertificateChains` | `test_domain_chains.py::test_only_http_ca_issuers`, `test_extract_chains.py::test_aia_only_when_asked_and_cached_per_request`, `test_certificates.py::test_chain_completed_from_aia`, `test_incomplete_chain_*` | Dominio |
| C-04 | Para armar la cadena se acepta SHA-1. | Es armado, no validación: la política de algoritmos es de la verificación. | `CertificateCodec.issued_by` | `test_codec.py::test_issued_by_accepts_sha1` | Adaptador |

## Firma (S)

| Id | Regla | Por qué | Dónde | Tests | Estado |
|----|-------|---------|-------|-------|--------|
| S-01 | Un PDF inválido o cifrado es una entrada inválida (422). | Un PDF cifrado no se puede firmar sin la contraseña, y pyHanko dejaba estado a medio configurar al intentarlo. | `PdfSigner.sign` | `test_sign.py::test_invalid_pdf_is_422`, `test_encrypted_pdf_is_rejected_and_signer_keeps_working` | Sin migrar (paso 6) |
| S-02 | El campo de firma es el primer `FirmaN` libre del formulario. | Contar firmas choca con campos ya existentes (una firma en `Firma2`, un campo de texto `Firma1`). | `_free_field_name` | `test_sign.py::test_cosign_*`, `test_free_field_name_*` | Sin migrar (paso 6) |
| S-03 | Cada firma usa un firmante nuevo. | pyHanko le instala estado durante la firma y no lo saca si falla: compartido, un pedido fallido rompía a los siguientes. | `PdfSigner._new_signer` | `test_sign.py::test_encrypted_pdf_is_rejected_and_signer_keeps_working`, suite de PDFs (canario) | Sin migrar (paso 6) |
| S-04 | PAdES con `ETSI.CAdES.detached` y SHA-256, DSS para B-LT, DocTimeStamp si se pide B-LTA, revocación hard-fail al firmar. | Es lo que define el perfil que promete `/sign`. | `PdfSigner.sign` | goldens `sign_b_lt`, `verify_b_lt`, `verify_b_lta` | Sin migrar (paso 6) |
