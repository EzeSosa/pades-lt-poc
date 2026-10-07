"""Extracción de la cadena de certificados (hoja -> raíz) de cada firma de un PDF."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable
from typing import TYPE_CHECKING

import requests
from asn1crypto import cms
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import AuthorityInformationAccessOID
from pyhanko.sign.validation import DocumentSecurityStore
from pyhanko.sign.validation.errors import SignatureValidationError
from pyhanko.sign.validation.generic_cms import (
    extract_certs_for_validation,
    extract_tst_data_iter,
    message_imprint_checker,
    validate_sig_integrity,
)
from pyhanko.sign.validation.pdf_embedded import EmbeddedPdfSignature

from . import read_signed_pdf

if TYPE_CHECKING:  # store importa de este módulo
    from .store import CertificateStore

AIA_TIMEOUT = 5  # segundos por descarga


class CertificateExtractor:
    """Cadena de certificados de cada firma (incluidos los DocTimeStamp) criptográficamente válida.

    No exige confianza: la cadena se arma con los certificados que trae el propio
    PDF (CMS de la firma + DSS), verificando que cada uno haya firmado al anterior.
    Si falta algún emisor, se busca en la fuente de certificados y, si tampoco está y
    `fetch_missing` es true, se descarga desde la URL AIA caIssuers del certificado
    (cada cert indica su origen en `source`, y si está en la fuente en `in_store`).

    Es bloqueante (descargas AIA): llamarlo fuera del event loop.
    """

    def __init__(self, store: CertificateStore | None = None) -> None:
        self.store = store

    def extract(self, pdf: bytes, fetch_missing: bool) -> dict:
        reader = read_signed_pdf(pdf)
        dss_certs: list[asn1_x509.Certificate] = (
            list(DocumentSecurityStore.read_dss(reader).load_certs()) if "/DSS" in reader.root else []
        )
        snapshot = self.store.snapshot() if self.store else None
        # Lo que no trae el PDF se busca en la fuente (habilitados) antes que por AIA.
        store_extra = [
            (asn1_x509.Certificate.load(c.public_bytes(serialization.Encoding.DER)), "store")
            for c in (snapshot.chain_certs if snapshot else ())
        ]
        fetcher = AiaFetcher() if fetch_missing else None

        results = []
        for sig in reader.embedded_signatures:
            is_doc_ts = sig.sig_object_type == "/DocTimeStamp"
            extra = [*((c, "dss") for c in dss_certs), *store_extra]
            entry = {
                "field": sig.field_name,
                "type": "DocTimeStamp" if is_doc_ts else "Signature",
                **_extract_chain(sig.signed_data, sig.compute_digest, extra, "el documento fue alterado", fetcher),
            }
            if not is_doc_ts:
                entry["signature_timestamp"] = (
                    self._signature_timestamp(sig, dss_certs, store_extra, fetcher) if entry["crypto_valid"] else None
                )
            results.append(entry)

        in_store = snapshot.sha256 if snapshot else frozenset()
        for entry in results:
            for chain in (entry, entry.get("signature_timestamp") or {}):
                for cert in chain.get("certificates") or []:
                    cert["in_store"] = cert["sha256_fingerprint"] in in_store
        return {"signatures": results}

    @staticmethod
    def _signature_timestamp(
        sig: EmbeddedPdfSignature,
        dss_certs: list[asn1_x509.Certificate],
        store_extra: list[tuple[asn1_x509.Certificate, str]],
        fetcher: AiaFetcher | None,
    ) -> dict | None:
        """Cadena de la TSA del sello de tiempo de la firma (atributo no firmado), o None si no tiene."""
        token = next(extract_tst_data_iter(sig.signer_info, signed=False), None)
        if token is None:
            return None
        # La TSA sella el valor de la firma. Sus certificados vienen en el token, y los
        # del CMS de la firma, del DSS y de la fuente sirven para completar la cadena.
        extra = [*((c, "cms") for c in sig.other_embedded_certs), *((c, "dss") for c in dss_certs), *store_extra]
        out = _extract_chain(
            token, message_imprint_checker(sig.signer_info), extra, "el sello no corresponde a esta firma", fetcher
        )
        gen_time = token["encap_content_info"]["content"].parsed["gen_time"].native
        return {"time": gen_time.isoformat(), **out}


class AiaFetcher:
    """Descarga emisores desde AIA caIssuers, con caché por request (firma y sello suelen compartir CA)."""

    def __init__(self) -> None:
        self._cache: dict[str, list[x509.Certificate] | str] = {}

    def issuers(self, cert: x509.Certificate) -> tuple[list[x509.Certificate], list[str]]:
        try:
            aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        except x509.ExtensionNotFound:
            return [], [f"{cert.subject.rfc4514_string()}: no tiene AIA caIssuers"]
        urls = [
            d.access_location.value
            for d in aia
            if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS
            and isinstance(d.access_location, x509.UniformResourceIdentifier)
            and d.access_location.value.lower().startswith(("http://", "https://"))
        ]
        certs: list[x509.Certificate] = []
        errors: list[str] = []
        for url in urls:
            if url not in self._cache:
                try:
                    self._cache[url] = _parse_certs(_http_get(url))
                except (requests.RequestException, ValueError) as e:
                    self._cache[url] = f"{url}: {e}"
            got = self._cache[url]
            if isinstance(got, str):
                errors.append(got)
            else:
                certs.extend(got)
        if not urls:
            errors.append(f"{cert.subject.rfc4514_string()}: no tiene AIA caIssuers por HTTP")
        return certs, errors


def _http_get(url: str) -> bytes:
    r = requests.get(url, timeout=AIA_TIMEOUT)
    r.raise_for_status()
    return r.content


def _parse_certs(data: bytes) -> list[x509.Certificate]:
    """Los `.crt`/`.p7c` publicados en AIA pueden venir en DER, PEM o PKCS#7."""
    loaders = (
        lambda d: [x509.load_der_x509_certificate(d)],
        x509.load_pem_x509_certificates,
        pkcs7.load_der_pkcs7_certificates,
        pkcs7.load_pem_pkcs7_certificates,
    )
    for load in loaders:
        try:
            return load(data)
        except ValueError:
            continue
    raise ValueError("no es un certificado DER, PEM ni PKCS#7")


def _check_integrity(
    signed_data: cms.SignedData, covered_digest: Callable[[str], bytes]
) -> tuple[bool, bool, str | None]:
    """(intact, valid, error) sólo criptográfico: no mira confianza ni revocación.

    `covered_digest(md)` devuelve el hash, con el algoritmo `md`, de lo que la
    firma dice cubrir: el ByteRange del PDF, o el valor de la firma que sella la TSA.
    """
    signer_info = signed_data["signer_infos"][0]
    eci = signed_data["encap_content_info"]
    content_type = eci["content_type"].native
    md = signer_info["digest_algorithm"]["algorithm"].native
    try:
        cert = extract_certs_for_validation(signed_data).signer_cert
        if content_type == "tst_info":
            # Sello de tiempo: los atributos firmados cubren el TSTInfo, y es su
            # messageImprint el que tiene que coincidir con lo sellado.
            tst_digest = hashlib.new(md, eci["content"].contents).digest()
            intact, valid = validate_sig_integrity(signer_info, cert, content_type, tst_digest)
            imprint = eci["content"].parsed["message_imprint"]
            imprint_md = imprint["hash_algorithm"]["algorithm"].native
            intact = intact and imprint["hashed_message"].native == covered_digest(imprint_md)
        else:
            intact, valid = validate_sig_integrity(signer_info, cert, content_type, covered_digest(md))
    except SignatureValidationError as e:
        return False, False, str(e)
    return intact, valid, None


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """True si `issuer` firmó `cert` (nombre del emisor + firma verificada)."""
    try:
        cert.verify_directly_issued_by(issuer)
    except ValueError as e:
        # cryptography rechaza algoritmos débiles como SHA-1, que siguen usando
        # PKIs reales (p. ej. la AC Raíz de Argentina firmando a sus CAs). Acá
        # sólo armamos la cadena, no evaluamos política: se verifica a mano.
        return "Unsupported signature algorithm" in str(e) and _verify_legacy(cert, issuer)
    except (TypeError, InvalidSignature):
        return False
    return True


def _verify_legacy(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    if cert.issuer != issuer.subject or cert.signature_hash_algorithm is None:
        return False
    key = issuer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        else:
            return False
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def _build_chain(
    leaf: x509.Certificate, pool: dict[x509.Certificate, str], fetcher: AiaFetcher | None
) -> tuple[list[tuple[x509.Certificate, str]], list[str]]:
    """Sube desde `leaf` buscando al emisor de cada eslabón, hasta un autofirmado.

    Primero en `pool` (cert -> origen) y, si no está y hay `fetcher`, en las URLs
    AIA caIssuers del eslabón. Devuelve la cadena como (cert, origen) y los errores de AIA.
    """
    chain = [(leaf, pool[leaf])]
    errors: list[str] = []
    while not _issued_by(chain[-1][0], chain[-1][0]):
        current, used = chain[-1][0], [c for c, _ in chain]
        candidates = [(c, src) for c, src in pool.items() if c not in used]
        issuer = next(((c, s) for c, s in candidates if _issued_by(current, c)), None)
        if issuer is None and fetcher is not None:
            fetched, errs = fetcher.issuers(current)
            issuer = next(((c, "aia") for c in fetched if c not in used and _issued_by(current, c)), None)
            if issuer is None:
                errors.extend(errs or [f"{current.subject.rfc4514_string()}: AIA no trae a su emisor"])
        if issuer is None:
            break
        chain.append(issuer)
    return chain, errors


def _describe(cert: x509.Certificate, position: int, source: str) -> dict:
    self_signed = _issued_by(cert, cert)
    der = cert.public_bytes(serialization.Encoding.DER)
    return {
        "type": "end_entity" if position == 0 else "root" if self_signed else "intermediate",
        "source": source,
        "self_signed": self_signed,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "der_b64": base64.b64encode(der).decode(),
    }


def _extract_chain(
    signed_data: cms.SignedData,
    covered_digest: Callable[[str], bytes],
    extra_certs: list[tuple[asn1_x509.Certificate, str]],
    altered_msg: str,
    fetcher: AiaFetcher | None = None,
) -> dict:
    """Chequeo criptográfico + cadena del firmante de `signed_data`.

    `extra_certs` son (cert, origen) que no vienen en `signed_data` pero sirven
    para completar la cadena; con `fetcher` se completa además por AIA.
    """
    intact, valid, error = _check_integrity(signed_data, covered_digest)
    out = {"crypto_valid": intact and valid, "intact": intact, "valid": valid}
    if not out["crypto_valid"]:
        out["error"] = error or (altered_msg if not intact else "firma inválida")
        out["certificates"] = None
        return out

    # Firmante primero, sin duplicados (el mismo cert suele estar en el CMS y en el
    # DSS: gana el primer origen).
    cms_certs = extract_certs_for_validation(signed_data)
    by_der: dict[bytes, str] = {}
    for c, src in [(cms_certs.signer_cert, "cms"), *((c, "cms") for c in cms_certs.other_certs), *extra_certs]:
        by_der.setdefault(c.dump(), src)
    pool = {x509.load_der_x509_certificate(der): src for der, src in by_der.items()}
    chain, aia_errors = _build_chain(next(iter(pool)), pool, fetcher)
    out["chain_complete"] = _issued_by(chain[-1][0], chain[-1][0])
    out["certificates"] = [_describe(c, i, src) for i, (c, src) in enumerate(chain)]
    if aia_errors:
        out["aia_errors"] = aia_errors
    return out
