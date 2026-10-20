"""`SignedPdfReader` con pyHanko: las firmas de un PDF, sus certificados y su integridad criptográfica.

Ver docs/arquitectura/adaptadores.md.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from io import BytesIO

from asn1crypto import cms
from pyhanko.pdf_utils.crypt import AuthStatus, PubKeySecurityHandler
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import DocumentSecurityStore
from pyhanko.sign.validation.errors import SignatureValidationError
from pyhanko.sign.validation.generic_cms import (
    extract_certs_for_validation,
    extract_tst_data_iter,
    message_imprint_checker,
    validate_sig_integrity,
)

from ....application.ports import CertificateCodec
from ....domain.errors import UnprocessablePdf
from ....domain.signatures import CmsSignature, EmbeddedSignature, Integrity, SignatureKind, SignedDocument, TimestampToken
from .convert import CertificateConverter


def open_pdf(data: bytes) -> PdfFileReader:
    """El PDF abierto con pyHanko (sin modo estricto) y, si está cifrado, autenticado con la contraseña vacía.

    Lanza `UnprocessablePdf` si no es un PDF que se pueda leer, o si hace falta una contraseña o un
    certificado para abrirlo (D-03).
    """
    try:
        reader = PdfFileReader(BytesIO(data), strict=False)
    except Exception as e:  # noqa: BLE001 - cualquier error de lectura es un PDF inválido
        raise UnprocessablePdf(f"No es un PDF válido o está dañado: {type(e).__name__}: {e}") from e
    handler = reader.security_handler
    if isinstance(handler, PubKeySecurityHandler):
        raise UnprocessablePdf("El PDF está cifrado para certificados (/Adobe.PubSec): sin la clave del destinatario no se puede leer.")
    if handler is not None and reader.decrypt("").status is AuthStatus.FAILED:
        raise UnprocessablePdf("El PDF está cifrado con contraseña de apertura: sin ella no se puede leer ni validar.")
    return reader


def open_signed_pdf(data: bytes) -> PdfFileReader:
    """Como `open_pdf`, y además lanza `UnprocessablePdf` si no tiene firmas (V-10)."""
    reader = open_pdf(data)
    if not reader.embedded_signatures:
        raise UnprocessablePdf("El PDF no tiene firmas")
    return reader


class PyHankoSignedPdfReader:
    """Implementa `application.ports.SignedPdfReader`. Convierte los certificados con el `CertificateCodec`."""

    def __init__(self, codec: CertificateCodec) -> None:
        self.codec = codec

    def read(self, pdf: bytes) -> SignedDocument:
        reader = open_signed_pdf(pdf)
        convert = CertificateConverter(self.codec)
        dss = list(DocumentSecurityStore.read_dss(reader).load_certs()) if "/DSS" in reader.root else []
        signatures = []
        for sig in reader.embedded_signatures:
            is_doc_ts = sig.sig_object_type == "/DocTimeStamp"
            timestamp = None
            if not is_doc_ts:
                token = next(extract_tst_data_iter(sig.signer_info, signed=False), None)
                if token is not None:
                    timestamp = TimestampToken(
                        time=token["encap_content_info"]["content"].parsed["gen_time"].native,
                        cms=_cms(token, message_imprint_checker(sig.signer_info), convert),
                    )
            signatures.append(
                EmbeddedSignature(
                    field_name=sig.field_name,
                    kind=SignatureKind.DOC_TIMESTAMP if is_doc_ts else SignatureKind.SIGNATURE,
                    cms=_cms(sig.signed_data, sig.compute_digest, convert),
                    timestamp=timestamp,
                )
            )
        return SignedDocument(tuple(signatures), tuple(convert(c) for c in dss))


def _cms(signed_data: cms.SignedData, covered_digest: Callable[[str], bytes], convert: CertificateConverter) -> CmsSignature:
    integrity = check_integrity(signed_data, covered_digest)
    try:
        found = extract_certs_for_validation(signed_data)
    except SignatureValidationError:  # sin firmante identificable: la integridad ya lo dice
        return CmsSignature(None, (), integrity)
    return CmsSignature(convert(found.signer_cert), tuple(convert(c) for c in found.other_certs), integrity)


def check_integrity(signed_data: cms.SignedData, covered_digest: Callable[[str], bytes]) -> Integrity:
    """Sólo criptografía: no mira confianza ni revocación.

    `covered_digest(md)` devuelve el hash, con el algoritmo `md`, de lo que la firma dice cubrir:
    el ByteRange del PDF, o el valor de la firma que sella la TSA.
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
        return Integrity(False, False, str(e))
    return Integrity(intact, valid)
