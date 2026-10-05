"""Firma PAdES B-LT (opcionalmente B-LTA)."""

from __future__ import annotations

from io import BytesIO

from asn1crypto import x509 as asn1_x509
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers
from pyhanko.sign.timestamps import HTTPTimeStamper
from pyhanko_certvalidator import ValidationContext

from .. import pki
from . import UnprocessablePdf


class PdfSigner:
    """Firma con el firmante de la mini PKI y la TSA de la propia app."""

    def __init__(self, signer: signers.Signer, trust_root: asn1_x509.Certificate) -> None:
        self.signer = signer
        self.trust_root = trust_root  # ancla de confianza para firmar

    @classmethod
    def from_pki(cls) -> PdfSigner:
        signer = signers.SimpleSigner.load(
            key_file=str(pki.entity(pki.SIGNER).key_path),
            cert_file=str(pki.entity(pki.SIGNER).cert_path),
            ca_chain_files=(
                str(pki.entity(pki.INTERMEDIATE).cert_path),
                str(pki.entity(pki.ROOT).cert_path),
            ),
        )
        return cls(signer, load_cert_from_pemder(str(pki.entity(pki.ROOT).cert_path)))

    async def sign(self, pdf: bytes, *, reason: str, location: str, lta: bool, tsa_url: str) -> bytes:
        writer = IncrementalPdfFileWriter(BytesIO(pdf))
        # Nombre de campo único, así se puede re-firmar un PDF ya firmado (co-firma).
        field_name = f"Firma{len(writer.prev.embedded_signatures) + 1}"

        # Contexto de validación usado AL FIRMAR: pyHanko construye la cadena,
        # descarga las CRL (del CDP de cada certificado) y las embebe en el DSS.
        vc = ValidationContext(
            trust_roots=[self.trust_root],
            allow_fetching=True,
            revocation_mode="hard-fail",
        )
        meta = signers.PdfSignatureMetadata(
            field_name=field_name,
            reason=reason,
            location=location,
            md_algorithm="sha256",
            subfilter=fields.SigSeedSubFilter.PADES,  # ETSI.CAdES.detached
            embed_validation_info=True,  # => DSS con certs + CRLs  => B-LT
            use_pades_lta=lta,  # => + DocTimeStamp          => B-LTA
            validation_context=vc,
        )
        try:
            out = await signers.async_sign_pdf(
                writer,
                meta,
                signer=self.signer,
                timestamper=HTTPTimeStamper(tsa_url),  # sello de tiempo de firma => B-T
            )
        except Exception as e:  # noqa: BLE001 - PoC: devolver el motivo al cliente
            raise UnprocessablePdf(f"No se pudo firmar: {type(e).__name__}: {e}") from e
        return out.getvalue()
