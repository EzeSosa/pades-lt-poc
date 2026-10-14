"""Firma PAdES B-LT (opcionalmente B-LTA)."""

from __future__ import annotations

from io import BytesIO

from asn1crypto import x509 as asn1_x509
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers
from pyhanko.sign.timestamps import HTTPTimeStamper
from pyhanko_certvalidator import ValidationContext

from .. import pki
from . import UnprocessablePdf


class PdfSigner:
    """Firma con el firmante de la mini PKI y la TSA de la propia app."""

    def __init__(self, signer: signers.SimpleSigner, trust_root: asn1_x509.Certificate) -> None:
        self.signer = signer  # plantilla: cada firma usa una copia (ver _new_signer)
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

    def _new_signer(self) -> signers.SimpleSigner:
        """Un Signer por firma: pyHanko le instala estado durante la firma (p. ej. el MAC de los
        PDF cifrados) y, si la firma falla, no lo saca. Compartido, un pedido fallido rompía a todos
        los siguientes. Clave, certificado y cadena se cargan una sola vez y se reusan."""
        t = self.signer
        return signers.SimpleSigner(signing_cert=t.signing_cert, signing_key=t.signing_key, cert_registry=t.cert_registry)

    async def sign(self, pdf: bytes, *, reason: str, location: str, lta: bool, tsa_url: str) -> bytes:
        try:
            writer = IncrementalPdfFileWriter(BytesIO(pdf))
        except Exception as e:  # noqa: BLE001 - cualquier error de lectura es un PDF inválido
            raise UnprocessablePdf(f"No es un PDF válido o está dañado: {type(e).__name__}: {e}") from e
        if writer.prev.encrypted:
            raise UnprocessablePdf("El PDF está protegido con contraseña: quitale la protección antes de firmarlo.")
        field_name = _free_field_name(writer.prev)

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
                signer=self._new_signer(),
                timestamper=HTTPTimeStamper(tsa_url),  # sello de tiempo de firma => B-T
            )
        except Exception as e:  # noqa: BLE001 - PoC: devolver el motivo al cliente
            raise UnprocessablePdf(f"No se pudo firmar: {type(e).__name__}: {e}") from e
        return out.getvalue()


def _free_field_name(reader: PdfFileReader) -> str:
    """`FirmaN` con el menor N que no use ningún campo del formulario, sea de firma o no.

    Contar las firmas no alcanza: el PDF puede traer un campo `Firma2` con una sola firma,
    o un campo de texto `Firma1`, y pyHanko no firma sobre ninguno de los dos.
    """
    taken = _field_names(reader)
    n = 1
    while f"Firma{n}" in taken:
        n += 1
    return f"Firma{n}"


def _field_names(reader: PdfFileReader) -> set[str]:
    """Nombres completos (con los de sus padres, separados por punto) de los campos del AcroForm."""
    names: set[str] = set()

    def walk(field_refs, prefix: str) -> None:
        for ref in field_refs:
            node = ref.get_object()
            name = prefix
            if "/T" in node:
                name = f"{prefix}.{node['/T']}" if prefix else str(node["/T"])
                names.add(name)
            if "/Kids" in node:
                walk(node["/Kids"], name)

    form = reader.root.get("/AcroForm")
    if form is not None:
        walk(form.get_object().get("/Fields", []), "")
    return names
