"""`PdfSigningEngine` con pyHanko: firma PAdES B-LT (opcionalmente B-LTA) con una identidad fija.

Ver docs/arquitectura/adaptadores.md.
"""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

from asn1crypto import x509 as asn1_x509
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers
from pyhanko.sign.timestamps import HTTPTimeStamper
from pyhanko_certvalidator import ValidationContext

from ....domain.errors import UnprocessablePdf
from ....domain.signing import SignatureSpec

SUBFILTERS = {"ETSI.CAdES.detached": fields.SigSeedSubFilter.PADES}


class PyHankoPdfSigner:
    """Implementa `application.ports.PdfSigningEngine`.

    `signer` es la plantilla con la clave, el certificado y la cadena del firmante; `trust_root`
    es el ancla con la que se valida la cadena al firmar (para embeber su revocación).
    """

    def __init__(self, signer: signers.SimpleSigner, trust_root: asn1_x509.Certificate) -> None:
        self.signer = signer  # plantilla: cada firma usa una copia (S-03, ver _new_signer)
        self.trust_root = trust_root

    @classmethod
    def from_files(cls, key: Path, cert: Path, chain: list[Path], trust_root: Path) -> PyHankoPdfSigner:
        """La identidad desde archivos PEM: clave privada (sin contraseña), certificado y cadena."""
        signer = signers.SimpleSigner.load(
            key_file=str(key), cert_file=str(cert), ca_chain_files=tuple(str(c) for c in chain)
        )
        return cls(signer, load_cert_from_pemder(str(trust_root)))

    def open(self, pdf: bytes) -> _SignablePdf:
        try:
            writer = IncrementalPdfFileWriter(BytesIO(pdf))
        except Exception as e:  # noqa: BLE001 - cualquier error de lectura es un PDF inválido
            raise UnprocessablePdf(f"No es un PDF válido o está dañado: {type(e).__name__}: {e}") from e
        return _SignablePdf(self, writer)

    def _new_signer(self) -> signers.SimpleSigner:
        """Un Signer por firma (S-03): pyHanko le instala estado durante la firma (p. ej. el MAC de
        los PDF cifrados) y, si la firma falla, no lo saca. Compartido, un pedido fallido rompía a
        todos los siguientes. Clave, certificado y cadena se cargan una sola vez y se reusan."""
        t = self.signer
        return signers.SimpleSigner(signing_cert=t.signing_cert, signing_key=t.signing_key, cert_registry=t.cert_registry)


class _SignablePdf:
    """Implementa `application.ports.SignablePdf`."""

    def __init__(self, engine: PyHankoPdfSigner, writer: IncrementalPdfFileWriter) -> None:
        self._engine = engine
        self._writer = writer
        self.encrypted = bool(writer.prev.encrypted)

    @property
    def field_names(self) -> frozenset[str]:
        # Se lee recién cuando se pide: en un PDF cifrado (que se rechaza antes) leer el
        # formulario puede fallar.
        return frozenset(field_names(self._writer.prev))

    async def sign(self, spec: SignatureSpec, tsa_url: str) -> bytes:
        # Contexto de validación usado AL FIRMAR: pyHanko construye la cadena,
        # descarga las CRL (del CDP de cada certificado) y las embebe en el DSS.
        vc = ValidationContext(
            trust_roots=[self._engine.trust_root],
            allow_fetching=True,
            revocation_mode="hard-fail",
        )
        meta = signers.PdfSignatureMetadata(
            field_name=spec.field_name,
            reason=spec.reason,
            location=spec.location,
            md_algorithm=spec.digest_algorithm,
            subfilter=SUBFILTERS[spec.subfilter],  # ETSI.CAdES.detached
            embed_validation_info=True,  # => DSS con certs + CRLs  => B-LT
            use_pades_lta=spec.lta,  # => + DocTimeStamp          => B-LTA
            validation_context=vc,
        )
        try:
            out = await signers.async_sign_pdf(
                self._writer,
                meta,
                signer=self._engine._new_signer(),
                timestamper=HTTPTimeStamper(tsa_url),  # sello de tiempo de firma => B-T
            )
        except Exception as e:  # noqa: BLE001 - PoC: devolver el motivo al cliente
            raise UnprocessablePdf(f"No se pudo firmar: {type(e).__name__}: {e}") from e
        return out.getvalue()


def field_names(reader: PdfFileReader) -> set[str]:
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
