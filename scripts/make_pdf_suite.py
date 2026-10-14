"""
Genera la suite de PDFs de prueba para APIs de firma en testdata/pdf-suite/.

Cada caso queda en `manifest.json` (qué prueba, qué problema reproduce y qué se espera)
y el README.md de la suite se arma con los mismos datos, así no se desincronizan.

Uso:  uv run python scripts/make_pdf_suite.py [--out testdata/pdf-suite]

Sólo depende de pyHanko y cryptography. Los casos ya firmados usan una PKI de prueba
"ajena" que se genera en cada corrida (no es confiable para ningún validador): sirven
para probar integridad, co-firma y algoritmos, no confianza.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import zlib
from dataclasses import asdict, dataclass, field
from io import BytesIO
from pathlib import Path

from asn1crypto import keys as asn1_keys
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PdfFileWriter, copy_into_new_writer
from pyhanko.sign import fields, signers
from pyhanko.sign.fields import MDPPerm
from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko_certvalidator.registry import SimpleCertificateStore

DEFAULT_OUT = Path("testdata/pdf-suite")


# --------------------------------------------------------------------------- casos
@dataclass
class Case:
    id: str
    file: str  # relativo a la carpeta de la suite
    category: str
    title: str
    problem: str  # qué problemática reproduce
    expected: str  # qué tiene que hacer una API de firmas correcta
    sign: str  # "ok" | "reject" | "ok_or_reject"
    verify: dict | None = None  # para PDFs ya firmados: qué tiene que informar la verificación
    upload: dict = field(default_factory=dict)  # filename, content_type, form (campos extra)


CATEGORIES = {
    "estructura": "Variantes válidas de la estructura del archivo",
    "tolerancia": "Archivos imperfectos que circulan en la práctica",
    "contenido": "Páginas, tamaño y metadatos",
    "seguridad": "Cifrado y certificación (DocMDP)",
    "formularios": "AcroForm y campos de firma existentes",
    "firmados": "PDFs que ya traen firmas",
    "entrada": "Entradas inválidas y parámetros de la API",
}


# --------------------------------------------------------------------------- PDF a mano
def content_stream(lines: list[str], x: int = 72, y: int = 720) -> bytes:
    ops = [f"BT /F1 14 Tf {x} {y} Td 18 TL"]
    for line in lines:
        escaped = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        ops.append(f"({escaped}) '")
    ops.append("ET")
    return "\n".join(ops).encode("latin-1")


def stream_obj(data: bytes, extra: bytes = b"", compress: bool = False) -> bytes:
    if compress:
        data = zlib.compress(data)
        extra += b" /Filter /FlateDecode"
    return b"<< /Length %d%s >>\nstream\n" % (len(data), extra) + data + b"\nendstream"


def build_pdf(
    objs: list[bytes],
    *,
    version: str = "1.7",
    eol: bytes = b"\n",
    trailer_extra: bytes = b"",
    prefix: bytes = b"",
    suffix: bytes = b"",
    xref_shift: int = 0,
    final_eol: bool = True,
) -> bytes:
    """Arma un PDF con tabla xref clásica. El objeto 1 es el catálogo.

    `xref_shift` desplaza todos los offsets de la xref (xref rota que hay que reconstruir).
    `prefix` y `suffix` se agregan fuera de la estructura (bytes antes del header y después de %%EOF).
    """
    out = bytearray(f"%PDF-{version}".encode() + eol + b"%\xe2\xe3\xcf\xd3" + eol)
    offsets = []
    for i, obj in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj" % i + eol + obj + eol + b"endobj" + eol
    xref = len(out)
    out += b"xref" + eol + b"0 %d" % (len(objs) + 1) + eol
    # Las entradas miden 20 bytes: el fin de línea tiene que ser de 2 caracteres.
    entry_eol = b"\r\n" if eol == b"\r\n" else b" \n"
    out += b"0000000000 65535 f" + entry_eol
    out += b"".join(b"%010d 00000 n" % (o + xref_shift) + entry_eol for o in offsets)
    out += b"trailer" + eol + b"<< /Size %d /Root 1 0 R%s >>" % (len(objs) + 1, trailer_extra) + eol
    out += b"startxref" + eol + b"%d" % xref + eol + b"%%EOF" + (eol if final_eol else b"")
    return prefix + bytes(out) + suffix


def simple_doc(pages: list[list[str]] | None = None, *, page_extra: bytes = b"", catalog_extra: bytes = b"", **kw) -> bytes:
    """Catálogo, árbol de páginas plano, Helvetica y una página por lista de líneas."""
    pages = pages or [["Documento de prueba"]]
    n = len(pages)
    font = 3
    first_page = 4
    kids = b" ".join(b"%d 0 R" % (first_page + 2 * i) for i in range(n))
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R%s >>" % catalog_extra,
        b"<< /Type /Pages /Kids [%s] /Count %d >>" % (kids, n),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
    ]
    for i, lines in enumerate(pages):
        objs.append(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 %d 0 R >> >> "
            b"/Contents %d 0 R%s >>" % (font, first_page + 2 * i + 1, page_extra)
        )
        objs.append(stream_obj(content_stream(lines)))
    return build_pdf(objs, **kw)


def incremental(pdf: bytes, new_objs: dict[int, bytes], root: int = 1, trailer_extra: bytes = b"") -> bytes:
    """Agrega una revisión con xref clásica que reemplaza o agrega los objetos dados."""
    reader = PdfFileReader(BytesIO(pdf))
    size = max(reader.trailer["/Size"], max(new_objs) + 1)
    prev = reader.last_startxref
    out = bytearray(pdf if pdf.endswith(b"\n") else pdf + b"\n")
    offsets = {}
    for num, obj in sorted(new_objs.items()):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + obj + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 1\n0000000000 65535 f \n"
    for num, off in sorted(offsets.items()):
        out += b"%d 1\n%010d 00000 n \n" % (num, off)
    out += b"trailer\n<< /Size %d /Root %d 0 R%s /Prev %d >>\nstartxref\n%d\n%%%%EOF\n" % (
        size, root, trailer_extra, prev, xref)
    return bytes(out)


def rewrite(pdf: bytes, **writer_kwargs) -> PdfFileWriter:
    """Copia el PDF a un writer nuevo (reescritura completa, no incremental)."""
    return copy_into_new_writer(PdfFileReader(BytesIO(pdf)), writer_kwargs=writer_kwargs)


def writer_bytes(w) -> bytes:
    buf = BytesIO()
    w.write(buf)
    return buf.getvalue()


# --------------------------------------------------------------------------- PKI ajena
@dataclass
class Identity:
    cert: asn1_x509.Certificate
    key: asn1_keys.PrivateKeyInfo
    chain: list[asn1_x509.Certificate]


def _name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "AR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI de prueba de la suite (no confiable)"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _issue(subject_key, cn, issuer_key, issuer_name, *, ca: bool, eku=None, hash_alg=hashes.SHA256()):
    now = dt.datetime.now(dt.UTC)
    b = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_name or _name(cn))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
    )
    if ca:
        b = b.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
    else:
        b = b.add_extension(
            x509.KeyUsage(True, True, False, False, False, False, False, False, False), critical=True
        )
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage([eku]), critical=True)
    return b.sign(issuer_key, hash_alg)


def _asn1(cert: x509.Certificate) -> asn1_x509.Certificate:
    return asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


def _asn1_key(key) -> asn1_keys.PrivateKeyInfo:
    der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return asn1_keys.PrivateKeyInfo.load(der)


class ForeignPki:
    """CA raíz autofirmada, un firmante RSA, uno ECDSA P-256 y una TSA. Nada de esto es confiable."""

    def __init__(self) -> None:
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca = _issue(ca_key, "Raiz de prueba de la suite", ca_key, None, ca=True)
        self.root = _asn1(ca)

        def leaf(key, cn, eku=None):
            cert = _issue(key, cn, ca_key, ca.subject, ca=False, eku=eku)
            return Identity(_asn1(cert), _asn1_key(key), [self.root])

        self.rsa = leaf(rsa.generate_private_key(public_exponent=65537, key_size=2048), "Firmante RSA de la suite")
        self.ecdsa = leaf(ec.generate_private_key(ec.SECP256R1()), "Firmante ECDSA de la suite")
        self.tsa = leaf(
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            "TSA de la suite",
            eku=ExtendedKeyUsageOID.TIME_STAMPING,
        )

    def signer(self, who: Identity) -> signers.SimpleSigner:
        return signers.SimpleSigner(
            signing_cert=who.cert,
            signing_key=who.key,
            cert_registry=SimpleCertificateStore.from_certs(who.chain),
        )

    def timestamper(self) -> DummyTimeStamper:
        return DummyTimeStamper(tsa_cert=self.tsa.cert, tsa_key=self.tsa.key, certs_to_embed=[self.root])


def sign_with(pdf: bytes, signer, *, field_name="FirmaPrevia", subfilter=fields.SigSeedSubFilter.PADES,
              certify=False, perms=MDPPerm.FILL_FORMS, timestamper=None, md="sha256") -> bytes:
    w = IncrementalPdfFileWriter(BytesIO(pdf))
    meta = signers.PdfSignatureMetadata(
        field_name=field_name,
        md_algorithm=md,
        subfilter=subfilter,
        certify=certify,
        docmdp_permissions=perms,
        reason="Firma previa de la suite",
    )
    return signers.sign_pdf(w, meta, signer=signer, timestamper=timestamper).getvalue()


# --------------------------------------------------------------------------- catálogo
def build_cases(pki: ForeignPki) -> list[tuple[Case, bytes]]:
    cases: list[tuple[Case, bytes]] = []

    def add(case: Case, data: bytes) -> None:
        cases.append((case, data))

    base = simple_doc([["Documento base de la suite", "PDF 1.7, xref clasica, una pagina."]])

    # ---------------------------------------------------------------- estructura
    add(Case(
        "E01", "estructura/E01-base.pdf", "estructura", "Documento mínimo correcto",
        "Línea de base: PDF 1.7 de una página, xref clásica y Helvetica sin embeber.",
        "Se firma. Si este falla, el resto de la suite no dice nada.", "ok"), base)

    add(Case(
        "E02", "estructura/E02-pdf-1.4.pdf", "estructura", "Versión de cabecera 1.4",
        "Documentos viejos o generados por herramientas antiguas. Algunos firmantes suben la versión "
        "de cabecera reescribiendo el archivo, lo que invalida firmas previas.",
        "Se firma por actualización incremental, sin reescribir los bytes originales.", "ok"),
        simple_doc([["Cabecera %PDF-1.4"]], version="1.4"))

    add(Case(
        "E03", "estructura/E03-pdf-2.0.pdf", "estructura", "Versión de cabecera 2.0",
        "PDF 2.0 (ISO 32000-2). Librerías viejas lo rechazan por la versión aunque la estructura sea la misma.",
        "Se firma. Si se rechaza, que sea con un mensaje claro y no con un 500.", "ok"),
        simple_doc([["Cabecera %PDF-2.0"]], version="2.0"))

    add(Case(
        "E04", "estructura/E04-xref-stream.pdf", "estructura", "Cross-reference stream y object streams",
        "Lo que generan Word, LibreOffice, Chrome y la mayoría de las herramientas modernas: sin tabla xref "
        "de texto, con objetos comprimidos dentro de object streams.",
        "Se firma. La revisión agregada puede usar xref stream o tabla, pero la firma previa al archivo "
        "tiene que seguir intacta.", "ok"),
        writer_bytes(rewrite(simple_doc([["Xref stream + object streams"]]), stream_xrefs=True)))

    rev1 = simple_doc([["Revision 1"]])
    rev2 = incremental(rev1, {5: stream_obj(content_stream(["Revision 2: contenido reemplazado"]))})
    rev3 = incremental(rev2, {6: b"<< /Title (Revision 3) /Producer (pdf-suite) >>"}, trailer_extra=b" /Info 6 0 R")
    add(Case(
        "E05", "estructura/E05-revisiones-incrementales.pdf", "estructura", "Varias revisiones incrementales previas",
        "El archivo ya tiene tres revisiones (/Prev encadenados). Pasa con documentos editados varias veces "
        "o rellenados en Acrobat antes de firmar.",
        "Se firma. El ByteRange de la nueva firma cubre todo el archivo, incluidas las revisiones previas.",
        "ok"), rev3)

    add(Case(
        "E06", "estructura/E06-fin-de-linea-crlf.pdf", "estructura", "Fines de línea CRLF",
        "Archivos generados en Windows o que pasaron por una conversión de texto. Los parsers que buscan "
        "`\\n` a mano calculan mal offsets.",
        "Se firma.", "ok"),
        simple_doc([["Fines de linea CRLF"]], eol=b"\r\n"))

    add(Case(
        "E07", "estructura/E07-sin-eol-final.pdf", "estructura", "Sin fin de línea después de %%EOF",
        "El archivo termina justo en `%%EOF`. Un firmante que concatena la revisión nueva sin agregar un "
        "fin de línea deja `%%EOF1 0 obj`, que algunos lectores no aceptan.",
        "Se firma, y la revisión nueva empieza en una línea propia.", "ok"),
        simple_doc([["Sin EOL final"]], final_eol=False))

    # ---------------------------------------------------------------- tolerancia
    add(Case(
        "T01", "tolerancia/T01-bytes-despues-de-eof.pdf", "tolerancia", "Bytes después de %%EOF",
        "Relleno con ceros o espacios al final, típico de sistemas de correo, escáneres y almacenamiento "
        "que redondea a bloques.",
        "Se firma, o se rechaza con 422. Si se firma, el resultado tiene que validar en Acrobat: el relleno "
        "queda dentro del ByteRange.", "ok_or_reject"),
        base + b"\x00" * 512)

    add(Case(
        "T02", "tolerancia/T02-bytes-antes-de-cabecera.pdf", "tolerancia", "Bytes antes de la cabecera %PDF",
        "Archivos con basura al principio (cabeceras MIME o de otro formato). Los offsets de la xref quedan "
        "corridos respecto del inicio del archivo.",
        "Se rechaza con 422, o se firma de forma que el resultado valide. No se acepta un 500 ni un PDF "
        "firmado que después no abre.", "ok_or_reject"),
        simple_doc([["Bytes antes de la cabecera"]], prefix=b"Content-Type: application/pdf\r\n\r\n"))

    add(Case(
        "T03", "tolerancia/T03-xref-desplazada.pdf", "tolerancia", "Offsets de la xref incorrectos",
        "La tabla xref apunta 7 bytes antes de cada objeto, como pasa cuando alguien edita el PDF como texto. "
        "Los lectores la reconstruyen; una firma incremental sobre una xref rota puede validar en una "
        "herramienta y no en otra.",
        "Se rechaza con 422, o se firma sólo si la revisión original queda intacta. Nunca un 500.",
        "ok_or_reject"),
        simple_doc([["Xref con offsets corridos"]], xref_shift=-7))

    # ---------------------------------------------------------------- contenido
    add(Case(
        "C01", "contenido/C01-300-paginas.pdf", "contenido", "300 páginas",
        "Expedientes largos. Detecta timeouts y procesos que recorren todas las páginas sin necesidad.",
        "Se firma en un tiempo razonable (medirlo).", "ok"),
        simple_doc([[f"Pagina {i + 1} de 300"] for i in range(300)]))

    add(Case(
        "C02", "contenido/C02-paginas-rotadas-y-tamanos-mixtos.pdf", "contenido", "Páginas rotadas y de tamaños distintos",
        "A4, oficio y A3 apaisada, con /Rotate 90 y 270. Las firmas visibles calculan mal la posición o "
        "quedan giradas.",
        "Se firma. Si la firma es visible, el sello queda derecho y dentro de la página.", "ok"),
        _mixed_pages())

    add(Case(
        "C03", "contenido/C03-atributos-heredados.pdf", "contenido", "MediaBox y Resources heredados",
        "Las páginas no tienen /MediaBox ni /Resources propios: los heredan del nodo /Pages. Un estampador "
        "que lee sólo la página no encuentra el tamaño ni las fuentes.",
        "Se firma.", "ok"),
        _inherited_attrs())

    add(Case(
        "C04", "contenido/C04-25-mb.pdf", "contenido", "Archivo de unos 25 MB",
        "Límites de subida (proxy, framework, gateway) y lecturas completas en memoria. El contenido es "
        "una imagen sin comprimir, que git guarda comprimida.",
        "Se firma, o se rechaza con 413 y un mensaje claro si supera el límite documentado.", "ok_or_reject"),
        _big_doc(25 * 1024 * 1024))

    add(Case(
        "C05", "contenido/C05-metadatos-unicode.pdf", "contenido", "Metadatos Unicode y XMP",
        "Título, autor y asunto en UTF-16BE con acentos, eñes y caracteres fuera de Latin-1, más un paquete "
        "XMP. Rompe a quien loguea o propaga metadatos asumiendo ASCII.",
        "Se firma y los metadatos se conservan.", "ok"),
        _unicode_metadata())

    add(Case(
        "C06", "contenido/C06-declara-pdfa-2b.pdf", "contenido", "Declara PDF/A-2B",
        "El XMP declara PDF/A-2B (pdfaid). Archivo exigido en muchos organismos. Una firma visible con fuente "
        "sin embeber, o una revisión que reescribe el archivo, rompe la conformidad. El archivo sólo la "
        "declara: verificar el resultado con veraPDF.",
        "Se firma por actualización incremental y el resultado sigue declarando PDF/A.", "ok"),
        _pdfa_declared())

    add(Case(
        "C07", "contenido/C07-adjunto.pdf", "contenido", "Archivo adjunto embebido",
        "Un XML adjunto (EmbeddedFiles), como en las facturas o en PDF/A-3. La firma tiene que cubrirlo.",
        "Se firma y el adjunto se conserva.", "ok"),
        _with_attachment())

    add(Case(
        "C08", "contenido/C08-pagina-vacia-sin-contents.pdf", "contenido", "Página sin /Contents ni /Resources",
        "Página en blanco válida que no tiene stream de contenido. El código que asume que /Contents existe "
        "falla al estampar.",
        "Se firma.", "ok"),
        build_pdf([
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
        ]))

    # ---------------------------------------------------------------- seguridad
    w = rewrite(simple_doc([["Cifrado con clave de apertura"]]))
    w.encrypt("propietario", "usuario")
    add(Case(
        "S01", "seguridad/S01-cifrado-con-clave-de-apertura.pdf", "seguridad", "Cifrado con clave de apertura",
        "Hace falta la clave para abrirlo (contraseña de usuario `usuario`, de propietario `propietario`). "
        "Sin clave no se puede firmar.",
        "Se rechaza con 422 y un mensaje que diga que el PDF está protegido. Nunca un 500.", "reject"),
        writer_bytes(w))

    w = rewrite(simple_doc([["Cifrado sin clave de apertura"]]))
    w.encrypt("propietario", "")
    add(Case(
        "S02", "seguridad/S02-cifrado-sin-clave-de-apertura.pdf", "seguridad", "Cifrado sólo con clave de propietario",
        "Abre sin contraseña pero está cifrado y tiene permisos restringidos. Es muy común. Firmarlo exige "
        "escribir la revisión cifrada con la clave de propietario.",
        "Se rechaza con 422 explicando la protección, o se firma respetando los permisos. Nunca un 500 ni "
        "una revisión sin cifrar mezclada con una cifrada.", "ok_or_reject"),
        writer_bytes(w))

    certified_p1 = sign_with(simple_doc([["Certificado: sin cambios permitidos (P=1)"]]),
                             pki.signer(pki.rsa), field_name="Certificacion", certify=True, perms=MDPPerm.NO_CHANGES)
    add(Case(
        "S03", "seguridad/S03-certificado-p1.pdf", "seguridad", "Certificado con DocMDP P=1",
        "Firma de certificación que no permite ningún cambio. Cualquier firma nueva invalida la certificación.",
        "Se rechaza con 422 explicando que el documento está certificado sin cambios permitidos.",
        "reject", verify={"signatures": 1, "intact": True}), certified_p1)

    certified_p2 = sign_with(simple_doc([["Certificado: firmas permitidas (P=2)"]]),
                             pki.signer(pki.rsa), field_name="Certificacion", certify=True, perms=MDPPerm.FILL_FORMS)
    add(Case(
        "S04", "seguridad/S04-certificado-p2.pdf", "seguridad", "Certificado con DocMDP P=2",
        "Firma de certificación que permite completar formularios y firmar. Es el flujo de un trámite que "
        "un organismo certifica y el ciudadano firma.",
        "Se firma y la certificación sigue válida (cambio permitido).", "ok",
        verify={"signatures": 1, "intact": True}), certified_p2)

    # ---------------------------------------------------------------- formularios
    add(Case(
        "F01", "formularios/F01-acroform.pdf", "formularios", "Formulario con campos completados",
        "AcroForm con texto y casilla, con apariencias. Una firma tiene que agregarse al /Fields sin perder "
        "los campos existentes.",
        "Se firma y los campos conservan sus valores.", "ok"),
        _acroform(need_appearances=False))

    add(Case(
        "F02", "formularios/F02-need-appearances.pdf", "formularios", "Formulario con NeedAppearances true",
        "El visor regenera las apariencias al abrir. Acrobat puede marcar el documento como modificado "
        "después de la firma.",
        "Se firma. Idealmente el firmante genera las apariencias y quita NeedAppearances antes de firmar.",
        "ok"),
        _acroform(need_appearances=True))

    w = IncrementalPdfFileWriter(BytesIO(simple_doc([["Con campo de firma vacio Firma1"]])))
    fields.append_signature_field(w, fields.SigFieldSpec("Firma1", box=(72, 600, 272, 660)))
    add(Case(
        "F03", "formularios/F03-campo-de-firma-vacio.pdf", "formularios", "Campo de firma vacío preexistente",
        "El documento trae un campo de firma `Firma1` sin firmar, preparado por quien emitió el trámite.",
        "Se firma, ya sea en ese campo o en uno nuevo, sin errores por nombre duplicado.", "ok"),
        writer_bytes(w))

    add(Case(
        "F04", "formularios/F04-campo-de-texto-llamado-firma1.pdf", "formularios",
        "Campo de texto con el nombre que el firmante elegiría",
        "Un campo de texto se llama `Firma1`. El firmante que arma el nombre como `Firma{n+1}` choca con un "
        "campo que no es de firma.",
        "Se firma con un nombre de campo libre. Nunca un 500.", "ok"),
        _acroform(need_appearances=False, text_field_name="Firma1"))

    signed_as_firma2 = sign_with(simple_doc([["Firmado en un campo llamado Firma2"]]),
                                 pki.signer(pki.rsa), field_name="Firma2")
    add(Case(
        "F05", "formularios/F05-firma-existente-llamada-firma2.pdf", "formularios",
        "Una firma existente en el campo Firma2",
        "Hay una sola firma, pero su campo se llama `Firma2`. El firmante que cuenta firmas para elegir el "
        "nombre (`Firma{n+1}`) intenta usar un campo ya firmado.",
        "Se co-firma con otro nombre de campo y la firma previa sigue intacta.", "ok",
        verify={"signatures": 1, "intact": True}), signed_as_firma2)

    # ---------------------------------------------------------------- firmados
    add(Case(
        "P01", "firmados/P01-firma-previa-pades.pdf", "firmados", "Firma PAdES previa de otra PKI",
        "Co-firma: el documento ya trae una firma PAdES con sello de tiempo, de una CA que el validador no "
        "conoce.",
        "Se firma y la firma previa queda intacta. La verificación la informa íntegra pero no confiable.",
        "ok", verify={"signatures": 1, "intact": True, "trusted": False}),
        sign_with(base, pki.signer(pki.rsa), timestamper=pki.timestamper()))

    add(Case(
        "P02", "firmados/P02-firma-previa-ecdsa.pdf", "firmados", "Firma previa ECDSA P-256",
        "Algoritmo de clave distinto de RSA. Validadores que asumen RSA fallan al leer la clave o el "
        "algoritmo de firma.",
        "Se firma y la verificación interpreta la firma ECDSA.", "ok",
        verify={"signatures": 1, "intact": True}),
        sign_with(base, pki.signer(pki.ecdsa)))

    add(Case(
        "P03", "firmados/P03-firma-previa-pkcs7-detached.pdf", "firmados", "Firma previa adbe.pkcs7.detached",
        "Subfiltro no PAdES, el más común en firmas viejas y de algunos productos. La verificación tiene que "
        "aceptarlo y no reportarlo como nivel PAdES.",
        "Se firma. La verificación informa el subfiltro.", "ok",
        verify={"signatures": 1, "intact": True}),
        sign_with(base, pki.signer(pki.rsa), subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED))

    add(Case(
        "P04", "firmados/P04-firma-previa-sha512.pdf", "firmados", "Firma previa con digest SHA-512",
        "Digest distinto del habitual SHA-256.",
        "Se firma. La verificación la valida.", "ok",
        verify={"signatures": 1, "intact": True}),
        sign_with(base, pki.signer(pki.rsa), md="sha512"))

    two = sign_with(sign_with(base, pki.signer(pki.rsa), field_name="FirmaA"), pki.signer(pki.ecdsa), field_name="FirmaB")
    add(Case(
        "P05", "firmados/P05-dos-firmas-previas.pdf", "firmados", "Dos firmas previas",
        "Circuito de varios firmantes. La tercera firma no puede alterar las dos anteriores.",
        "Se firma y las tres firmas quedan íntegras.", "ok",
        verify={"signatures": 2, "intact": True}), two)

    signed = sign_with(base, pki.signer(pki.rsa))
    page_content = 5  # contenido de la página en `base`
    modified = incremental(signed, {page_content: stream_obj(content_stream(["Texto agregado despues de firmar"]))})
    add(Case(
        "P06", "firmados/P06-contenido-modificado-tras-firmar.pdf", "firmados",
        "Contenido de página cambiado después de firmar",
        "Una revisión posterior a la firma reemplaza el texto de la página. La firma sigue siendo "
        "criptográficamente correcta para su revisión, pero el documento que se ve ya no es el firmado.",
        "La verificación informa la modificación (no da la firma por buena para el documento completo). "
        "Firmarlo de nuevo no debe ocultar el problema.",
        "ok_or_reject", verify={"signatures": 1, "intact": True, "modified": True}), modified)

    corrupted = bytearray(signed)
    pos = corrupted.find(b"Documento base de la suite")
    corrupted[pos:pos + 9] = b"DOCUMENTO"
    add(Case(
        "P07", "firmados/P07-bytes-firmados-alterados.pdf", "firmados", "Bytes firmados alterados",
        "Se cambió texto dentro del rango firmado sin tocar la estructura (mismo largo), como una corrupción "
        "en tránsito o una edición directa. El hash ya no coincide.",
        "La verificación informa la firma como no íntegra.", "ok_or_reject",
        verify={"signatures": 1, "intact": False}), bytes(corrupted))

    # ---------------------------------------------------------------- entrada (API)
    add(Case(
        "I01", "entrada/I01-vacio.pdf", "entrada", "Archivo vacío",
        "0 bytes, como cuando el cliente sube antes de terminar de leer el archivo.",
        "Se rechaza con 4xx y un mensaje claro.", "reject"), b"")

    add(Case(
        "I02", "entrada/I02-no-es-pdf.pdf", "entrada", "Otro formato con extensión .pdf",
        "Un PNG renombrado. Validar por extensión o content-type no alcanza.",
        "Se rechaza con 4xx.", "reject"), _tiny_png())

    add(Case(
        "I03", "entrada/I03-truncado.pdf", "entrada", "PDF truncado",
        "Descarga o subida cortada a la mitad: sin xref ni %%EOF.",
        "Se rechaza con 4xx, o se firma sólo si el resultado valida. Nunca un 500.", "ok_or_reject"),
        base[: len(base) // 2])

    add(Case(
        "I04", "estructura/E01-base.pdf", "entrada", "Nombre de archivo con caracteres no ASCII",
        "El nombre del archivo subido viaja al header Content-Disposition de la respuesta. Con caracteres "
        "fuera de Latin-1 el header no se puede codificar si no se usa `filename*` (RFC 6266).",
        "Se firma y la respuesta trae un nombre de descarga correcto.", "ok",
        upload={"filename": "Resolución Nº 123 – año 2026 ✓.pdf"}), None)

    add(Case(
        "I05", "estructura/E01-base.pdf", "entrada", "Nombre de archivo con comillas y extensión en mayúsculas",
        "Comillas dentro del nombre rompen un `filename=\"...\"` armado a mano; `.PDF` en mayúsculas no "
        "coincide con un `removesuffix('.pdf')`.",
        "Se firma y el nombre de descarga es válido y termina en .pdf una sola vez.", "ok",
        upload={"filename": 'Nota "urgente".PDF'}), None)

    add(Case(
        "I06", "estructura/E01-base.pdf", "entrada", "Motivo y lugar con Unicode",
        "Los campos /Reason y /Location se escriben como strings PDF: con caracteres fuera de PDFDocEncoding "
        "hay que usar UTF-16BE.",
        "Se firma y el motivo se lee igual en Acrobat.", "ok",
        upload={"form": {"reason": "Aprobación — Dirección de Ñandúes 📄", "location": "San Martín de los Andes, AR"}}),
        None)

    return cases


# --------------------------------------------------------------------------- helpers de casos
def _mixed_pages() -> bytes:
    sizes = [(b"[0 0 595 842]", b""), (b"[0 0 612 1008]", b" /Rotate 90"), (b"[0 0 1191 842]", b" /Rotate 270"),
             (b"[50 50 645 892]", b"")]
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [%s] /Count %d >>" % (b" ".join(b"%d 0 R" % (4 + 2 * i) for i in range(len(sizes))), len(sizes)),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    labels = ["A4", "Oficio, Rotate 90", "A3 apaisada, Rotate 270", "A4 con origen desplazado"]
    for i, ((box, extra), label) in enumerate(zip(sizes, labels)):
        objs.append(b"<< /Type /Page /Parent 2 0 R /MediaBox %s%s /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>"
                    % (box, extra, 5 + 2 * i))
        objs.append(stream_obj(content_stream([label], y=700 if i != 3 else 750)))
    return build_pdf(objs)


def _inherited_attrs() -> bytes:
    return build_pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [4 0 R 6 0 R] /Count 2 /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 3 0 R >> >> >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /Page /Parent 2 0 R /Contents 5 0 R >>",
        stream_obj(content_stream(["MediaBox y Resources heredados (1)"])),
        b"<< /Type /Page /Parent 2 0 R /Contents 7 0 R >>",
        stream_obj(content_stream(["MediaBox y Resources heredados (2)"])),
    ])


def _big_doc(size: int) -> bytes:
    side = int((size / 3) ** 0.5)
    # Degradé repetido: sin filtro en el PDF, pero muy compresible para git.
    row = bytes((x * 255 // side) for x in range(side) for _ in range(3))
    image = row * side
    return build_pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /XObject << /Im1 5 0 R >> >> /Contents 4 0 R >>",
        stream_obj(b"q 451 0 0 451 72 300 cm /Im1 Do Q"),
        stream_obj(image, b" /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceRGB /BitsPerComponent 8" % (side, side)),
    ])


def _utf16(text: str) -> bytes:
    return b"<FEFF" + text.encode("utf-16-be").hex().upper().encode() + b">"


XMP_TEMPLATE = """<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/"{extra_ns}>
   <dc:title><rdf:Alt><rdf:li xml:lang="x-default">{title}</rdf:li></rdf:Alt></dc:title>{extra}
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"""


def _xmp(title: str, extra_ns: str = "", extra: str = "") -> bytes:
    return stream_obj(XMP_TEMPLATE.format(title=title, extra_ns=extra_ns, extra=extra).encode("utf-8"),
                      b" /Type /Metadata /Subtype /XML")


def _unicode_metadata() -> bytes:
    title = "Resolución Nº 123/2026 — Ñandú «año» 日本 ✓"
    info = b"<< /Title %s /Author %s /Subject %s /Producer (pdf-suite) >>" % (
        _utf16(title), _utf16("José Peña Güemes"), _utf16("Prueba de metadatos: €, ½, Ω, emoji 📄"))
    return build_pdf([
        b"<< /Type /Catalog /Pages 2 0 R /Metadata 6 0 R >>",
        b"<< /Type /Pages /Kids [4 0 R] /Count 1 >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents 5 0 R >>",
        stream_obj(content_stream(["Metadatos Unicode (ver Propiedades del documento)"])),
        _xmp(title),
        info,
    ], trailer_extra=b" /Info 7 0 R")


def _pdfa_declared() -> bytes:
    # Sin texto: sin fuentes no hace falta embeber ninguna. Sólo un rectángulo.
    return build_pdf([
        b"<< /Type /Catalog /Pages 2 0 R /Metadata 5 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << >> /Contents 4 0 R >>",
        stream_obj(b"0 0 0 RG 2 w 72 600 451 170 re S"),
        _xmp("Declara PDF/A-2B", ' xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/"',
             "\n   <pdfaid:part>2</pdfaid:part><pdfaid:conformance>B</pdfaid:conformance>"),
    ], trailer_extra=b" /ID [<0123456789ABCDEF0123456789ABCDEF> <0123456789ABCDEF0123456789ABCDEF>]")


def _with_attachment() -> bytes:
    xml = b'<?xml version="1.0" encoding="UTF-8"?>\n<comprobante numero="0001-00000042" total="1234.56"/>\n'
    return build_pdf([
        b"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(comprobante.xml) 6 0 R] >> >> >>",
        b"<< /Type /Pages /Kids [4 0 R] /Count 1 >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents 5 0 R >>",
        stream_obj(content_stream(["Con comprobante.xml adjunto"])),
        b"<< /Type /Filespec /F (comprobante.xml) /UF %s /EF << /F 7 0 R >> /AFRelationship /Data >>" % _utf16("comprobante.xml"),
        stream_obj(xml, b" /Type /EmbeddedFile /Subtype /text#2Fxml"),
    ])


def _acroform(*, need_appearances: bool, text_field_name: str = "Nombre") -> bytes:
    na = b" /NeedAppearances true" if need_appearances else b""
    name = text_field_name.encode()
    return build_pdf([
        b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R 8 0 R] /DA (/Helv 0 Tf 0 g) "
        b"/DR << /Font << /Helv 3 0 R >> >>%s >> >>" % na,
        b"<< /Type /Pages /Kids [4 0 R] /Count 1 >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> "
        b"/Contents 5 0 R /Annots [6 0 R 8 0 R] >>",
        stream_obj(content_stream(["Formulario: campo de texto y casilla"])),
        b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (%s) /V (Juana Perez) /DA (/Helv 12 Tf 0 g) "
        b"/Rect [72 650 300 670] /P 4 0 R /F 4 /AP << /N 7 0 R >> >>" % name,
        stream_obj(b"/Tx BMC q BT /Helv 12 Tf 0 g 2 5 Td (Juana Perez) Tj ET Q EMC",
                   b" /Type /XObject /Subtype /Form /BBox [0 0 228 20] /Resources << /Font << /Helv 3 0 R >> >>"),
        b"<< /Type /Annot /Subtype /Widget /FT /Btn /T (Acepta) /V /Si /AS /Si /Rect [72 620 86 634] "
        b"/P 4 0 R /F 4 /AP << /N << /Si 9 0 R /Off 10 0 R >> >> >>",
        stream_obj(b"0 g 2 2 10 10 re f", b" /Type /XObject /Subtype /Form /BBox [0 0 14 14]"),
        stream_obj(b"", b" /Type /XObject /Subtype /Form /BBox [0 0 14 14]"),
    ])


def _tiny_png() -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return len(data).to_bytes(4, "big") + kind + data + zlib.crc32(kind + data).to_bytes(4, "big")

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", (1).to_bytes(4, "big") * 2 + b"\x08\x02\x00\x00\x00")
            + chunk(b"IDAT", zlib.compress(b"\x00\xff\x80\x00")) + chunk(b"IEND", b""))


# --------------------------------------------------------------------------- README
README_INTRO = """# Suite de PDFs para APIs de firma

PDFs de prueba para atajar errores en servicios de firma digital (PAdES) antes de que lleguen a
producción. Cada archivo reproduce una situación que aparece con documentos reales: estructuras que
generan distintas herramientas, archivos imperfectos, cifrado, certificación, formularios, firmas
previas y entradas inválidas.

La suite no depende de esta PoC: sirve para cualquier API que reciba un PDF y devuelva el PDF firmado,
o que verifique firmas.

## Contenido

- `manifest.json`: un registro por caso, con el archivo, qué prueba, qué se espera y cómo subirlo.
  Pensado para que un runner lo recorra (ver `scripts/run_pdf_suite.py`).
- Una carpeta por categoría con los PDFs.
- Este README, generado junto con el manifest por `scripts/make_pdf_suite.py`. Para cambiar un caso,
  editá el generador y volvé a correrlo: no edites este archivo a mano.

## Cómo leer lo esperado

Columna **Firma**, lo que tiene que hacer el endpoint de firma con ese archivo:

- `ok`: devuelve un PDF firmado. Además, la firma nueva valida íntegra y las firmas previas siguen
  íntegras.
- `reject`: responde 4xx con un mensaje que explique el motivo.
- `ok_or_reject`: cualquiera de las dos es aceptable, según la política del sistema.

En **todos** los casos es un error: un 5xx, un timeout, o un PDF firmado que después no valida o no
abre en Acrobat. También lo es que un caso deje al servicio roto para los pedidos siguientes: el
runner vuelve a firmar E01 después de cada respuesta que no sea 200 para detectarlo (estado
compartido entre pedidos, como un firmante reusado que queda a medio configurar).

## Cómo correrla

```powershell
uv run python scripts/make_pdf_suite.py                     # regenera PDFs, manifest y este README
uv run python scripts/run_pdf_suite.py --base-url http://127.0.0.1:8000
uv run python scripts/run_pdf_suite.py --only S01,F05       # algunos casos
```

Los PDFs firmados quedan en `out/pdf-suite/` para abrirlos en Acrobat. Para otra API, el runner es
lo único que cambia: los PDFs y el manifest no dependen de esta PoC.

Los casos de `firmados/` (y S03, S04, F05) traen firmas de una **PKI de prueba ajena**, generada por el
script en cada corrida. Ningún validador debería confiar en ella: esos casos prueban integridad,
co-firma y algoritmos, no confianza. Que la verificación diga "no confiable" es lo correcto.

Los casos I04 a I06 reusan `E01-base.pdf` y cambian lo que se envía: el nombre del archivo o los
campos del formulario (ver `upload` en el manifest).

## Qué revisar a mano

El runner automatiza la respuesta HTTP y la verificación por API. Hay cosas que conviene mirar con
otras herramientas al menos una vez por versión:

- Abrir los PDFs firmados en **Adobe Acrobat Reader** y revisar el panel de firmas: es el validador
  que van a usar los destinatarios.
- Validar C06 firmado con **veraPDF** (conformidad PDF/A).
- Validar con el **validador DSS de la Comisión Europea** para comparar el nivel PAdES informado.
- Medir el tiempo de C01 y C04 con la configuración de producción (proxy y límites de subida incluidos).
"""


def write_readme(out: Path, cases: list[Case]) -> None:
    parts = [README_INTRO, "\n## Casos\n"]
    for cat, label in CATEGORIES.items():
        rows = [c for c in cases if c.category == cat]
        if not rows:
            continue
        parts.append(f"\n### {label} (`{cat}`)\n\n| Caso | Archivo | Firma | Qué reproduce | Qué se espera |\n|---|---|---|---|---|\n")
        for c in rows:
            upload = ""
            if c.upload.get("filename"):
                upload = f" Se sube como `{c.upload['filename']}`."
            if c.upload.get("form"):
                upload = " Campos: " + ", ".join(f"`{k}={v}`" for k, v in c.upload["form"].items()) + "."
            cell = lambda s: s.replace("|", "\\|").replace("\n", " ")  # noqa: E731
            parts.append(
                f"| **{c.id}** {cell(c.title)} | `{c.file}` | `{c.sign}` | {cell(c.problem)}{cell(upload)} | {cell(c.expected)} |\n"
            )
    (out / "README.md").write_text("".join(parts), encoding="utf-8")


# --------------------------------------------------------------------------- main
def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    cases = build_cases(ForeignPki())
    for case, data in cases:
        if data is None:
            continue
        path = args.out / case.file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    manifest = {
        "description": "Suite de PDFs para APIs de firma. Ver README.md.",
        "sign_values": {"ok": "devuelve PDF firmado válido", "reject": "4xx con mensaje",
                        "ok_or_reject": "cualquiera de las dos; nunca 5xx"},
        "categories": CATEGORIES,
        "cases": [asdict(c) for c, _ in cases],
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_readme(args.out, [c for c, _ in cases])
    print(f"{len(cases)} casos en {args.out}")


if __name__ == "__main__":
    main()
