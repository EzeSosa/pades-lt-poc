"""
Fixtures compartidas. Los PDFs se firman en el mismo proceso con pyHanko (y la
TSA de la app, sin HTTP), porque /sign necesita que la app se consulte a sí misma
por red y TestClient no expone un puerto real.

La app se crea con un `Settings` propio: la PKI y la fuente de los tests viven en una
carpeta temporal (no tocan ./pki ni ./certs.db), y las URLs de CRL y OCSP de la PKI de
prueba apuntan a un puerto libre, donde `pki_server` sirve la app para el modo con
conexión de /verify y para /sign.
"""

import shutil
import socket
import tempfile
import threading
import time
from io import BytesIO
from pathlib import Path

import pytest
import requests
import uvicorn
from demo import minimal_pdf
from fastapi.testclient import TestClient
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers
from pyhanko.sign.signers.pdf_signer import PdfTimeStamper

from pades_lt_poc.app import create_app
from pades_lt_poc.config import Settings
from pades_lt_poc.pki import MiniPki
from pades_lt_poc.services import certificates as certificates_service


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


_PKI_DIR = Path(tempfile.mkdtemp(prefix="pades-test-pki-"))
_PORT = _free_port()
SETTINGS = Settings(
    pki_dir=_PKI_DIR,
    public_base_url=f"http://127.0.0.1:{_PORT}",
    cert_store_db=_PKI_DIR / "certs.db",
)
# La misma PKI que usa la app (misma carpeta y URL), para que los tests lean sus certificados
# y claves, revoquen y armen CRLs y respuestas OCSP. La genera el lifespan de `client`.
pki = MiniPki(SETTINGS.pki_dir, SETTINGS.public_base_url)
app = create_app(SETTINGS)


def pytest_unconfigure(config):
    shutil.rmtree(_PKI_DIR, ignore_errors=True)


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:  # el lifespan genera la PKI en _PKI_DIR
        yield c


@pytest.fixture(scope="session")
def services(client):
    """Los servicios que armó la raíz de composición (`bootstrap.build`) para la app de los tests."""
    return client.app.state.services


@pytest.fixture(scope="session")
def pki_server(client):
    """La misma app escuchando en PUBLIC_BASE_URL, para que se puedan descargar sus CRL y OCSP.

    Sin lifespan: comparte `app.state` (y la PKI) con el TestClient, que ya lo levantó.
    """
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=_PORT, lifespan="off", log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("uvicorn no arrancó")
        time.sleep(0.05)
    yield pki.base_url
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture(scope="session")
def timestamper(services):
    return services.tsa_engine


@pytest.fixture(autouse=True)
def no_aia_network(monkeypatch):
    """Sin red: las descargas AIA fallan salvo que el test instale su propio `_http_get`."""

    def offline(url: str) -> bytes:
        raise requests.ConnectionError(f"sin red en los tests: {url}")

    monkeypatch.setattr(certificates_service, "_http_get", offline)


@pytest.fixture
def pdf() -> bytes:
    return minimal_pdf("Hola PAdES")


def load_signer(chain=(pki.INTERMEDIATE, pki.ROOT)) -> signers.SimpleSigner:
    """El firmante de la PKI de prueba, embebiendo en el CMS sólo los certs de `chain`."""
    return signers.SimpleSigner.load(
        key_file=str(pki.entity(pki.SIGNER).key_path),
        cert_file=str(pki.entity(pki.SIGNER).cert_path),
        ca_chain_files=[str(pki.entity(name).cert_path) for name in chain],
    )


def sign(pdf: bytes, signer, timestamper=None) -> bytes:
    writer = IncrementalPdfFileWriter(BytesIO(pdf))
    meta = signers.PdfSignatureMetadata(
        field_name=f"Firma{len(writer.prev.embedded_signatures) + 1}",
        md_algorithm="sha256",
        subfilter=fields.SigSeedSubFilter.PADES,
    )
    return signers.sign_pdf(writer, meta, signer=signer, timestamper=timestamper).getvalue()


def doc_timestamp(pdf: bytes, timestamper) -> bytes:
    writer = IncrementalPdfFileWriter(BytesIO(pdf))
    return PdfTimeStamper(timestamper).timestamp_pdf(writer, "sha256").getvalue()
