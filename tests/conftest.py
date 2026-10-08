"""
Fixtures compartidas. Los PDFs se firman en el mismo proceso con pyHanko (y la
TSA de la app, sin HTTP), porque /sign necesita que la app se consulte a sí misma
por red y TestClient no expone un puerto real.
"""

import os
import shutil
import socket
import tempfile
import threading
import time


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# Antes de importar la app: pki.PKI_DIR, pki.BASE_URL y store.DB_PATH se leen al importar
# los módulos, y los tests no deben tocar la PKI de ./pki ni la fuente de ./certs.db. Las
# URLs de CRL y OCSP de la PKI de prueba apuntan a un puerto libre, donde `pki_server`
# sirve la app para el modo con conexión de /verify.
_PKI_DIR = tempfile.mkdtemp(prefix="pades-test-pki-")
_PORT = _free_port()
os.environ["PKI_DIR"] = _PKI_DIR
os.environ["CERT_STORE_DB"] = os.path.join(_PKI_DIR, "certs.db")
os.environ["PUBLIC_BASE_URL"] = f"http://127.0.0.1:{_PORT}"

from io import BytesIO  # noqa: E402

import pytest  # noqa: E402
import requests  # noqa: E402
from demo import minimal_pdf  # noqa: E402
import uvicorn  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter  # noqa: E402
from pyhanko.sign import fields, signers  # noqa: E402
from pyhanko.sign.signers.pdf_signer import PdfTimeStamper  # noqa: E402

from pades_lt_poc import pki  # noqa: E402
from pades_lt_poc.app import app  # noqa: E402
from pades_lt_poc.services import certificates as certificates_service  # noqa: E402


def pytest_unconfigure(config):
    shutil.rmtree(_PKI_DIR, ignore_errors=True)


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:  # el lifespan genera la PKI en _PKI_DIR
        yield c


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
    yield pki.BASE_URL
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture(scope="session")
def timestamper(client):
    return client.app.state.tsa_engine


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
