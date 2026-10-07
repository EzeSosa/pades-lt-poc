"""
PoC FastAPI: firma PAdES B-LT (opcionalmente B-LTA) con pyHanko.

Endpoints:
  GET  /pki/{root|intermediate}.crt   certificados de las CAs (PEM)
  GET  /pki/{root|intermediate}.crl   CRLs (DER)
  POST /pki/revoke/{entidad}          revoca intermediate|signer|tsa (para pruebas)
  POST /pki/unrevoke-all              deshace todas las revocaciones
  POST /ocsp  | GET /ocsp/{b64}       respondedor OCSP RFC 6960
  POST /tsa                           TSA RFC 3161
  POST /sign                          sube un PDF, devuelve el PDF firmado PAdES B-LT
  POST /verify                        valida offline con el DSS embebido y la fuente de certificados
  POST /certificates                  extrae la cadena de certificados de cada firma válida
  POST /certificates/inspect          detalle de un certificado (DER, PEM, PKCS#7 o base64)
  GET/POST /store/certificates        fuente de certificados (raíces e intermedios): listar y agregar
  GET/PATCH/DELETE /store/certificates/{id}   ver, habilitar/confiar/anotar y borrar
  POST /store/certificates/seed       vuelve a agregar lo que falte de la carga inicial
  GET  /ui/firmas                     UI: un PDF, tres tabs (certificados, verificación e inspección)
  GET  /ui/certificado                UI de un certificado suelto (mismo reporte que la tab Inspección)
  GET  /ui/fuente                     UI del ABM de la fuente de certificados

Estructura:
  routers/    endpoints HTTP, uno por área
  services/   una clase por operación (firmar, verificar, extraer e inspeccionar certificados) y la
              fuente de certificados (SQLite), sin HTTP
  seed/       la carga inicial de la fuente (AC Raíz Argentina 2007 y 2016, AC ONTI)
  static/     las páginas de /ui, su CSS y un JS por tab (servidos en /ui/static)
  pki.py      la mini PKI (certificados, CRLs, OCSP)
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import pki
from .routers import certificates, ocsp, signing, store, tsa, ui, verification
from .routers import pki as pki_router
from .services import UnprocessableInput
from .services.certificates import CertificateExtractor
from .services.inspection import CertificateInspector
from .services.signing import PdfSigner
from .services.store import CertificateStore
from .services.timestamping import load_tsa
from .services.verification import SignatureVerifier


@asynccontextmanager
async def lifespan(app: FastAPI):
    pki.ensure_pki()
    app.state.tsa_engine = load_tsa()
    app.state.signer = PdfSigner.from_pki()
    # La fuente de certificados se abre (y la primera vez se crea con la carga inicial) al arrancar.
    app.state.store = CertificateStore()
    app.state.verifier = SignatureVerifier.from_pki(app.state.store)
    app.state.certificate_extractor = CertificateExtractor(app.state.store)
    app.state.certificate_inspector = CertificateInspector(app.state.store)
    yield
    app.state.store.close()


app = FastAPI(title="PoC PAdES B-LT", lifespan=lifespan)
for module in (pki_router, ocsp, tsa, signing, verification, certificates, store, ui):
    app.include_router(module.router)
app.mount("/ui/static", StaticFiles(directory=ui.STATIC_DIR), name="ui-static")


@app.exception_handler(UnprocessableInput)
def unprocessable_input(request: Request, exc: UnprocessableInput) -> JSONResponse:
    return JSONResponse({"detail": str(exc)}, status_code=422)


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/ui/firmas")


def main() -> None:
    import uvicorn

    uvicorn.run("pades_lt_poc.app:app", host="127.0.0.1", port=8000)
