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
  POST /verify                        valida offline usando sólo el DSS embebido
  POST /certificates                  extrae la cadena de certificados de cada firma válida
  GET  /ui/certificates               UI de POST /certificates (una card por firma)
  GET  /ui/verify                     UI de POST /verify (reporte de validación)

Estructura:
  routers/    endpoints HTTP, uno por área
  services/   una clase por operación (firmar, verificar, extraer certificados), sin HTTP
  static/     páginas de /ui y su CSS compartido (servido en /ui/static)
  pki.py      la mini PKI (certificados, CRLs, OCSP)
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import pki
from .routers import certificates, ocsp, signing, tsa, ui, verification
from .routers import pki as pki_router
from .services import UnprocessablePdf
from .services.certificates import CertificateExtractor
from .services.signing import PdfSigner
from .services.timestamping import load_tsa
from .services.verification import SignatureVerifier


@asynccontextmanager
async def lifespan(app: FastAPI):
    pki.ensure_pki()
    app.state.tsa_engine = load_tsa()
    app.state.signer = PdfSigner.from_pki()
    app.state.verifier = SignatureVerifier.from_pki()
    app.state.certificate_extractor = CertificateExtractor()
    yield


app = FastAPI(title="PoC PAdES B-LT", lifespan=lifespan)
for module in (pki_router, ocsp, tsa, signing, verification, certificates, ui):
    app.include_router(module.router)
app.mount("/ui/static", StaticFiles(directory=ui.STATIC_DIR), name="ui-static")


@app.exception_handler(UnprocessablePdf)
def unprocessable_pdf(request: Request, exc: UnprocessablePdf) -> JSONResponse:
    return JSONResponse({"detail": str(exc)}, status_code=422)


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/ui/certificates")


def main() -> None:
    import uvicorn

    uvicorn.run("pades_lt_poc.app:app", host="127.0.0.1", port=8000)
