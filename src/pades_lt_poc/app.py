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
  config.py     la configuración (variables de entorno), leída una vez al crear la app
  bootstrap.py  raíz de composición: crea los servicios y los conecta
  routers/      endpoints HTTP, uno por área
  services/     una clase por operación (firmar, verificar, extraer e inspeccionar certificados) y la
                fuente de certificados (SQLite), sin HTTP
  seed/         la carga inicial de la fuente (AC Raíz Argentina 2007 y 2016, AC ONTI)
  static/       las páginas de /ui, su CSS y un JS por tab (servidos en /ui/static)
  pki.py        la mini PKI (certificados, CRLs, OCSP)

La app se crea con `create_app()` (uvicorn: `--factory pades_lt_poc.app:create_app`), así que
importar este módulo no lee la configuración ni crea nada.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse

from . import bootstrap
from .config import Settings
from .routers import certificates, ocsp, signing, store, tsa, ui, verification
from .routers import pki as pki_router
from .domain.errors import UnprocessableInput


def create_app(settings: Settings | None = None) -> FastAPI:
    """La app con `settings`, o con la configuración del entorno si no se pasa."""
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # La PKI se genera y la fuente se abre (la primera vez, con su carga inicial) al arrancar.
        services = bootstrap.build(settings)
        app.state.services = services
        yield
        services.close()

    app = FastAPI(title="PoC PAdES B-LT", lifespan=lifespan)
    for module in (pki_router, ocsp, tsa, signing, verification, certificates, store, ui):
        app.include_router(module.router)
    app.mount("/ui/static", ui.RevalidatedStaticFiles(directory=ui.STATIC_DIR), name="ui-static")

    @app.exception_handler(UnprocessableInput)
    def unprocessable_input(request: Request, exc: UnprocessableInput) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=422)

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse("/ui/firmas")

    return app


def main() -> None:
    import uvicorn

    uvicorn.run("pades_lt_poc.app:create_app", factory=True, host="127.0.0.1", port=8000)
