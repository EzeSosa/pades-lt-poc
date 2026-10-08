from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

# Páginas estáticas que llaman a la API desde el navegador. Su CSS y JS se sirven en
# /ui/static (montado en app.py).
STATIC_DIR = Path(__file__).parent.parent / "static"

router = APIRouter(prefix="/ui", tags=["UI"])


class RevalidatedStaticFiles(StaticFiles):
    """El CSS y el JS de la UI, que el navegador revalida en cada carga (ETag: 304 si no cambiaron).

    Sin `Cache-Control`, con sólo `Last-Modified`, el navegador los reusa sin preguntar
    (caché heurístico) mientras las páginas, que no lo tienen, llegan siempre nuevas: después
    de actualizar la app quedaba el HTML nuevo con el JS viejo, y los controles nuevos no andaban.
    """

    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache"
        return response


def _page(name: str) -> HTMLResponse:
    return HTMLResponse((STATIC_DIR / name).read_text(encoding="utf-8"))


@router.get("", include_in_schema=False)
def ui() -> RedirectResponse:
    return RedirectResponse("/ui/firmas")


@router.get("/firmas", response_class=HTMLResponse)
def firmas() -> HTMLResponse:
    """Inspector de firmas: un PDF, tres tabs (certificados, verificación e inspección)."""
    return _page("firmas.html")


@router.get("/certificado", response_class=HTMLResponse)
def certificado() -> HTMLResponse:
    """Inspector de un certificado suelto (.crt, .pem, .p7c o base64), con el reporte de la tab Inspección."""
    return _page("certificado.html")


@router.get("/fuente", response_class=HTMLResponse)
def fuente() -> HTMLResponse:
    """ABM de la fuente de certificados (/store/certificates)."""
    return _page("fuente.html")
