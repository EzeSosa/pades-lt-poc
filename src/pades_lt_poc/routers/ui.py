from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, RedirectResponse

# Páginas estáticas que llaman a la API desde el navegador. Su CSS y JS se sirven en
# /ui/static (montado en app.py).
STATIC_DIR = Path(__file__).parent.parent / "static"

router = APIRouter(prefix="/ui", tags=["UI"])


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
