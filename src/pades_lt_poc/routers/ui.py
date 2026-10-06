from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

# Las páginas llaman a los endpoints de la API desde el navegador; los estilos
# compartidos se sirven en /ui/static (montado en app.py).
STATIC_DIR = Path(__file__).parent.parent / "static"

router = APIRouter(prefix="/ui", tags=["UI"])


def _page(name: str) -> HTMLResponse:
    return HTMLResponse((STATIC_DIR / name).read_text(encoding="utf-8"))


@router.get("/certificates", response_class=HTMLResponse)
def certificates_ui() -> HTMLResponse:
    """UI sobre POST /certificates: una card por firma, con descarga y copia de cada certificado."""
    return _page("certificates.html")


@router.get("/verify", response_class=HTMLResponse)
def verify_ui() -> HTMLResponse:
    """Reporte de POST /verify: nivel PAdES, DSS y el resultado de cada firma."""
    return _page("verify.html")
