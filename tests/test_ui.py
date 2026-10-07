"""Tests de la UI (/ui/firmas, /ui/certificado y /ui/fuente)."""

import re

import pytest

FIRMAS_SCRIPTS = ["ui.js", "certificates.js", "verify.js", "inspect.js", "firmas.js"]
CERTIFICADO_SCRIPTS = ["ui.js", "inspect.js", "certificado.js"]
FUENTE_SCRIPTS = ["ui.js", "inspect.js", "fuente.js"]


def scripts(html: str) -> list[str]:
    return re.findall(r'<script src="/ui/static/([\w.]+)"', html)


@pytest.mark.parametrize(
    "page, expected",
    [("firmas", FIRMAS_SCRIPTS), ("certificado", CERTIFICADO_SCRIPTS), ("fuente", FUENTE_SCRIPTS)],
)
def test_pages_load_their_assets(client, page, expected):
    r = client.get(f"/ui/{page}")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert 'href="/ui/static/ui.css"' in r.text
    assert scripts(r.text) == expected  # ui.js primero: los demás lo usan


@pytest.mark.parametrize("page", ["firmas", "certificado", "fuente"])
def test_nav_links_the_pages_in_the_same_tab(client, page):
    html = client.get(f"/ui/{page}").text
    nav = re.search(r'<nav class="nav".*?</nav>', html, re.S).group()
    assert re.findall(r'href="(/ui/\w+)"', nav) == ["/ui/firmas", "/ui/certificado", "/ui/fuente"]
    assert "target=" not in nav
    assert f'href="/ui/{page}" aria-current="page"' in nav


def test_firmas_has_one_pdf_upload_and_three_tabs(client):
    html = client.get("/ui/firmas").text
    assert re.findall(r'role="tab" id="tab-(\w+)"', html) == ["certificados", "verificacion", "inspeccion"]
    assert html.count('role="tabpanel"') == 3
    assert html.count('type="file"') == 1  # sólo el PDF: el certificado suelto va en /ui/certificado


def test_certificado_page_reuses_the_inspection_report(client):
    html = client.get("/ui/certificado").text
    assert 'name="crt"' in html and 'name="b64"' in html
    js = client.get("/ui/static/certificado.js").text
    assert "renderInspection(" in js  # el mismo reporte que la tab Inspección (inspect.js)
    assert 'postForm("/certificates/inspect"' in js


@pytest.mark.parametrize("asset", ["ui.css", *dict.fromkeys(FIRMAS_SCRIPTS + CERTIFICADO_SCRIPTS + FUENTE_SCRIPTS)])
def test_assets_are_served(client, asset):
    r = client.get(f"/ui/static/{asset}")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/css" if asset.endswith(".css") else "text/javascript")


def test_firmas_calls_the_three_endpoints(client):
    js = client.get("/ui/static/firmas.js").text
    for endpoint in ("/certificates", "/verify", "/certificates/inspect"):
        assert f'postForm("{endpoint}"' in js


def test_pdf_and_certificate_are_saved_between_pages(client):
    assert 'save("firmas-pdf"' in client.get("/ui/static/firmas.js").text
    assert 'save("certificado"' in client.get("/ui/static/certificado.js").text
    assert "indexedDB.open" in client.get("/ui/static/ui.js").text


def test_dark_theme(client):
    css = client.get("/ui/static/ui.css").text
    assert "prefers-color-scheme: dark" in css
    assert ':root[data-theme="dark"]' in css


@pytest.mark.parametrize("path", ["/", "/ui"])
def test_redirects_to_firmas(client, path):
    r = client.get(path, follow_redirects=False)
    assert r.status_code == 307
    assert r.headers["location"] == "/ui/firmas"


@pytest.mark.parametrize("old", ["/ui/certificates", "/ui/verify", "/ui/certificate"])
def test_old_urls_are_gone(client, old):
    assert client.get(old).status_code == 404


def test_fuente_page_manages_the_store(client):
    js = client.get("/ui/static/fuente.js").text
    assert 'api("/store/certificates")' in js  # listar
    assert "patchJSON(`/store/certificates/${cert.id}`" in js  # habilitar, confiar, notas
    assert 'method: "DELETE"' in js  # baja
    assert 'postForm("/store/certificates/seed"' in js
    # Las altas no están acá: se hacen desde el reporte de inspección.
    assert 'postForm("/store/certificates",' not in js
    html = client.get("/ui/fuente").text
    assert 'type="file"' not in html
    assert 'href="/ui/certificado"' in html


def test_inspection_report_adds_to_the_store(client):
    """Alta en un solo lugar: el reporte de inspección, que usan /ui/certificado, la tab
    Inspección de /ui/firmas y el detalle de /ui/fuente."""
    inspect_js = client.get("/ui/static/inspect.js").text
    assert 'postForm("/store/certificates", body)' in inspect_js
    assert "cert.in_store" in inspect_js
    assert "store:added" in client.get("/ui/static/certificates.js").text  # la cadena se entera
    assert 'origin: "pdf"' in client.get("/ui/static/firmas.js").text
