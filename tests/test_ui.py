"""Tests de las páginas de /ui."""

import pytest


@pytest.mark.parametrize("page, endpoint", [("certificates", "/certificates"), ("verify", "/verify")])
def test_page_calls_its_endpoint(client, page, endpoint):
    r = client.get(f"/ui/{page}")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert f'fetch("{endpoint}"' in r.text
    assert 'href="/ui/static/ui.css"' in r.text


def test_shared_stylesheet(client):
    r = client.get("/ui/static/ui.css")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/css")


def test_root_redirects_to_ui(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 307
    assert r.headers["location"] == "/ui/certificates"
