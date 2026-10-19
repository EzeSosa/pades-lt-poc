"""La suite de PDFs de prueba (testdata/pdf-suite) contra /sign y /verify, como test de aceptación.

Es lo mismo que `scripts/run_pdf_suite.py` contra un server levantado, pero contra `pki_server`:
cada caso del manifest es un test, con el mismo chequeo y el mismo canario (después de un
rechazo se vuelve a firmar el PDF base, para detectar estado compartido entre pedidos).
"""

import json

import pytest

from run_pdf_suite import SUITE, canary_ok, run_case

pytestmark = pytest.mark.suite

CASES = json.loads((SUITE / "manifest.json").read_text(encoding="utf-8"))["cases"]


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_case(case, pki_server, tmp_path):
    result, detail, _elapsed = run_case(case, pki_server, SUITE, tmp_path)
    assert result == "ok", detail
    if "HTTP 200" not in detail:
        assert canary_ok(pki_server, SUITE), "después de este caso el servicio ya no firma el PDF base (E01)"
