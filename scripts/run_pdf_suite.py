"""
Corre la suite de testdata/pdf-suite contra la API (POST /sign y POST /verify) y compara con lo esperado.

Uso (con el server levantado):
  uv run python scripts/run_pdf_suite.py [--base-url http://127.0.0.1:8000] [--only E01,P05] [--out out/pdf-suite]

Por cada caso:
  - Firma: el status tiene que coincidir con `sign` del manifest (ok / reject / ok_or_reject).
    Un 5xx o un timeout es siempre un fallo.
  - Si firmó: el PDF devuelto se verifica, tiene que traer una firma más y todas íntegras
    (salvo las que ya venían rotas), y el nombre de descarga tiene que terminar en .pdf.
  - Si el caso trae `verify`: el PDF de entrada se verifica y se compara con lo esperado.
  - Canario: después de cada respuesta que no sea 200 se vuelve a firmar E01. Si falla, el caso
    dejó al servicio roto para los pedidos siguientes (estado compartido entre pedidos).

Los PDFs firmados quedan en --out para abrirlos en Acrobat. Sale con código 1 si algún caso falla.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import requests

SUITE = Path("testdata/pdf-suite")
TIMEOUT = 180


def post(base: str, path: str, pdf: bytes, filename: str, content_type: str, form: dict) -> requests.Response:
    return requests.post(f"{base}{path}", files={"pdf": (filename, pdf, content_type)}, data=form, timeout=TIMEOUT)


def verify(base: str, pdf: bytes) -> dict:
    r = post(base, "/verify", pdf, "doc.pdf", "application/pdf", {})
    if r.status_code != 200:
        raise AssertionError(f"/verify respondió {r.status_code}: {r.text[:200]}")
    return r.json()


def signatures(report: dict) -> list[dict]:
    return [s for s in report["signatures"] if s["type"] == "Signature"]


def modified(sig: dict) -> bool:
    return sig["modifications"]["level"] not in (None, "NONE", "LTA_UPDATES", "FORM_FILLING")


def check_input(case: dict, base: str, pdf: bytes) -> list[str]:
    """Lo que la verificación tiene que decir del PDF de entrada (casos ya firmados)."""
    exp = case["verify"]
    sigs = signatures(verify(base, pdf))
    errors = []
    if len(sigs) != exp["signatures"]:
        errors.append(f"verify: {len(sigs)} firmas, se esperaban {exp['signatures']}")
    if "intact" in exp and any(s["intact"] != exp["intact"] for s in sigs):
        errors.append(f"verify: intact={[s['intact'] for s in sigs]}, se esperaba {exp['intact']}")
    if "trusted" in exp and any(s["trusted"] != exp["trusted"] for s in sigs):
        errors.append(f"verify: trusted={[s['trusted'] for s in sigs]}, se esperaba {exp['trusted']}")
    if exp.get("modified") and not any(modified(s) or not s["bottom_line"] for s in sigs):
        errors.append("verify: no informa la modificación posterior a la firma")
    return errors


def check_signed(case: dict, base: str, signed: bytes, before: list[dict], response: requests.Response) -> list[str]:
    errors = []
    disposition = response.headers.get("content-disposition", "")
    if not disposition.lower().rstrip('"').endswith(".pdf") or ".pdf-" in disposition.lower():
        errors.append(f"nombre de descarga raro: {disposition!r}")
    sigs = signatures(verify(base, signed))
    if len(sigs) != len(before) + 1:
        errors.append(f"el PDF firmado tiene {len(sigs)} firmas, se esperaban {len(before) + 1}")
    broken_before = {s["field"] for s in before if not s["intact"]}
    for s in sigs:
        if not s["intact"] and s["field"] not in broken_before:
            errors.append(f"firma {s['field']} no íntegra en el PDF firmado")
    previously_modified = {s["field"] for s in before if modified(s)}
    for s in sigs[:-1]:
        if s["field"] not in previously_modified and modified(s):
            errors.append(f"la firma nueva modificó lo cubierto por {s['field']}: {s['modifications']}")
    return errors


def run_case(case: dict, base: str, suite: Path, out: Path) -> tuple[str, str, float]:
    upload = case.get("upload") or {}
    pdf = (suite / case["file"]).read_bytes()
    filename = upload.get("filename", Path(case["file"]).name)
    errors: list[str] = []
    before: list[dict] = []
    started = time.monotonic()
    try:
        if case.get("verify"):
            errors += check_input(case, base, pdf)
            before = signatures(verify(base, pdf))
        r = post(base, "/sign", pdf, filename, upload.get("content_type", "application/pdf"), upload.get("form", {}))
    except requests.Timeout:
        return "FALLA", f"timeout ({TIMEOUT} s)", time.monotonic() - started
    except AssertionError as e:
        return "FALLA", str(e), time.monotonic() - started
    elapsed = time.monotonic() - started
    status = r.status_code
    detail = f"HTTP {status}"

    if status >= 500:
        errors.append(f"5xx: {r.text[:200]}")
    elif status == 200:
        if case["sign"] == "reject":
            errors.append("firmó un PDF que tenía que rechazar")
        else:
            (out / f"{case['id']}-firmado.pdf").write_bytes(r.content)
            try:
                errors += check_signed(case, base, r.content, before, r)
            except AssertionError as e:
                errors.append(str(e))
    else:
        message = r.text[:160].replace("\n", " ")
        detail += f": {message}"
        if case["sign"] == "ok":
            errors.append(f"rechazó un PDF que tenía que firmar ({message})")
    return ("FALLA" if errors else "ok"), "; ".join(errors) or detail, elapsed


def canary_ok(base: str, suite: Path) -> bool:
    try:
        pdf = (suite / "estructura/E01-base.pdf").read_bytes()
        return post(base, "/sign", pdf, "E01-base.pdf", "application/pdf", {}).status_code == 200
    except requests.RequestException:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Corre la suite de PDFs contra la API.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--suite", type=Path, default=SUITE)
    parser.add_argument("--out", type=Path, default=Path("out/pdf-suite"))
    parser.add_argument("--only", help="ids separados por coma")
    args = parser.parse_args()

    manifest = json.loads((args.suite / "manifest.json").read_text(encoding="utf-8"))
    only = set(args.only.split(",")) if args.only else None
    args.out.mkdir(parents=True, exist_ok=True)

    failures = 0
    for case in manifest["cases"]:
        if only and case["id"] not in only:
            continue
        base = args.base_url.rstrip("/")
        result, detail, elapsed = run_case(case, base, args.suite, args.out)
        # Un error no debe dejar al servicio roto para los pedidos siguientes (estado compartido).
        if "HTTP 200" not in detail and not canary_ok(base, args.suite):
            result = "FALLA"
            detail += "; después de este caso el servicio ya no firma el PDF base (E01)"
        failures += result != "ok"
        print(f"{case['id']:4} {result:5} {elapsed:6.1f}s  {case['title']}\n{'':18}{detail}")
    print(f"\n{failures} caso(s) con fallas")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
