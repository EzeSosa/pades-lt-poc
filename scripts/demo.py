"""
Cliente de demo: genera un PDF mínimo, lo firma vía /sign y lo valida vía /verify.
Uso (con el server levantado):  uv run python scripts/demo.py [--lta]
"""

import json
import sys
from pathlib import Path

import requests

BASE = "http://127.0.0.1:8000"
OUT = Path("out")


def minimal_pdf(text: str) -> bytes:
    stream = f"BT /F1 24 Tf 72 720 Td ({text}) Tj ET".encode()
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, obj in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + obj + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)


def main() -> None:
    lta = "--lta" in sys.argv
    OUT.mkdir(exist_ok=True)
    src = OUT / "documento.pdf"
    src.write_bytes(minimal_pdf("Hola PAdES B-LT"))

    r = requests.post(
        f"{BASE}/sign",
        files={"pdf": (src.name, src.read_bytes(), "application/pdf")},
        data={"reason": "Prueba de concepto", "lta": str(lta).lower()},
        timeout=60,
    )
    r.raise_for_status()
    signed = OUT / ("documento-pades-lta.pdf" if lta else "documento-pades-lt.pdf")
    signed.write_bytes(r.content)
    print(f"Firmado -> {signed} ({len(r.content)} bytes)")

    (OUT / "root.crt.pem").write_bytes(requests.get(f"{BASE}/pki/root.crt", timeout=10).content)

    r = requests.post(
        f"{BASE}/verify",
        files={"pdf": (signed.name, signed.read_bytes(), "application/pdf")},
        timeout=60,
    )
    r.raise_for_status()
    report = r.json()
    for s in report["signatures"]:
        s.pop("details", None)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
