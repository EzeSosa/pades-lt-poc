"""La documentación de arquitectura no cita cosas que no existen."""

import ast
import fnmatch
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
TESTS = Path(__file__).parent
ARCH = ROOT / "docs" / "arquitectura"


def _test_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test")}


def test_cited_tests_exist():
    """Cada `archivo.py::test_x` (o `test_x_*`) citado en docs/arquitectura existe en tests/."""
    missing = []
    for doc in ARCH.glob("*.md"):
        for file, name in re.findall(r"`?(test_\w+\.py)::(test\w*\*?)`?", doc.read_text(encoding="utf-8")):
            path = TESTS / file
            if not path.exists() or not fnmatch.filter(_test_names(path), name):
                missing.append(f"{doc.name}: {file}::{name}")
    assert missing == []


def test_cited_goldens_exist():
    """Cada golden citado (`golden \\`nombre\\``) existe en tests/golden/."""
    missing = []
    for doc in ARCH.glob("*.md"):
        for names in re.findall(r"goldens? ((?:`[\w*]+`(?:, )?)+)", doc.read_text(encoding="utf-8")):
            for name in re.findall(r"`([\w*]+)`", names):
                if not list((TESTS / "golden").glob(f"{name}.json")):
                    missing.append(f"{doc.name}: {name}")
    assert missing == []
