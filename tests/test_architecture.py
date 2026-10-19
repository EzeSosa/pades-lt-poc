"""Reglas de dependencias entre módulos y de dónde se lee la configuración.

Ver docs/adr/0001-arquitectura-hexagonal.md y docs/arquitectura/README.md. Si falla el de
import-linter, `uv run lint-imports` muestra qué import rompe qué contrato.
"""

import ast
from pathlib import Path

from importlinter.cli import lint_imports

ROOT = Path(__file__).parent.parent
PACKAGE = ROOT / "src" / "pades_lt_poc"


def test_import_contracts():
    """Los contratos de `[tool.importlinter]` en pyproject.toml."""
    assert lint_imports(config_filename=str(ROOT / "pyproject.toml"), no_cache=True, no_logo=True) == 0


def test_only_config_reads_the_environment():
    """Sólo `config.py` lee variables de entorno: ningún otro módulo depende de cómo se lo configura."""
    readers = []
    for path in PACKAGE.rglob("*.py"):
        if path.name == "config.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Attribute) and node.attr in ("environ", "getenv", "environb"):
                readers.append(f"{path.relative_to(PACKAGE)}:{node.lineno}")
    assert readers == []
