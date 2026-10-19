"""Reglas de dependencias entre módulos: los contratos de `[tool.importlinter]` en pyproject.toml.

Ver docs/adr/0001-arquitectura-hexagonal.md. Si falla, `uv run lint-imports` muestra qué
import rompe qué contrato.
"""

from pathlib import Path

from importlinter.cli import lint_imports

PYPROJECT = Path(__file__).parent.parent / "pyproject.toml"


def test_import_contracts():
    assert lint_imports(config_filename=str(PYPROJECT), no_cache=True, no_logo=True) == 0
