from importlib import import_module
from pathlib import Path
from typing import Any

import tomllib


def _load_pytest_config() -> dict[str, Any]:
    pyproject_path = Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    return data["tool"]["pytest"]["ini_options"]


def _marker_names(pytestmark: Any) -> set[str]:
    if isinstance(pytestmark, list):
        markers = pytestmark
    else:
        markers = [pytestmark]
    return {marker.name for marker in markers if getattr(marker, "name", None)}


def test_default_pytest_addopts_skip_heavy_markers() -> None:
    addopts = _load_pytest_config()["addopts"]

    assert "not benchmark" in addopts
    assert "not acceptance" in addopts
    assert "not integration" in addopts


def test_acceptance_benchmark_module_is_marked_acceptance() -> None:
    module = import_module("tests.test_acceptance_benchmark")

    assert "acceptance" in _marker_names(module.pytestmark)


def test_performance_benchmark_module_is_marked_benchmark() -> None:
    module = import_module("tests.test_performance_benchmark")

    assert "benchmark" in _marker_names(module.pytestmark)


def test_lsp_end_to_end_modules_are_marked_integration() -> None:
    e2e_module = import_module("tests.test_lsp_e2e")
    integration_module = import_module("tests.test_lsp_integration")

    assert "integration" in _marker_names(e2e_module.pytestmark)
    assert "integration" in _marker_names(integration_module.pytestmark)
