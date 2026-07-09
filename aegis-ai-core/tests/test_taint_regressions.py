from pathlib import Path
from typing import Any, cast

import pytest

from src.analysis.taint.cross_file_analyzer import CrossFileAnalyzer
from src.analysis.taint.taint_analyzer import TaintAnalyzer
from src.analysis.taint.taint_graph import TaintPath


class _FakeNode:
    def __init__(self, text: bytes) -> None:
        self.text = text


class _FakeRoot:
    type = "program"
    children: list[Any] = []


class _FakeTree:
    root_node = _FakeRoot()


class _FakeParser:
    def __init__(self, name: str, calls: list[str]) -> None:
        self._name = name
        self._calls = calls

    def parse(self, code: bytes) -> _FakeTree:
        self._calls.append(self._name)
        return _FakeTree()


def test_taint_node_text_helpers_decode_bytes() -> None:
    node = _FakeNode(b"user_input")

    assert CrossFileAnalyzer._get_node_text(node) == "user_input"
    assert TaintAnalyzer._get_node_text(node) == "user_input"


def test_taint_path_allows_empty_endpoints_for_partial_paths() -> None:
    path = TaintPath()

    assert path.source_node is None
    assert path.sink_node is None


def test_cross_file_analyzer_uses_typescript_parser_for_ts_files(tmp_path, monkeypatch) -> None:
    source = tmp_path / "service.ts"
    source.write_text("interface User { id: string }\nexport const q: string = 'x';\n", encoding="utf-8")

    analyzer = CrossFileAnalyzer(tmp_path)
    calls: list[str] = []
    target = cast(Any, analyzer)
    target._js_parser = _FakeParser("javascript", calls)
    target._ts_parser = _FakeParser("typescript", calls)
    monkeypatch.setattr(analyzer, "_traverse_js_ast", lambda _node, _file_path: None)

    analyzer._analyze_js_file(source)

    assert calls == ["typescript"]


def test_cross_file_analyzer_resolves_typescript_import_export_with_types(tmp_path) -> None:
    models = tmp_path / "models.ts"
    models.write_text(
        "export interface User { id: string }\nexport const getUser = (id: string): User => ({ id });\n",
        encoding="utf-8",
    )
    service = tmp_path / "service.ts"
    service.write_text(
        'import { getUser } from "./models";\nconst user: User = getUser("1");\n',
        encoding="utf-8",
    )

    analyzer = CrossFileAnalyzer(tmp_path)
    if cast(Any, analyzer)._ts_parser is None:
        pytest.skip("TypeScript Tree-sitter parser is unavailable")

    analyzer.scan_project()

    model_info = analyzer.get_module_info(str(models))
    service_info = analyzer.get_module_info(str(service))
    assert {"name": "getUser", "type": "VARIABLE", "line": 2} in model_info["exports"]
    assert service_info["imports"][0]["name"] == "getUser"
    assert service_info["imports"][0]["resolved"] == str(models)
    assert str(models) in service_info["dependencies"]


def test_cross_file_analyzer_resolves_python_package_relative_imports(tmp_path) -> None:
    package = tmp_path / "app"
    services = package / "services"
    package.mkdir()
    services.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (services / "__init__.py").write_text("", encoding="utf-8")

    helper = services / "helper.py"
    helper.write_text("def render():\n    return 'ok'\n", encoding="utf-8")
    helpers = services / "helpers.py"
    helpers.write_text("def normalize(value):\n    return value\n", encoding="utf-8")
    models = package / "models.py"
    models.write_text("class User:\n    pass\n", encoding="utf-8")
    handler = services / "handler.py"
    handler.write_text(
        "\n".join(
            [
                "from . import helper",
                "from .helpers import normalize",
                "from ..models import User",
                "",
            ]
        ),
        encoding="utf-8",
    )

    analyzer = CrossFileAnalyzer(tmp_path)
    analyzer.scan_project()

    handler_info = analyzer.get_module_info(str(handler))
    assert str(helper) in handler_info["dependencies"]
    assert str(helpers) in handler_info["dependencies"]
    assert str(models) in handler_info["dependencies"]


def test_cross_file_analyzer_preserves_python_absolute_search_paths(tmp_path) -> None:
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    utils = src_dir / "utils.py"
    utils.write_text("def sanitize(value):\n    return value\n", encoding="utf-8")
    entry = tmp_path / "main.py"
    entry.write_text("import utils\n", encoding="utf-8")

    analyzer = CrossFileAnalyzer(tmp_path)
    analyzer.scan_project()

    entry_info = analyzer.get_module_info(str(entry))
    assert str(utils) in entry_info["dependencies"]


def test_cross_file_analyzer_reuses_project_source_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    js_file = tmp_path / "app.js"
    py_file = tmp_path / "service.py"
    js_source = "export const value = 1;\n"
    py_source = "def public_api():\n    return 1\n"
    js_file.write_text(js_source, encoding="utf-8")
    py_file.write_text(py_source, encoding="utf-8")

    analyzer = CrossFileAnalyzer(
        tmp_path,
        source_snapshot={
            js_file.resolve(): js_source,
            py_file.resolve(): py_source,
        },
    )

    def fail_disk_read(*args, **kwargs):
        raise AssertionError("source snapshot should avoid disk reads")

    monkeypatch.setattr(Path, "read_text", fail_disk_read)

    analyzer.scan_project()

    assert analyzer.get_stats()["files_analyzed"] == 2


def test_cross_file_module_resolution_uses_project_file_index(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    module = package / "module.py"
    importer = tmp_path / "main.py"
    module_source = "value = 1\n"
    importer_source = "from pkg.module import value\n"
    module.write_text(module_source, encoding="utf-8")
    importer.write_text(importer_source, encoding="utf-8")

    analyzer = CrossFileAnalyzer(
        tmp_path,
        source_snapshot={
            module.resolve(): module_source,
            importer.resolve(): importer_source,
        },
    )

    original_exists = Path.exists

    def fail_source_exists(path: Path) -> bool:
        if path.suffix in {".py", ".js", ".jsx", ".ts", ".tsx"}:
            raise AssertionError("module resolution should use the project file index")
        return original_exists(path)

    monkeypatch.setattr(Path, "exists", fail_source_exists)

    analyzer.scan_project()

    importer_info = analyzer.get_module_info(str(importer.resolve()))
    assert importer_info["imports"][0]["resolved"] == str(module.resolve())


def test_cross_file_module_resolution_caches_repeated_imports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = tmp_path / "shared.py"
    module.write_text("value = 1\n", encoding="utf-8")
    analyzer = CrossFileAnalyzer(tmp_path)
    analyzer._project_source_files = {analyzer._path_index_key(module)}

    checks = 0
    original_exists = analyzer._source_file_exists

    def counted_exists(candidate: Path | str) -> bool:
        nonlocal checks
        checks += 1
        return original_exists(candidate)

    monkeypatch.setattr(analyzer, "_source_file_exists", counted_exists)

    first = analyzer._find_module_in_project("shared")
    checks_after_first = checks
    second = analyzer._find_module_in_project("shared")

    assert first == module
    assert second == module
    assert checks_after_first > 0
    assert checks == checks_after_first
