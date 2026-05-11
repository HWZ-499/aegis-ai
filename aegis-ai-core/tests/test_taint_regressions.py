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
