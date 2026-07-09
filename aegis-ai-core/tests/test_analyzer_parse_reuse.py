from pathlib import Path
from typing import Any

import pytest

from src.analysis.analyzers.go_analyzer import GoAnalyzer
from src.analysis.analyzers.java_analyzer import JavaAnalyzer
from src.analysis.analyzers.php_analyzer import PhpAnalyzer


class _FakeRoot:
    children: list[Any] = []


class _FakeTree:
    root_node = _FakeRoot()


class _CountingParser:
    def __init__(self) -> None:
        self.calls = 0

    def parse(self, code: bytes) -> _FakeTree:
        self.calls += 1
        return _FakeTree()


class _FakeTaintAnalyzer:
    initialize_parser_values: list[bool] = []

    def __init__(self, language: str, initialize_parser: bool = True) -> None:
        self.initialize_parser_values.append(initialize_parser)

    def analyze_tree(self, root: object, file_path: str, code: str) -> None:
        return

    def get_graph(self) -> object:
        return object()


@pytest.mark.parametrize("analyzer_cls", [JavaAnalyzer, GoAnalyzer, PhpAnalyzer])
def test_analyzer_reuses_single_parse_for_taint_and_rule_traversal(
    analyzer_cls: type,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parser = _CountingParser()
    analyzer = analyzer_cls([])
    analyzer._parser = parser
    _FakeTaintAnalyzer.initialize_parser_values = []
    monkeypatch.setattr("src.analysis.taint.TaintAnalyzer", _FakeTaintAnalyzer)

    analyzer.analyze("source code", Path("app.source"))

    assert parser.calls == 1
    assert _FakeTaintAnalyzer.initialize_parser_values == [False]
