from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Any

import pytest

from src.analysis.analyzers.go_analyzer import GoAnalyzer
from src.analysis.analyzers.java_analyzer import JavaAnalyzer
from src.analysis.analyzers.javascript_analyzer import JavaScriptAnalyzer
from src.analysis.analyzers.php_analyzer import PhpAnalyzer
from src.analysis.analyzers.python_analyzer import PythonAnalyzer
from src.analysis.base import AnalysisContext, SecurityRule


class _FakeRoot:
    children: list[Any] = []
    type = "program"


class _FakeTree:
    root_node = _FakeRoot()


class _FailingParser:
    def parse(self, code: bytes) -> _FakeTree:
        raise RuntimeError("parser failed")


class _WorkingParser:
    def parse(self, code: bytes) -> _FakeTree:
        return _FakeTree()


class _AfterFileRule(SecurityRule):
    def __init__(self) -> None:
        super().__init__("AFTER_FILE_TEST", "Low")

    def visit(self, node: Any, context: AnalysisContext) -> None:
        return

    def after_file(self, context: AnalysisContext) -> None:
        context.add_finding(
            {
                "type": "TEST",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": 1,
                "details": "after_file still executed",
            }
        )


class _FailingVisitRule(SecurityRule):
    def __init__(self) -> None:
        super().__init__("FAILING_VISIT", "Low")

    def visit(self, node: Any, context: AnalysisContext) -> None:
        raise RuntimeError("traversal failed")


class _FailingTaintAnalyzer:
    def __init__(self, language: str, initialize_parser: bool = True) -> None:
        return

    def analyze_tree(self, root: object, file_path: str, code: str) -> None:
        raise RuntimeError("taint failed")

    def get_graph(self) -> object:
        return object()


class _WorkingTaintAnalyzer:
    def __init__(self, language: str, initialize_parser: bool = True) -> None:
        return

    def analyze_tree(self, root: object, file_path: str, code: str) -> None:
        return

    def get_graph(self) -> object:
        return object()


TREE_ANALYZERS = [
    (JavaScriptAnalyzer, "_js_parser", "javascript"),
    (JavaAnalyzer, "_parser", "java"),
    (GoAnalyzer, "_parser", "go"),
    (PhpAnalyzer, "_parser", "php"),
]


def _run_analyzer(analyzer: Any, language: str, source: str = "source") -> list[dict]:
    if isinstance(analyzer, JavaScriptAnalyzer):
        return analyzer.analyze(source, Path("sample.js"), language=language)
    return analyzer.analyze(source, Path(f"sample.{language}"))


@pytest.mark.parametrize(("analyzer_cls", "parser_attr", "language"), TREE_ANALYZERS)
def test_tree_analyzer_parse_degradation_is_logged_and_after_file_runs(
    analyzer_cls: type,
    parser_attr: str,
    language: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    analyzer = analyzer_cls([_AfterFileRule()])
    setattr(analyzer, parser_attr, _FailingParser())

    with caplog.at_level(logging.DEBUG):
        findings = _run_analyzer(analyzer, language)

    assert {finding.get("rule_id") for finding in findings} == {"AFTER_FILE_TEST"}
    assert f"analysis_degraded language={language} stage=parse" in caplog.text
    assert "error=RuntimeError: parser failed" in caplog.text


@pytest.mark.parametrize(("analyzer_cls", "parser_attr", "language"), TREE_ANALYZERS)
def test_tree_analyzer_taint_degradation_is_logged(
    analyzer_cls: type,
    parser_attr: str,
    language: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr("src.analysis.taint.TaintAnalyzer", _FailingTaintAnalyzer)
    analyzer = analyzer_cls([_AfterFileRule()])
    setattr(analyzer, parser_attr, _WorkingParser())

    with caplog.at_level(logging.DEBUG):
        findings = _run_analyzer(analyzer, language)

    assert {finding.get("rule_id") for finding in findings} == {"AFTER_FILE_TEST"}
    assert f"analysis_degraded language={language} stage=taint" in caplog.text
    assert "error=RuntimeError: taint failed" in caplog.text


@pytest.mark.parametrize(("analyzer_cls", "parser_attr", "language"), TREE_ANALYZERS)
def test_tree_analyzer_traversal_degradation_is_logged_and_after_file_runs(
    analyzer_cls: type,
    parser_attr: str,
    language: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr("src.analysis.taint.TaintAnalyzer", _WorkingTaintAnalyzer)
    analyzer = analyzer_cls([_FailingVisitRule(), _AfterFileRule()])
    setattr(analyzer, parser_attr, _WorkingParser())

    with caplog.at_level(logging.DEBUG):
        findings = _run_analyzer(analyzer, language)

    assert {finding.get("rule_id") for finding in findings} == {"AFTER_FILE_TEST"}
    assert f"analysis_degraded language={language} stage=traverse" in caplog.text
    assert "error=RuntimeError: traversal failed" in caplog.text


def test_python_syntax_degradation_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    analyzer = PythonAnalyzer([_AfterFileRule()])

    with caplog.at_level(logging.DEBUG):
        findings = analyzer.analyze("def broken(:\n", Path("broken.py"))

    assert findings == []
    assert "analysis_degraded language=python stage=parse" in caplog.text
    assert "error=SyntaxError" in caplog.text


def test_language_analyzers_do_not_reintroduce_silent_exception_passes() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    analyzer_files = [
        "python_analyzer.py",
        "javascript_analyzer.py",
        "php_analyzer.py",
        "java_analyzer.py",
        "go_analyzer.py",
    ]

    for filename in analyzer_files:
        source = (repo_root / "src/analysis/analyzers" / filename).read_text(encoding="utf-8")
        tree = ast.parse(source)
        silent_handlers = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ExceptHandler) and any(isinstance(statement, ast.Pass) for statement in node.body)
        ]
        assert silent_handlers == [], f"{filename} contains a silent exception handler"
        assert "log_analysis_degradation" in source
