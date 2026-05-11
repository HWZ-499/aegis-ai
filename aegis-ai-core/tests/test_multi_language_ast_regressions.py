from typing import Any

from src.analysis.multi_language_ast import MultiLanguageASTAnalyzer


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


def test_unsupported_language_falls_back_to_normalized_regex_findings() -> None:
    analyzer = MultiLanguageASTAnalyzer()

    findings = analyzer.analyze(
        "eval(params[:code])",
        language="ruby",
        file_path="test.rb",
    )

    assert isinstance(findings, list)
    assert findings
    assert isinstance(findings[0], dict)
    assert {"line", "type", "severity", "details", "source"} <= set(findings[0])


def test_typescript_analysis_uses_typescript_parser(monkeypatch) -> None:
    analyzer = MultiLanguageASTAnalyzer()
    calls: list[str] = []
    analyzer.parsers["javascript"] = _FakeParser("javascript", calls)
    analyzer.parsers["typescript"] = _FakeParser("typescript", calls)
    monkeypatch.setattr(analyzer, "_traverse_javascript_tree", lambda _node: [])

    analyzer.analyze(
        "interface User { id: string }\nconst q: string = 'x';\n",
        language="typescript",
        file_path="service.ts",
    )

    assert calls == ["typescript"]
