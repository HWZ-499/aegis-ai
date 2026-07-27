from src.analysis.multi_language_ast import MultiLanguageASTAnalyzer


def test_unsupported_language_returns_no_findings() -> None:
    analyzer = MultiLanguageASTAnalyzer()

    findings = analyzer.analyze(
        "eval(params[:code])",
        language="ruby",
        file_path="test.rb",
    )

    assert findings == []


def test_typescript_analysis_uses_canonical_dispatch(monkeypatch) -> None:
    analyzer = MultiLanguageASTAnalyzer()
    calls: list[tuple[str, str, str | None]] = []

    def fake_analyze_source(code: str, file_path: str, language: str | None = None) -> list[dict]:
        calls.append((code, file_path, language))
        return []

    monkeypatch.setattr("src.analysis.multi_language_ast.analyze_source", fake_analyze_source)

    analyzer.analyze(
        "interface User { id: string }\nconst q: string = 'x';\n",
        language="typescript",
        file_path="service.ts",
    )

    assert calls == [("interface User { id: string }\nconst q: string = 'x';\n", "service.ts", "typescript")]
