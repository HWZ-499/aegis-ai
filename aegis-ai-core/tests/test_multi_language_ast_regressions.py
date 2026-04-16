from src.analysis.multi_language_ast import MultiLanguageASTAnalyzer


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
