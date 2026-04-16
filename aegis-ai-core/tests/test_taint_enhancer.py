from src.scanner.taint_enhancer import TaintEnhancer


def test_taint_enhancer_without_analyzer_returns_safe_defaults() -> None:
    enhancer = TaintEnhancer(language="javascript")
    enhancer._analyzer = None

    assert enhancer.analyze_code("eval(user_input)", "demo.js") == []
    findings = [{"type": "RCE_COMMAND_EXEC", "line": 1}]
    assert enhancer.enhance_findings(findings, "eval(user_input)", "demo.js") == findings
