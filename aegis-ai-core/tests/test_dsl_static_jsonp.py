from pathlib import Path

from src.analysis.base import AnalysisContext
from src.analysis.dsl import load_dsl_rules_for_language


def _run_xss_innerhtml_dsl(source: str) -> list[dict]:
    rules = [
        rule for rule in load_dsl_rules_for_language("javascript") if rule.rule_id == "dsl.javascript.xss-innerhtml"
    ]
    assert len(rules) == 1

    context = AnalysisContext(
        file_path=Path("app/csp/source/high.js"),
        language="javascript",
    )
    context.extras["source"] = source
    rules[0].after_file(context)
    return context.findings


def test_dsl_xss_innerhtml_skips_static_jsonp_answer_callback() -> None:
    source = """
function clickButton() {
    var s = document.createElement("script");
    s.src = "source/jsonp.php?callback=solveSum";
    document.body.appendChild(s);
}

function solveSum(obj) {
    if ("answer" in obj) {
        document.getElementById("answer").innerHTML = obj['answer'];
    }
}
"""

    findings = _run_xss_innerhtml_dsl(source)

    assert findings == []


def test_dsl_xss_innerhtml_keeps_generic_callback_object_assignment() -> None:
    source = """
function render(obj) {
    document.getElementById("answer").innerHTML = obj['answer'];
}
"""

    findings = _run_xss_innerhtml_dsl(source)

    assert any(finding.get("type") == "XSS_RISK" for finding in findings)
