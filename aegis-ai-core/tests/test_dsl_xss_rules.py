from pathlib import Path

from src.analysis.dsl.dsl_engine import load_rules_from_directory, match_source
from src.analysis.dsl.rule_schema import DslRule

DSL_RULES_DIR = Path("src/analysis/rules/dsl")


def _load_javascript_xss_rule(rule_id: str) -> DslRule:
    rules = [
        rule
        for rule in load_rules_from_directory(DSL_RULES_DIR)
        if rule.language == "javascript" and rule.id == rule_id
    ]
    assert len(rules) == 1
    return rules[0]


def _javascript_innerhtml_findings(source: str) -> list[dict]:
    rule = _load_javascript_xss_rule("dsl.javascript.xss-innerhtml")
    return match_source(rule, source, Path("src/app/web.js"))


def _javascript_response_send_findings(source: str) -> list[dict]:
    rule = _load_javascript_xss_rule("dsl.javascript.xss-response-send")
    return match_source(rule, source, Path("src/app/server.js"))


def test_javascript_innerhtml_dsl_skips_untainted_object_property() -> None:
    findings = _javascript_innerhtml_findings(
        """
function solveSum(obj) {
    document.getElementById("answer").innerHTML = obj["answer"];
}
"""
    )

    assert findings == []


def test_javascript_innerhtml_dsl_keeps_direct_request_source() -> None:
    findings = _javascript_innerhtml_findings(
        """
function render(req) {
    document.getElementById("answer").innerHTML = req.query.answer;
}
"""
    )

    assert any(finding.get("type") == "XSS_RISK" for finding in findings)


def test_javascript_response_send_dsl_skips_safe_template_variable() -> None:
    findings = _javascript_response_send_findings(
        """
function showProfile(res, profile) {
    const html = renderProfile(profile);
    res.send(html);
    res.write(html);
}
"""
    )

    assert findings == []


def test_javascript_response_send_dsl_keeps_direct_request_source() -> None:
    findings = _javascript_response_send_findings(
        """
function showProfile(req, res) {
    res.send(req.query.name);
    res.write(request.body.html);
}
"""
    )

    xss_lines = {finding.get("line") for finding in findings if finding.get("type") == "XSS_RISK"}
    assert xss_lines == {3, 4}
