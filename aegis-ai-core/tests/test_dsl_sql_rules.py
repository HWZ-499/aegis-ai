from pathlib import Path

from src.analysis.dsl.dsl_engine import load_rules_from_directory, match_source
from src.analysis.dsl.rule_schema import DslRule

DSL_RULES_DIR = Path("src/analysis/rules/dsl")


def _load_rule(rule_id: str, language: str) -> DslRule:
    rules = [
        rule for rule in load_rules_from_directory(DSL_RULES_DIR) if rule.language == language and rule.id == rule_id
    ]
    assert len(rules) == 1
    return rules[0]


def _javascript_sqli_findings(source: str) -> list[dict]:
    rule = _load_rule("dsl.javascript.sql-injection-concat", "javascript")
    return match_source(rule, source, Path("src/app/db.js"))


def _python_sqli_findings(source: str) -> list[dict]:
    rule = _load_rule("dsl.python.sql-injection-format", "python")
    return match_source(rule, source, Path("src/app/views.py"))


def test_javascript_sql_dsl_skips_safe_query_variable() -> None:
    findings = _javascript_sqli_findings(
        """
function loadUser(db, id) {
    const sql = "SELECT * FROM users WHERE id = ?";
    return db.query(sql);
}
"""
    )

    assert findings == []


def test_javascript_sql_dsl_keeps_direct_string_concat() -> None:
    findings = _javascript_sqli_findings(
        """
function loadUser(db, req) {
    return db.query("SELECT * FROM users WHERE id = " + req.query.id);
}
"""
    )

    assert any(finding.get("type") == "SQL_INJECTION" for finding in findings)


def test_javascript_sql_dsl_keeps_direct_user_source_query() -> None:
    findings = _javascript_sqli_findings(
        """
function runReport(db, req) {
    return db.query(req.query.sql);
}
"""
    )

    assert any(finding.get("type") == "SQL_INJECTION" for finding in findings)


def test_python_sql_dsl_matches_percent_format_query_body() -> None:
    findings = _python_sqli_findings(
        """
def load_user(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id=%s" % user_id)
"""
    )

    assert any(finding.get("type") == "SQL_INJECTION" for finding in findings)


def test_python_sql_dsl_matches_f_string_query_body() -> None:
    findings = _python_sqli_findings(
        """
def load_user(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
"""
    )

    assert any(finding.get("type") == "SQL_INJECTION" for finding in findings)
