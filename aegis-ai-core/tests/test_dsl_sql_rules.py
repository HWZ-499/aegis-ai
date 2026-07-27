import os
from pathlib import Path

from src.analysis.dsl.dsl_engine import (
    _build_regex_from_pattern,
    _load_rules_from_versions,
    load_rules_from_directory,
    match_source,
)
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


def test_dsl_pattern_regex_is_compiled_once_per_match_call_and_cached_across_files() -> None:
    rule = DslRule.model_validate(
        {
            "id": "dsl.python.test-cache",
            "language": "python",
            "severity": "LOW",
            "message": "cache test",
            "vuln_type": "CACHE_TEST",
            "patterns": [{"pattern": "danger($ARG)"}],
        }
    )
    _build_regex_from_pattern.cache_clear()

    first = match_source(rule, "danger(first)\ndanger(second)", Path("src/first.py"))
    second = match_source(rule, "danger(third)\ndanger(fourth)", Path("src/second.py"))
    cache_info = _build_regex_from_pattern.cache_info()

    assert len(first) == 2
    assert len(second) == 2
    assert cache_info.misses == 1
    assert cache_info.hits == 1


def test_dsl_rule_loading_cache_invalidates_on_file_change_and_returns_isolated_models(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_file = rules_dir / "custom.yaml"
    rule_file.write_text(
        """
id: dsl.python.cache-test
language: python
severity: LOW
message: first
vuln_type: CACHE_TEST
patterns:
  - pattern: danger($ARG)
""",
        encoding="utf-8",
    )
    _load_rules_from_versions.cache_clear()

    first = load_rules_from_directory(rules_dir)
    second = load_rules_from_directory(rules_dir)

    assert first[0].message == "first"
    first[0].message = "mutated"
    assert second[0].message == "first"
    assert _load_rules_from_versions.cache_info().hits == 1

    old_stat = rule_file.stat()
    rule_file.write_text(
        rule_file.read_text(encoding="utf-8").replace("message: first", "message: later"), encoding="utf-8"
    )
    os.utime(
        rule_file,
        ns=(old_stat.st_atime_ns, max(rule_file.stat().st_mtime_ns, old_stat.st_mtime_ns + 1)),
    )

    changed = load_rules_from_directory(rules_dir)

    assert changed[0].message == "later"
    assert _load_rules_from_versions.cache_info().misses == 2
