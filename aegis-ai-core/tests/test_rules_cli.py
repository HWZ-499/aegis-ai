from pathlib import Path

import pytest

from src.analysis.dsl.rule_schema import DslRule
from src.scanner.rules_cli import run_embedded_rule_tests, run_rules_command


def test_rules_init_writes_skeleton_with_embedded_tests(tmp_path: Path, capsys) -> None:
    rule_path = tmp_path / "rules" / "custom.yaml"

    exit_code = run_rules_command(["init", str(rule_path)])

    assert exit_code == 0
    text = rule_path.read_text(encoding="utf-8")
    assert "id: dsl.custom.example" in text
    assert "tests:" in text
    assert "expect_findings: 1" in text
    assert "Created DSL rule skeleton" in capsys.readouterr().out


def test_rules_init_type_lang_writes_testable_template(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)

    exit_code = run_rules_command(["init", "--type", "sqli", "--lang", "python"])

    rule_path = tmp_path / ".aegis" / "rules" / "python.sql-injection.yaml"
    assert exit_code == 0
    assert rule_path.exists()
    text = rule_path.read_text(encoding="utf-8")
    assert "id: dsl.python.sql-injection-custom" in text
    assert "vuln_type: SQL_INJECTION" in text
    assert "Created DSL rule skeleton" in capsys.readouterr().out
    assert run_rules_command(["test", str(rule_path), "--quiet"]) == 0


@pytest.mark.parametrize(
    ("rule_type", "language"),
    [
        ("sqli", "python"),
        ("xss", "python"),
        ("rce", "python"),
        ("path-traversal", "python"),
        ("hardcoded-credentials", "python"),
        ("sqli", "javascript"),
        ("xss", "javascript"),
        ("path-traversal", "javascript"),
    ],
)
def test_rules_init_type_templates_are_self_testing(tmp_path: Path, rule_type: str, language: str) -> None:
    rule_path = tmp_path / f"{language}-{rule_type}.yaml"

    init_exit_code = run_rules_command(["init", str(rule_path), "--type", rule_type, "--lang", language])

    assert init_exit_code == 0
    assert run_rules_command(["test", str(rule_path), "--quiet"]) == 0


def test_rules_init_refuses_overwrite_without_force(tmp_path: Path) -> None:
    rule_path = tmp_path / "custom.yaml"
    rule_path.write_text("existing", encoding="utf-8")

    exit_code = run_rules_command(["init", str(rule_path)])

    assert exit_code == 2
    assert rule_path.read_text(encoding="utf-8") == "existing"


def test_rules_test_runs_embedded_cases(tmp_path: Path, capsys) -> None:
    rule_path = tmp_path / "custom.yaml"
    rule_path.write_text(
        """
id: dsl.test.custom
language: python
severity: MEDIUM
message: "Custom risky call"
vuln_type: CUSTOM
patterns:
  - pattern: dangerous_call($ARG)
tests:
  - name: detects call
    code: |
      dangerous_call(user_input)
    expect_findings: 1
  - name: skips unrelated call
    code: |
      safe_call(user_input)
    expect_findings: 0
""",
        encoding="utf-8",
    )

    exit_code = run_rules_command(["test", str(tmp_path)])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "PASS" in output
    assert "Rule tests: 2 passed, 0 failed, 1 rule file(s)" in output


def test_rules_test_fails_on_mismatch(tmp_path: Path, capsys) -> None:
    rule_path = tmp_path / "custom.yaml"
    rule_path.write_text(
        """
id: dsl.test.custom
language: python
severity: MEDIUM
message: "Custom risky call"
vuln_type: CUSTOM
patterns:
  - pattern: dangerous_call($ARG)
tests:
  - name: expects missing call
    code: |
      safe_call(user_input)
    expect_findings: 1
""",
        encoding="utf-8",
    )

    exit_code = run_rules_command(["test", str(rule_path)])

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "FAIL" in output
    assert "Rule tests: 0 passed, 1 failed, 1 rule file(s)" in output


def test_run_embedded_rule_tests_uses_boolean_expectations(tmp_path: Path) -> None:
    rule = DslRule.model_validate(
        {
            "id": "dsl.test.boolean",
            "language": "python",
            "severity": "LOW",
            "message": "Custom risky call",
            "vuln_type": "CUSTOM",
            "patterns": [{"pattern": "dangerous_call($ARG)"}],
            "tests": [
                {"name": "match expected", "code": "dangerous_call(value)", "expect_findings": True},
                {"name": "no match expected", "code": "safe_call(value)", "expect_findings": False},
            ],
        }
    )

    results, errors = run_embedded_rule_tests(tmp_path / "custom.yaml", rule)

    assert errors == []
    assert [result.passed for result in results] == [True, True]


def test_builtin_dsl_rules_have_passing_embedded_tests(capsys) -> None:
    rule_count = len(list(Path("src/analysis/rules/dsl").glob("*.yaml")))

    exit_code = run_rules_command(["test", "src/analysis/rules/dsl", "--quiet"])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert rule_count >= 5
    assert "0 failed" in output
    assert f"{rule_count} rule file(s)" in output
