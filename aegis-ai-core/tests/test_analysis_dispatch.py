from pathlib import Path

import pytest

import src.analysis.rule_engine as rule_engine
from src.analysis.languages import normalize_analysis_language


@pytest.mark.parametrize(
    ("language", "file_path", "expected"),
    [
        ("py", "app.unknown", "python"),
        ("tsx", "app.unknown", "typescript"),
        ("golang", "app.unknown", "go"),
        (None, "app.cjs", "javascript"),
        ("unknown", "app.php5", "php"),
        (None, "main.hpp", "cpp"),
        ("unknown", "README.md", None),
    ],
)
def test_normalize_analysis_language_uses_alias_then_extension(
    language: str | None,
    file_path: str,
    expected: str | None,
) -> None:
    assert normalize_analysis_language(language, file_path) == expected


def test_analyze_source_dispatches_typescript_with_shared_options(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: dict[str, object] = {}
    rule_dir = tmp_path / "rules"

    def fake_analyze_with(
        language: str,
        code: str,
        file_path: Path | str,
        include_dsl: bool = True,
        extra_rule_dirs: list[Path] | None = None,
        rules_allowed_root: Path | None = None,
        dsl_rule_definitions=None,
    ) -> list[dict]:
        captured.update(
            {
                "code": code,
                "file_path": str(file_path),
                "language": language,
                "include_dsl": include_dsl,
                "extra_rule_dirs": extra_rule_dirs,
                "rules_allowed_root": rules_allowed_root,
                "dsl_rule_definitions": dsl_rule_definitions,
            }
        )
        return [{"type": "TEST"}]

    monkeypatch.setattr(rule_engine, "_analyze_with", fake_analyze_with)

    definitions = {"typescript": ()}
    result = rule_engine.analyze_source(
        "const value: string = input;",
        "app.ts",
        language="tsx",
        include_dsl=False,
        extra_rule_dirs=[rule_dir],
        rules_allowed_root=tmp_path,
        dsl_rule_definitions=definitions,
    )

    assert result == [{"type": "TEST"}]
    assert captured == {
        "code": "const value: string = input;",
        "file_path": "app.ts",
        "language": "typescript",
        "include_dsl": False,
        "extra_rule_dirs": [rule_dir],
        "rules_allowed_root": tmp_path,
        "dsl_rule_definitions": definitions,
    }


def test_analyze_source_returns_empty_for_unknown_language() -> None:
    assert rule_engine.analyze_source("text", "README.md", language="unknown") == []


def test_analyze_source_does_not_delegate_to_language_compat_helpers() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    source = (repo_root / "src/analysis/rule_engine.py").read_text(encoding="utf-8")
    function_source = source.split("def analyze_source(", maxsplit=1)[1].split("__all__ =", maxsplit=1)[0]

    forbidden = (
        "analyze_python(",
        "analyze_javascript(",
        "analyze_php(",
        "analyze_java(",
        "analyze_go(",
    )
    assert "_analyze_with(" in function_source
    assert not any(token in function_source for token in forbidden)


def test_production_callers_use_unified_analysis_entrypoint() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    production_callers = [
        "src/scanner/project_scanner.py",
        "src/scanner/benchmark.py",
        "src/scanner/performance_optimizer.py",
        "src/lsp/server.py",
        "src/worker_daemon.py",
        "src/analysis/taint/cross_file_analyzer.py",
    ]
    specialized_calls = (
        "analyze_python(",
        "analyze_javascript(",
        "analyze_php(",
        "analyze_java(",
        "analyze_go(",
        "analyze_c_cpp(",
    )

    for relative_path in production_callers:
        source = (repo_root / relative_path).read_text(encoding="utf-8")
        assert "analyze_source" in source, f"{relative_path} must use the canonical analysis entrypoint"
        assert not any(call in source for call in specialized_calls), (
            f"{relative_path} reintroduced language-specific production dispatch"
        )


def test_project_scanner_has_no_legacy_engine_dependencies() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    source = (repo_root / "src/scanner/project_scanner.py").read_text(encoding="utf-8")

    forbidden = (
        "analyze_code_ast",
        "scan_code_locally",
        "analyze_code_multi_language",
        "merge_findings",
        'engine == "legacy"',
    )
    assert not any(token in source for token in forbidden)


def test_php_production_entry_has_no_regex_supplement_dependency() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    source = (repo_root / "src/analysis/rule_engine.py").read_text(encoding="utf-8")
    function_source = source.split("def analyze_php(", maxsplit=1)[1].split("def analyze_source(", maxsplit=1)[0]

    assert "scan_code_locally" not in function_source
    assert "PHP-Regex" not in function_source


def test_production_rule_factories_have_no_legacy_regex_rules() -> None:
    repo_root = Path(__file__).resolve().parents[1]

    for language in ("python", "javascript", "typescript", "php", "java", "go"):
        rules = rule_engine.get_default_rules_for_language(language, include_dsl=False)
        assert all(rule.rule_id != "SQL_INJECTION_REGEX" for rule in rules)
        assert all("regex_rule" not in type(rule).__module__ for rule in rules)

    assert not (repo_root / "src/analysis/rules/sql_injection/regex_rule.py").exists()


def test_python_ast_rule_keeps_percent_format_sqli_after_regex_removal() -> None:
    findings = rule_engine.analyze_source(
        """
def load_user(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id=%s" % user_id)
""",
        "app.py",
        language="python",
        include_dsl=False,
    )

    sql_findings = [finding for finding in findings if finding.get("type") == "SQL_INJECTION"]
    assert [(finding.get("rule_id"), finding.get("line")) for finding in sql_findings] == [("SQL_INJECTION_PY_AST", 3)]
