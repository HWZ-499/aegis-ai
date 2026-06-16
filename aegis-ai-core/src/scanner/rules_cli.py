"""CLI helpers for authoring and testing custom DSL rules."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import pydantic
import yaml

from src.analysis.dsl.dsl_engine import match_source
from src.analysis.dsl.rule_schema import DslRule, DslRuleTestCase

_DEFAULT_RULE_PATH = ".aegis/rules/custom-rule.yaml"
_DEFAULT_TEMPLATE_TYPE = "custom"
_LANGUAGE_SUFFIXES = {
    "go": ".go",
    "java": ".java",
    "javascript": ".js",
    "php": ".php",
    "python": ".py",
    "typescript": ".ts",
}
_TYPE_ALIASES = {
    "command-exec": "rce",
    "command_exec": "rce",
    "custom": "custom",
    "hardcoded-credential": "hardcoded-credentials",
    "hardcoded-credentials": "hardcoded-credentials",
    "path": "path-traversal",
    "path-traversal": "path-traversal",
    "path_traversal": "path-traversal",
    "rce": "rce",
    "secret": "hardcoded-credentials",
    "secrets": "hardcoded-credentials",
    "sql": "sql-injection",
    "sqli": "sql-injection",
    "sql-injection": "sql-injection",
    "sql_injection": "sql-injection",
    "xss": "xss",
}
_TYPE_DEFAULTS = {
    "custom": {
        "slug": "custom",
        "vuln_type": "CUSTOM",
        "severity": "MEDIUM",
        "message": "Detected custom risky call.",
    },
    "hardcoded-credentials": {
        "slug": "hardcoded-credentials",
        "vuln_type": "HARDCODED_CREDENTIALS",
        "severity": "HIGH",
        "message": "Detected a likely hardcoded credential.",
    },
    "path-traversal": {
        "slug": "path-traversal",
        "vuln_type": "PATH_TRAVERSAL",
        "severity": "HIGH",
        "message": "Detected user-controlled path data reaching a file API.",
    },
    "rce": {
        "slug": "rce",
        "vuln_type": "RCE_COMMAND_EXEC",
        "severity": "CRITICAL",
        "message": "Detected user-controlled data reaching a code execution sink.",
    },
    "sql-injection": {
        "slug": "sql-injection",
        "vuln_type": "SQL_INJECTION",
        "severity": "HIGH",
        "message": "Detected SQL string construction with user-controlled data.",
    },
    "xss": {
        "slug": "xss",
        "vuln_type": "XSS_RISK",
        "severity": "HIGH",
        "message": "Detected user-controlled data reaching an HTML output sink.",
    },
}


@dataclass(frozen=True)
class RuleCliResult:
    """Result for one embedded rule test case."""

    path: Path
    rule_id: str
    case_name: str
    expected: int | bool
    actual: int
    passed: bool


def run_rules_command(argv: list[str], *, prog: str = "aegis rules") -> int:
    """Run the `rules` subcommand family.

    Args:
        argv: Arguments after the `rules` token.
        prog: Program label for argparse help text.

    Returns:
        Process exit code.
    """
    parser = _build_parser(prog)
    args = parser.parse_args(argv)
    if args.command == "init":
        return _init_rule(args)
    if args.command == "test":
        return _test_rules(args)
    parser.error("unknown rules command")
    return 2


def _build_parser(prog: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        description="Author and validate Aegis YAML DSL rules.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create a DSL rule skeleton with embedded tests.")
    init_parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help=(f"Output path (default: {_DEFAULT_RULE_PATH}, or .aegis/rules/<lang>.<type>.yaml when --type is set)"),
    )
    init_parser.add_argument("--force", action="store_true", help="Overwrite an existing rule file.")
    init_parser.add_argument(
        "--language",
        "--lang",
        dest="language",
        default="python",
        help="Rule language (default: python).",
    )
    init_parser.add_argument(
        "--type",
        dest="rule_type",
        default=_DEFAULT_TEMPLATE_TYPE,
        help="Template type, such as sqli, xss, rce, path-traversal, hardcoded-credentials, or custom.",
    )
    init_parser.add_argument("--rule-id", default=None, help="Rule id for the generated skeleton.")
    init_parser.add_argument("--vuln-type", default=None, help="Finding type for the generated skeleton.")
    init_parser.add_argument("--severity", default=None, help="Severity for the generated skeleton.")

    test_parser = subparsers.add_parser("test", help="Run embedded tests from one rule file or a rule directory.")
    test_parser.add_argument(
        "path", nargs="?", default=".aegis/rules", help="Rule file or directory (default: .aegis/rules)."
    )
    test_parser.add_argument("--quiet", action="store_true", help="Only print failures and the final summary.")

    return parser


def _init_rule(args: argparse.Namespace) -> int:
    language = str(args.language).lower()
    rule_type = _normalize_rule_type(args.rule_type)
    spec = _template_spec(rule_type)
    path = Path(args.path or _default_rule_path(rule_type, language, spec))
    if path.exists() and not args.force:
        print(f"Rule file already exists: {path}")
        print("Use --force to overwrite it.")
        return 2

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        _rule_template(
            language=language,
            rule_id=args.rule_id or _default_rule_id(rule_type, language, spec),
            severity=(args.severity or spec["severity"]),
            vuln_type=(args.vuln_type or spec["vuln_type"]),
            message=spec["message"],
            rule_type=rule_type,
        ),
        encoding="utf-8",
    )
    print(f"Created DSL rule skeleton: {path}")
    return 0


def _rule_template(
    *,
    language: str,
    rule_id: str,
    severity: str,
    vuln_type: str,
    message: str,
    rule_type: str,
) -> str:
    body = _template_body(rule_type, language)
    return f"""id: {rule_id}
language: {language}
severity: {severity.upper()}
message: "{message}"
vuln_type: {vuln_type.upper()}
{body}
"""


def _normalize_rule_type(raw_type: str) -> str:
    normalized = raw_type.strip().lower().replace("_", "-")
    return _TYPE_ALIASES.get(normalized, normalized)


def _template_spec(rule_type: str) -> dict[str, str]:
    if rule_type in _TYPE_DEFAULTS:
        return _TYPE_DEFAULTS[rule_type]
    slug = rule_type.replace("_", "-")
    return {
        "slug": slug,
        "vuln_type": slug.replace("-", "_").upper(),
        "severity": "MEDIUM",
        "message": f"Detected {slug} pattern.",
    }


def _default_rule_path(rule_type: str, language: str, spec: dict[str, str]) -> str:
    if rule_type == "custom":
        return _DEFAULT_RULE_PATH
    return f".aegis/rules/{language}.{spec['slug']}.yaml"


def _default_rule_id(rule_type: str, language: str, spec: dict[str, str]) -> str:
    if rule_type == "custom":
        return "dsl.custom.example"
    return f"dsl.{language}.{spec['slug']}-custom"


def _template_body(rule_type: str, language: str) -> str:
    if rule_type == "sql-injection":
        return _sql_injection_template(language)
    if rule_type == "xss":
        return _xss_template(language)
    if rule_type == "hardcoded-credentials":
        return _hardcoded_credentials_template(language)
    if rule_type == "rce":
        return _rce_template(language)
    if rule_type == "path-traversal":
        return _path_traversal_template(language)
    return _custom_template()


def _custom_template() -> str:
    return """patterns:
  - pattern: dangerous_call($ARG)
tests:
  - name: detects risky call
    code: |
      dangerous_call(user_input)
    expect_findings: 1
  - name: skips unrelated call
    code: |
      safe_call(user_input)
    expect_findings: 0"""


def _sql_injection_template(language: str) -> str:
    if language in {"javascript", "typescript"}:
        return """patterns:
  - pattern: $DB.query("SELECT" + $EXPR)
  - pattern: $DB.query("SELECT $SQL" + $EXPR)
tests:
  - name: detects SQL concatenation
    code: |
      db.query("SELECT" + req.query.id)
    expect_findings: 1
  - name: skips parameterized SQL
    code: |
      db.query("SELECT * FROM users WHERE id = ?", [req.query.id])
    expect_findings: 0"""
    if language == "go":
        return """patterns:
  - pattern: $DB.Query("SELECT" + $EXPR)
  - pattern: $DB.Exec("DELETE" + $EXPR)
tests:
  - name: detects SQL concatenation
    code: |
      db.Query("SELECT" + userInput)
    expect_findings: 1
  - name: skips parameterized SQL
    code: |
      db.Query("SELECT * FROM users WHERE id = ?", id)
    expect_findings: 0"""
    return """patterns:
  - pattern: $CURSOR.execute("SELECT" % $EXPR)
  - pattern: $CURSOR.execute(f"SELECT {$EXPR}")
tests:
  - name: detects SQL string formatting
    code: |
      cursor.execute("SELECT" % request.args["id"])
    expect_findings: 1
  - name: skips parameterized SQL
    code: |
      cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    expect_findings: 0"""


def _xss_template(language: str) -> str:
    if language in {"javascript", "typescript"}:
        return """patterns:
  - pattern: res.send($EXPR)
    metavariables:
      EXPR:
        regex: '(?i)\\b(?:req|request)\\.(?:query|body|params|cookies|headers)\\b|\\b(?:location\\.(?:search|hash)|document\\.cookie|window\\.name)\\b'
  - pattern: $ELEM.innerHTML = $EXPR
    metavariables:
      EXPR:
        regex: '(?i)\\b(?:req|request)\\.(?:query|body|params|cookies|headers)\\b|\\b(?:location\\.(?:search|hash)|document\\.cookie|window\\.name)\\b'
tests:
  - name: detects user input in HTML output
    code: |
      res.send(req.query.name)
    expect_findings: 1
  - name: skips local HTML output
    code: |
      res.send(profileName)
    expect_findings: 0"""
    return """patterns:
  - pattern: mark_safe($EXPR)
    metavariables:
      EXPR:
        regex: '(?i)\\brequest\\.(?:GET|POST|args|form|json|data)\\b'
tests:
  - name: detects mark_safe request output
    code: |
      mark_safe(request.GET["name"])
    expect_findings: 1
  - name: skips escaped request output
    code: |
      escape(request.GET["name"])
    expect_findings: 0"""


def _hardcoded_credentials_template(language: str) -> str:
    operator = ":=" if language == "go" else "="
    return f"""patterns:
  - pattern: $VAR {operator} "$SECRET"
    metavariables:
      VAR:
        regex: "(?i)(password|passwd|pwd|secret|token|api_?key)"
      SECRET:
        not_regex: "^(changeme|example|sample|test|null|none)$"
tests:
  - name: detects hardcoded credential
    code: |
      password {operator} "S3cr3tValue!"
    expect_findings: 1
  - name: skips placeholder credential
    code: |
      password {operator} "example"
    expect_findings: 0"""


def _rce_template(language: str) -> str:
    source_regex = (
        "'(?i)\\b(?:req|request)\\.(?:query|body|params|cookies|headers)\\b'"
        if language in {"javascript", "typescript"}
        else "'(?i)\\brequest\\.(?:GET|POST|args|form|json|data)\\b'"
    )
    positive = "eval(req.query.cmd)" if language in {"javascript", "typescript"} else 'eval(request.GET["cmd"])'
    negative = 'eval("1 + 1")'
    return f"""patterns:
  - pattern: eval($EXPR)
    metavariables:
      EXPR:
        regex: {source_regex}
tests:
  - name: detects user-controlled eval
    code: |
      {positive}
    expect_findings: 1
  - name: skips static eval
    code: |
      {negative}
    expect_findings: 0"""


def _path_traversal_template(language: str) -> str:
    if language in {"javascript", "typescript"}:
        return """patterns:
  - pattern: fs.readFileSync($PATH)
    metavariables:
      PATH:
        regex: '(?i)\\b(?:req|request)\\.(?:query|body|params)\\b'
tests:
  - name: detects request path read
    code: |
      fs.readFileSync(req.query.path)
    expect_findings: 1
  - name: skips static path read
    code: |
      fs.readFileSync("config.json")
    expect_findings: 0"""
    return """patterns:
  - pattern: open($PATH)
    metavariables:
      PATH:
        regex: '(?i)\\brequest\\.(?:GET|POST|args|form|json|data)\\b'
tests:
  - name: detects request path open
    code: |
      open(request.args["path"])
    expect_findings: 1
  - name: skips static path open
    code: |
      open("config.json")
    expect_findings: 0"""


def _test_rules(args: argparse.Namespace) -> int:
    target = Path(args.path)
    errors: list[str] = []
    results: list[RuleCliResult] = []
    rule_count = 0

    for path in _iter_rule_files(target):
        rule_count += 1
        rule, load_errors = _load_rule_file(path)
        errors.extend(load_errors)
        if rule is None:
            continue
        case_results, case_errors = run_embedded_rule_tests(path, rule)
        results.extend(case_results)
        errors.extend(case_errors)

    if rule_count == 0:
        errors.append(f"No YAML rule files found under {target}.")

    quiet = bool(args.quiet)
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        if quiet and result.passed:
            continue
        print(
            f"{status} {result.path}: {result.rule_id} :: {result.case_name} "
            f"(expected={result.expected}, actual={result.actual})"
        )

    for error in errors:
        print(f"ERROR {error}")

    passed = sum(1 for result in results if result.passed)
    failed = len(results) - passed + len(errors)
    print(f"Rule tests: {passed} passed, {failed} failed, {rule_count} rule file(s)")

    return 0 if failed == 0 else 1


def run_embedded_rule_tests(path: Path, rule: DslRule) -> tuple[list[RuleCliResult], list[str]]:
    """Run all embedded test cases for a validated rule.

    Args:
        path: Rule file path, used for diagnostics.
        rule: Validated DSL rule.

    Returns:
        A tuple of structured test results and diagnostic errors.
    """
    if not rule.tests:
        return [], [f"{path}: rule {rule.id} has no embedded tests."]

    results: list[RuleCliResult] = []
    errors: list[str] = []
    for index, case in enumerate(rule.tests, start=1):
        if not case.code.strip():
            errors.append(f"{path}: rule {rule.id} test #{index} has empty code.")
            continue
        actual = len(match_source(rule, case.code, _case_file_path(rule, case)))
        expected = case.expect_findings
        passed = _expectation_passed(expected, actual)
        results.append(
            RuleCliResult(
                path=path,
                rule_id=rule.id,
                case_name=case.name or f"case {index}",
                expected=expected,
                actual=actual,
                passed=passed,
            )
        )
    return results, errors


def _iter_rule_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target] if target.suffix.lower() in {".yaml", ".yml"} else []
    if not target.exists():
        return []
    return sorted(target.rglob("*.yaml")) + sorted(target.rglob("*.yml"))


def _load_rule_file(path: Path) -> tuple[DslRule | None, list[str]]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        return None, [f"{path}: could not read YAML rule: {exc}"]

    if not isinstance(data, dict):
        return None, [f"{path}: YAML rule must be a mapping/object."]

    try:
        return DslRule.model_validate(data), []
    except pydantic.ValidationError as exc:
        return None, [f"{path}: invalid DSL rule schema: {_format_validation_error(exc)}"]


def _format_validation_error(exc: pydantic.ValidationError) -> str:
    details: list[str] = []
    for error in exc.errors():
        loc = ".".join(str(part) for part in error.get("loc", ())) or "<root>"
        msg = error.get("msg", "invalid value")
        details.append(f"{loc}: {msg}")
    return "; ".join(details)


def _case_file_path(rule: DslRule, case: DslRuleTestCase) -> Path:
    if case.file_path:
        return Path(case.file_path)
    suffix = _LANGUAGE_SUFFIXES.get(rule.language, ".txt")
    return Path(f"inline{suffix}")


def _expectation_passed(expected: int | bool, actual: int) -> bool:
    if isinstance(expected, bool):
        return actual > 0 if expected else actual == 0
    return actual == expected


__all__ = ["RuleCliResult", "run_embedded_rule_tests", "run_rules_command"]
