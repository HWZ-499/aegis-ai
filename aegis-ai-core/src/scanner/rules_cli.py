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
_LANGUAGE_SUFFIXES = {
    "go": ".go",
    "java": ".java",
    "javascript": ".js",
    "php": ".php",
    "python": ".py",
    "typescript": ".ts",
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
        "path", nargs="?", default=_DEFAULT_RULE_PATH, help=f"Output path (default: {_DEFAULT_RULE_PATH})"
    )
    init_parser.add_argument("--force", action="store_true", help="Overwrite an existing rule file.")
    init_parser.add_argument("--language", default="python", help="Rule language (default: python).")
    init_parser.add_argument("--rule-id", default="dsl.custom.example", help="Rule id for the generated skeleton.")
    init_parser.add_argument("--vuln-type", default="CUSTOM", help="Finding type for the generated skeleton.")
    init_parser.add_argument("--severity", default="MEDIUM", help="Severity for the generated skeleton.")

    test_parser = subparsers.add_parser("test", help="Run embedded tests from one rule file or a rule directory.")
    test_parser.add_argument(
        "path", nargs="?", default=".aegis/rules", help="Rule file or directory (default: .aegis/rules)."
    )
    test_parser.add_argument("--quiet", action="store_true", help="Only print failures and the final summary.")

    return parser


def _init_rule(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if path.exists() and not args.force:
        print(f"Rule file already exists: {path}")
        print("Use --force to overwrite it.")
        return 2

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        _rule_template(
            language=args.language,
            rule_id=args.rule_id,
            severity=args.severity,
            vuln_type=args.vuln_type,
        ),
        encoding="utf-8",
    )
    print(f"Created DSL rule skeleton: {path}")
    return 0


def _rule_template(*, language: str, rule_id: str, severity: str, vuln_type: str) -> str:
    return f"""id: {rule_id}
language: {language}
severity: {severity.upper()}
message: "Detected custom risky call."
vuln_type: {vuln_type.upper()}
patterns:
  - pattern: dangerous_call($ARG)
tests:
  - name: detects risky call
    code: |
      dangerous_call(user_input)
    expect_findings: 1
  - name: skips unrelated call
    code: |
      safe_call(user_input)
    expect_findings: 0
"""


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
