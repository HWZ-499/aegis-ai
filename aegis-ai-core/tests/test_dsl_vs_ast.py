"""
test_dsl_vs_ast.py

AST 规则 vs DSL 规则 检出率对比（PoC）。

当前仅针对 Hardcoded Credentials（Python/Go）进行基础验证：
- 同一组 TP/FP 样本，AST-only 与 DSL-only 的行为应一致。
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, List

from src.analysis.analyzers.go_analyzer import GoAnalyzer
from src.analysis.analyzers.python_analyzer import PythonAnalyzer
from src.analysis.dsl import load_dsl_rules_for_language
from src.analysis.rules import GoHardcodedCredentialsAstRule, PythonHardcodedCredentialsAstRule


RULES_DIR = Path(__file__).parent / "rules" / "hardcoded_credentials"


def _load_code(rel_path: str) -> tuple[str, Path]:
    path = RULES_DIR / rel_path
    code = path.read_text(encoding="utf-8")
    return code, path


def _run_python_ast_only(path: Path) -> List[dict]:
    code = path.read_text(encoding="utf-8")
    rules = [PythonHardcodedCredentialsAstRule()]
    analyzer = PythonAnalyzer(rules)
    return analyzer.analyze(code, path)


def _run_python_dsl_only(path: Path) -> List[dict]:
    code = path.read_text(encoding="utf-8")
    rules = load_dsl_rules_for_language("python")
    analyzer = PythonAnalyzer(rules)
    return analyzer.analyze(code, path)


def _run_go_ast_only(path: Path) -> List[dict]:
    code = path.read_text(encoding="utf-8")
    rules = [GoHardcodedCredentialsAstRule()]
    analyzer = GoAnalyzer(rules)
    return analyzer.analyze(code, path)


def _run_go_dsl_only(path: Path) -> List[dict]:
    code = path.read_text(encoding="utf-8")
    rules = load_dsl_rules_for_language("go")
    analyzer = GoAnalyzer(rules)
    return analyzer.analyze(code, path)


def _has_hardcoded_credentials(findings: List[dict]) -> bool:
    return any(f.get("type") == "HARDCODED_CREDENTIALS" for f in findings)


def _assert_pair(
    rel_path: str,
    runner_ast: Callable[[Path], List[dict]],
    runner_dsl: Callable[[Path], List[dict]],
    expect_finding: bool,
) -> None:
    path = RULES_DIR / rel_path
    ast_findings = runner_ast(path)
    dsl_findings = runner_dsl(path)

    ast_detected = _has_hardcoded_credentials(ast_findings)
    dsl_detected = _has_hardcoded_credentials(dsl_findings)

    assert ast_detected == expect_finding, (
        f"[AST mismatch] {rel_path} expect={expect_finding}, got={ast_detected}, "
        f"findings={ast_findings}"
    )
    assert dsl_detected == expect_finding, (
        f"[DSL mismatch] {rel_path} expect={expect_finding}, got={dsl_detected}, "
        f"findings={dsl_findings}"
    )


def test_python_hardcoded_credentials_ast_vs_dsl() -> None:
    """Python 硬编码凭证 AST-only 与 DSL-only 结果应一致。"""
    _assert_pair(
        "true_positive/tp_python_password_string.py",
        _run_python_ast_only,
        _run_python_dsl_only,
        True,
    )
    _assert_pair(
        "false_positive/fp_python_env_password.py",
        _run_python_ast_only,
        _run_python_dsl_only,
        False,
    )


def test_go_hardcoded_credentials_ast_vs_dsl() -> None:
    """Go 硬编码凭证 AST-only 与 DSL-only 结果应一致。"""
    _assert_pair(
        "true_positive/tp_go_hardcoded_password.go",
        _run_go_ast_only,
        _run_go_dsl_only,
        True,
    )
    _assert_pair(
        "false_positive/fp_go_config_placeholder.go",
        _run_go_ast_only,
        _run_go_dsl_only,
        False,
    )

