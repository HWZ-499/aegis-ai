"""
test_performance_benchmark.py

基于 pytest-benchmark 的简单性能基准：
- 度量单文件扫描（Python/JavaScript/PHP/Java/Go）在空规则缓存下的耗时；
- 为后续规则 DSL 评估提供 baseline，对比 DSL 版规则的性能开销。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.analysis.analyzers.go_analyzer import GoAnalyzer
from src.analysis.analyzers.javascript_analyzer import JavaScriptAnalyzer
from src.analysis.analyzers.python_analyzer import PythonAnalyzer
from src.analysis.rule_engine import (
    analyze_go,
    analyze_java,
    analyze_javascript,
    analyze_php,
    analyze_python,
)
from src.analysis.rules import (
    GoDeserializationAstRule,
    GoRCEAstRule,
    JavaScriptDeserializationAstRule,
    JavaScriptRCEAstRule,
    PythonDeserializationAstRule,
    PythonRCEAstRule,
)

FIXTURE_DIR = Path(__file__).parent / "rules"
pytestmark = pytest.mark.benchmark


def _load_sample(relative: str) -> tuple[str, str]:
    path = FIXTURE_DIR / relative
    code = path.read_text(encoding="utf-8")
    return code, str(path)


def test_benchmark_python_single_file_with_dsl(benchmark) -> None:
    """基准：Python 单文件扫描性能（AST + DSL 规则，使用 analyze_python）。"""
    code, path = _load_sample("deserialization/true_positive/tp_pickle_loads.py")

    def run() -> None:
        findings = analyze_python(code, path)
        assert isinstance(findings, list)

    benchmark(run)


def test_benchmark_python_single_file_ast_only(benchmark) -> None:
    """基准：Python 单文件扫描性能（仅 AST 规则）。"""
    code, raw_path = _load_sample("deserialization/true_positive/tp_pickle_loads.py")
    path = Path(raw_path)
    rules = [PythonRCEAstRule(), PythonDeserializationAstRule()]
    analyzer = PythonAnalyzer(rules)

    def run() -> None:
        findings = analyzer.analyze(code, path)
        assert isinstance(findings, list)

    benchmark(run)


def test_benchmark_javascript_single_file_with_dsl(benchmark) -> None:
    """基准：JavaScript 单文件扫描性能（AST + DSL 规则，使用 analyze_javascript）。"""
    code, path = _load_sample("xss/true_positive/tp_innerhtml_userinput.js")

    def run() -> None:
        findings = analyze_javascript(code, path)
        assert isinstance(findings, list)

    benchmark(run)


def test_benchmark_javascript_single_file_ast_only(benchmark) -> None:
    """基准：JavaScript 单文件扫描性能（仅 AST 规则）。"""
    code, raw_path = _load_sample("xss/true_positive/tp_innerhtml_userinput.js")
    path = Path(raw_path)
    rules = [JavaScriptRCEAstRule(), JavaScriptDeserializationAstRule()]
    analyzer = JavaScriptAnalyzer(rules)

    def run() -> None:
        findings = analyzer.analyze(code, path)
        assert isinstance(findings, list)

    benchmark(run)


def test_benchmark_php_single_file(benchmark) -> None:
    """基准：PHP 单文件扫描性能。"""
    code, path = _load_sample("deserialization/true_positive/tp_unserialize_get.php")

    def run() -> None:
        findings = analyze_php(code, path)
        assert isinstance(findings, list)

    benchmark(run)


def test_benchmark_java_single_file(benchmark) -> None:
    """基准：Java 单文件扫描性能（保持 AST 规则集合不变）。"""
    code, path = _load_sample("sql_injection/true_positive/tp_java_statement_concat.java")

    def run() -> None:
        findings = analyze_java(code, path)
        assert isinstance(findings, list)

    benchmark(run)


def test_benchmark_go_single_file_with_dsl(benchmark) -> None:
    """基准：Go 单文件扫描性能（AST + DSL 规则，使用 analyze_go）。"""
    code, path = _load_sample("rce/true_positive/tp_go_exec_command_user_input.go")

    def run() -> None:
        findings = analyze_go(code, path)
        assert isinstance(findings, list)

    benchmark(run)


def test_benchmark_go_single_file_ast_only(benchmark) -> None:
    """基准：Go 单文件扫描性能（仅 AST 规则）。"""
    code, raw_path = _load_sample("rce/true_positive/tp_go_exec_command_user_input.go")
    path = Path(raw_path)
    rules = [GoRCEAstRule(), GoDeserializationAstRule()]
    analyzer = GoAnalyzer(rules)

    def run() -> None:
        findings = analyzer.analyze(code, path)
        assert isinstance(findings, list)

    benchmark(run)
