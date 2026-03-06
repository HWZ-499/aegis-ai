"""
test_performance_benchmark.py

基于 pytest-benchmark 的简单性能基准：
- 度量单文件扫描（Python/JavaScript/PHP/Java/Go）在空规则缓存下的耗时；
- 为后续规则 DSL 评估提供 baseline，对比 DSL 版规则的性能开销。
"""

from __future__ import annotations

from pathlib import Path

from src.analysis.rule_engine import (
    analyze_python,
    analyze_javascript,
    analyze_php,
    analyze_java,
    analyze_go,
)


FIXTURE_DIR = Path(__file__).parent / "rules"


def _load_sample(relative: str) -> tuple[str, str]:
    path = FIXTURE_DIR / relative
    code = path.read_text(encoding="utf-8")
    return code, str(path)


def test_benchmark_python_single_file(benchmark) -> None:
    """基准：Python 单文件扫描性能。"""
    code, path = _load_sample("deserialization/true_positive/tp_pickle_loads.py")

    def run() -> None:
        findings = analyze_python(code, path)
        assert isinstance(findings, list)

    benchmark(run)


def test_benchmark_javascript_single_file(benchmark) -> None:
    """基准：JavaScript 单文件扫描性能。"""
    code, path = _load_sample("xss/true_positive/tp_innerhtml_userinput.js")

    def run() -> None:
        findings = analyze_javascript(code, path)
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
    """基准：Java 单文件扫描性能。"""
    code, path = _load_sample("sql_injection/true_positive/tp_java_statement_concat.java")

    def run() -> None:
        findings = analyze_java(code, path)
        assert isinstance(findings, list)

    benchmark(run)


def test_benchmark_go_single_file(benchmark) -> None:
    """基准：Go 单文件扫描性能。"""
    code, path = _load_sample("rce/true_positive/tp_go_exec_command_user_input.go")

    def run() -> None:
        findings = analyze_go(code, path)
        assert isinstance(findings, list)

    benchmark(run)

