from __future__ import annotations

from src.scanner.benchmark import run_benchmark
from src.scanner.benchmark_cases import BENCH_CASES_TP


def _tp_case(case_id: str):
    return next(c for c in BENCH_CASES_TP if c.id == case_id)


def test_run_benchmark_dispatches_python_open_redirect_case() -> None:
    """
    TP-REDIR-01 是 Python/Flask 用例，基准引擎应按语言分发到 Python 分析器。
    """
    case = _tp_case("TP-REDIR-01")
    result = run_benchmark([case])
    assert result.tp == 1
    assert result.fn == 0
