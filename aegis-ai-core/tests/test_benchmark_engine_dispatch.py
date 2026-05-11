from __future__ import annotations

from pathlib import Path

from src.analysis.analyzers.javascript_analyzer import JavaScriptAnalyzer
from src.scanner.benchmark import evaluate_project_against_ground_truth, run_benchmark
from src.scanner.benchmark_cases import BENCH_CASES_TP, BenchCase


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


def test_run_benchmark_dispatches_typescript_case_with_ts_context(monkeypatch) -> None:
    """
    TypeScript benchmark cases must keep TypeScript language and filename context.
    """
    captured: dict[str, object] = {}

    def fake_analyze_javascript(
        code: str,
        file_path: Path | str,
        language: str = "javascript",
        include_dsl: bool = True,
        extra_rule_dirs: list[Path] | None = None,
        rules_allowed_root: Path | None = None,
    ) -> list[dict]:
        captured["code"] = code
        captured["file_path"] = str(file_path)
        captured["language"] = language
        if language == "typescript" and str(file_path).endswith(".ts") and "interface User" in code:
            return [{"type": "SQL_INJECTION"}]
        return []

    import src.analysis.rule_engine as rule_engine_module

    monkeypatch.setattr(rule_engine_module, "analyze_javascript", fake_analyze_javascript)

    case = BenchCase(
        id="TP-TS-SQL-01",
        category="SQL_INJECTION",
        pattern="typescript_sql_concat",
        description="TypeScript syntax with SQL string concatenation",
        code='interface User { id: string }\nconst q: string = "SELECT " + req.query.id;\n',
        expect_finding=True,
        language="typescript",
    )

    result = run_benchmark([case])

    assert result.tp == 1
    assert result.fn == 0
    assert captured["file_path"] == "benchmark.ts"
    assert captured["language"] == "typescript"


def test_javascript_analyzer_uses_typescript_parser_for_typescript() -> None:
    analyzer = JavaScriptAnalyzer([])

    expected_parser = analyzer._ts_parser or analyzer._js_parser
    assert analyzer._parser_for_language("typescript") is expected_parser


def test_phase_metrics_render_summary_prints_language_recall(capsys) -> None:
    from scripts.benchmark.phase_metrics import render_summary

    render_summary({"javascript": {"tp": 1, "fp": 0, "fn": 0, "tn": 1}})
    out = capsys.readouterr().out
    assert "javascript" in out
    assert "recall=100.0%" in out


def test_phase_metrics_collect_from_rule_samples_filters_language() -> None:
    from scripts.benchmark.phase_metrics import collect_from_rule_samples

    result = collect_from_rule_samples(Path("tests/rules"), "javascript")
    assert set(result.keys()) == {"javascript"}


def test_evaluate_project_against_ground_truth_disables_cache(monkeypatch, tmp_path: Path) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    captured: dict[str, bool] = {}

    class FakeScanner:
        def __init__(
            self,
            project_path: str,
            ignore_patterns=None,
            use_cache: bool = True,
            use_parallel: bool = True,
            max_workers=None,
            engine: str = "new",
            extra_rule_dirs=None,
        ) -> None:
            captured["use_cache"] = use_cache

        def scan_project(self, verbose: bool = False):
            return {}

    import src.scanner.project_scanner as project_scanner_module

    monkeypatch.setattr(project_scanner_module, "ProjectScanner", FakeScanner)

    evaluate_project_against_ground_truth(project_dir, [], engine="new")

    assert captured["use_cache"] is False


def test_evaluate_project_matches_line_candidates(monkeypatch, tmp_path: Path) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    class FakeScanner:
        def __init__(
            self,
            project_path: str,
            ignore_patterns=None,
            use_cache: bool = True,
            use_parallel: bool = True,
            max_workers=None,
            engine: str = "new",
            extra_rule_dirs=None,
        ) -> None:
            pass

        def scan_project(self, verbose: bool = False):
            return {
                "vulnerabilities/sqli/source/low.php": [
                    {"type": "XSS_RISK", "line": 20},
                ]
            }

    import src.scanner.project_scanner as project_scanner_module

    monkeypatch.setattr(project_scanner_module, "ProjectScanner", FakeScanner)

    ground_truth = [
        {
            "file": "vulnerabilities/sqli/source/low.php",
            "line": 32,
            "line_candidates": [20, 47],
            "type": "XSS_RISK",
            "is_true_positive": True,
        }
    ]

    result = evaluate_project_against_ground_truth(project_dir, ground_truth, engine="new")
    assert result.tp == 1
    assert result.fn == 0
