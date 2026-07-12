"""Integration checks for the maintained analysis, scanner, and report paths."""

from pathlib import Path
from tempfile import TemporaryDirectory

from src.analysis.rule_engine import analyze_source
from src.scanner.project_scanner import ProjectScanner
from src.scanner.report_generator import ReportGenerator

_TESTS = Path(__file__).parent
_PROJECT_ROOT = _TESTS.parent


def _vulnerable_python_findings() -> list[dict]:
    test_file = _TESTS / "test_vulnerable_code.py"
    return analyze_source(test_file.read_text(encoding="utf-8"), test_file, include_dsl=False)


def test_canonical_analyzer_returns_normalized_findings() -> None:
    findings = _vulnerable_python_findings()

    assert findings
    assert all({"line", "type", "severity", "details"} <= finding.keys() for finding in findings)


def test_unknown_language_is_not_sent_to_a_generic_regex_scanner() -> None:
    findings = analyze_source("eval(params[:code])", "sample.rb")

    assert findings == []


def test_project_scanner() -> None:
    scanner = ProjectScanner(str(_PROJECT_ROOT / "src"))
    scanner.scan_project()
    stats = scanner.get_stats()

    assert stats["scanned_files"] > 0


def test_project_scanner_support_level() -> None:
    with TemporaryDirectory() as directory:
        scanner = ProjectScanner(directory)
        assert scanner.get_support_level(".py") == "full"
        assert scanner.get_support_level(".js") == "full"
        assert scanner.get_support_level(".cjs") == "full"
        assert scanner.get_support_level(".java") == "full"
        assert scanner.get_support_level(".php") == "full"
        assert scanner.get_support_level(".go") == "full"
        assert scanner.get_support_level(".rs") is None
        assert scanner.get_support_level(".swift") is None


def test_report_generator_accepts_canonical_findings() -> None:
    findings = _vulnerable_python_findings()
    results = {"test_vulnerable_code.py": findings}
    stats = {
        "total_files": 1,
        "scanned_files": 1,
        "files_with_issues": 1,
        "total_issues": len(findings),
        "scan_time": 0.1,
        "severity_stats": {},
    }
    generator = ReportGenerator("Test Project")

    assert generator.generate_json(results, stats)
    assert generator.generate_markdown(results, stats)
    assert generator.generate_html(results, stats)
    assert generator.generate_sarif(results, stats)
