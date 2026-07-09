import json
from pathlib import Path

import pytest

from src.scanner.cli import main


@pytest.mark.parametrize(
    ("report_format", "suffix"),
    [
        ("json", ".json"),
        ("html", ".html"),
        ("markdown", ".md"),
        ("sarif", ".sarif"),
    ],
)
def test_cli_generates_each_report_format(
    tmp_path: Path,
    report_format: str,
    suffix: str,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "safe.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    output = tmp_path / f"report{suffix}"

    with pytest.raises(SystemExit) as exit_info:
        main(
            [
                str(project),
                "--format",
                report_format,
                "--output",
                str(output),
                "--no-cache",
                "--no-parallel",
                "--no-fail-on-findings",
            ]
        )

    assert exit_info.value.code == 0
    assert output.is_file()
    report = output.read_text(encoding="utf-8")
    assert report.strip()

    if report_format == "json":
        data = json.loads(report)
        assert data["project_name"] == "project"
        assert data["summary"]["partial"] is False
    elif report_format == "sarif":
        data = json.loads(report)
        assert data["version"] == "2.1.0"
        assert data["runs"][0]["invocations"][0]["executionSuccessful"] is True
    elif report_format == "html":
        assert "<!DOCTYPE html>" in report
        assert "project" in report
    else:
        assert "安全扫描报告" in report
        assert "project" in report
