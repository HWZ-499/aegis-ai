from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.agent import cli
from src.agent.workflow import AgentDependencyError


def _fake_report(project_path: Path) -> dict[str, Any]:
    return {
        "workflow": {
            "nodes": ["scan", "analyze", "retrieve", "fix", "review", "summarize"],
            "tool_trace": [{"node": "scan", "tool": "scan_project", "status": "ok", "duration_ms": 1.0}],
            "partial": False,
            "error_count": 0,
            "errors": [],
        },
        "summary": {
            "project_path": str(project_path),
            "total_findings": 1,
            "severity_counts": {"Critical": 0, "High": 1, "Medium": 0, "Low": 0},
            "status_counts": {"new": 1},
            "new_findings": 1,
            "accepted_risk_findings": 0,
            "suppressed_by_source_markers": 0,
        },
        "findings": [
            {
                "finding_id": "abc123",
                "file": "app.js",
                "line": 3,
                "rule_id": "SQL_INJECTION",
                "severity": "High",
                "cwe": "CWE-89",
                "cause": "Dynamic SQL",
                "status": "new",
                "knowledge": [{"title": "CWE-89 SQL Injection", "snippet": "Use prepared statements."}],
                "fix": {
                    "fix_suggestion": "Use a prepared statement.",
                    "fixed_code": "db.query(sql, [id]);",
                    "patch_preview": {
                        "status": "preview",
                        "file": "app.js",
                        "start_line": 3,
                        "end_line": 3,
                        "original_code": "bad()",
                        "replacement_code": "safe()",
                        "unified_diff": "--- a/app.js\n+++ b/app.js\n@@ -1 +1 @@\n-bad()\n+safe()\n",
                    },
                },
                "review_note": "Preview and rescan.",
            }
        ],
        "memory": {"baseline_entries": [], "source_suppression_count": 0},
    }


def test_cli_json_report_exits_successfully(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(cli, "run_agent_workflow", lambda project_path, **_kwargs: _fake_report(Path(project_path)))
    output = tmp_path / "report.json"

    code = cli.run(["diagnose", str(tmp_path), "--format", "json", "--output", str(output)])

    assert code == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["summary"]["total_findings"] == 1
    assert data["workflow"]["nodes"][0] == "scan"


def test_cli_tools_json_exports_openai_schemas(capsys: Any) -> None:
    code = cli.run(["tools", "--format", "json"])

    assert code == 0
    data = json.loads(capsys.readouterr().out)
    names = {tool["function"]["name"] for tool in data["tools"]}
    assert "scan_project" in names
    assert "generate_patch_preview" in names
    assert "apply_patch_preview" in names
    assert all(tool["type"] == "function" for tool in data["tools"])


def test_cli_tools_markdown_exports_descriptions(capsys: Any) -> None:
    code = cli.run(["tools", "--format", "markdown"])

    assert code == 0
    out = capsys.readouterr().out
    assert "Aegis Agent Tool Schemas" in out
    assert "`search_vulnerability_knowledge`" in out
    assert "`generate_patch_preview`" in out
    assert "`apply_patch_preview`" in out


def test_cli_workflow_mermaid_exports_graph(capsys: Any) -> None:
    code = cli.run(["workflow", "--format", "mermaid"])

    assert code == 0
    out = capsys.readouterr().out
    assert "flowchart LR" in out
    assert "scan_project" in out
    assert "patch preview" in out


def test_cli_markdown_report_contains_agent_sections(tmp_path: Path, monkeypatch: Any, capsys: Any) -> None:
    monkeypatch.setattr(cli, "run_agent_workflow", lambda project_path, **_kwargs: _fake_report(Path(project_path)))

    code = cli.run(["diagnose", str(tmp_path), "--format", "markdown"])

    assert code == 0
    out = capsys.readouterr().out
    assert "Aegis Agent Diagnosis Report" in out
    assert "Vulnerability List" in out
    assert "SQL_INJECTION" in out
    assert "Use a prepared statement" in out


def test_cli_html_report_contains_agent_sections(tmp_path: Path, monkeypatch: Any, capsys: Any) -> None:
    monkeypatch.setattr(cli, "run_agent_workflow", lambda project_path, **_kwargs: _fake_report(Path(project_path)))

    code = cli.run(["diagnose", str(tmp_path), "--format", "html"])

    assert code == 0
    out = capsys.readouterr().out
    assert "<!DOCTYPE html>" in out
    assert "Aegis Agent Diagnosis Report" in out
    assert "SQL_INJECTION" in out
    assert "Tool Calls" in out
    assert "Finding ID" in out
    assert "aegis-agent apply-fix aegis-agent-report.json --finding-id abc123" in out
    assert "--yes --rescan" in out


def test_cli_missing_langgraph_message(tmp_path: Path, monkeypatch: Any, capsys: Any) -> None:
    def raise_missing(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise AgentDependencyError("LangGraph is required. Install with: pip install -e .[agent]")

    monkeypatch.setattr(cli, "run_agent_workflow", raise_missing)

    code = cli.run(["diagnose", str(tmp_path), "--format", "json"])

    assert code == 2
    assert "pip install -e .[agent]" in capsys.readouterr().err


def _write_apply_report(tmp_path: Path) -> Path:
    (tmp_path / "app.js").write_text("bad()\n", encoding="utf-8")
    report = {
        "summary": {"project_path": str(tmp_path)},
        "findings": [
            {
                "finding_id": "abc123",
                "fix": {
                    "patch_preview": {
                        "status": "preview",
                        "file": "app.js",
                        "start_line": 1,
                        "end_line": 1,
                        "original_code": "bad()",
                        "replacement_code": "safe()",
                        "unified_diff": "--- a/app.js\n+++ b/app.js\n@@ -1 +1 @@\n-bad()\n+safe()\n",
                    }
                },
            }
        ],
    }
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    return report_path


def test_cli_apply_fix_dry_run_does_not_mutate_file(tmp_path: Path, capsys: Any) -> None:
    report_path = _write_apply_report(tmp_path)

    code = cli.run(["apply-fix", str(report_path), "--finding-id", "abc123", "--format", "json"])

    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "dry_run"
    assert data["mutates_files"] is False
    assert (tmp_path / "app.js").read_text(encoding="utf-8") == "bad()\n"


def test_cli_apply_fix_writes_only_with_yes(tmp_path: Path, capsys: Any) -> None:
    report_path = _write_apply_report(tmp_path)

    code = cli.run(["apply-fix", str(report_path), "--finding-id", "abc123", "--yes", "--format", "json"])

    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "applied"
    assert data["mutates_files"] is True
    assert (tmp_path / "app.js").read_text(encoding="utf-8") == "safe()\n"


def test_cli_apply_fix_rescan_flag_is_forwarded(monkeypatch: Any, capsys: Any) -> None:
    captured: dict[str, Any] = {}

    def fake_apply_patch_preview_tool(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {
            "status": "applied",
            "reason": "ok",
            "finding_id": kwargs["finding_id"],
            "mutates_files": True,
            "dry_run": False,
            "rescan": {"status": "passed", "target_finding_present": False},
        }

    monkeypatch.setattr(cli, "apply_patch_preview_tool", fake_apply_patch_preview_tool)

    code = cli.run(["apply-fix", "report.json", "--finding-id", "abc123", "--yes", "--rescan", "--format", "json"])

    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["rescan"]["status"] == "passed"
    assert captured["confirm"] is True
    assert captured["rescan"] is True
