from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from src.agent import workflow
from src.agent.tools import apply_patch_preview_tool


def _write_vulnerable_project(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "\n".join(
            [
                "function handler(req, db) {",
                "  const id = req.query.id;",
                '  db.query("SELECT * FROM users WHERE id = " + id);',
                "}",
            ]
        ),
        encoding="utf-8",
    )


def _write_agent_demo_project(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "\n".join(
            [
                'const express = require("express");',
                "",
                "const app = express();",
                "",
                'app.get("/users/:id", async (req, res) => {',
                "  const id = req.params.id;",
                '  const sql = "SELECT * FROM users WHERE id = " + id;',
                "  const rows = await req.db.query(sql);",
                "  res.json(rows);",
                "});",
                "",
                'app.get("/profile", (req, res) => {',
                '  res.send("<h1>Welcome " + req.query.name + "</h1>");',
                "});",
                "",
                'app.get("/proxy", async (req, res) => {',
                "  const target = req.query.url;",
                "  const response = await fetch(target);",
                "  res.send(await response.text());",
                "});",
                "",
                "module.exports = app;",
            ]
        ),
        encoding="utf-8",
    )


def test_missing_langgraph_has_clear_install_message(monkeypatch: Any) -> None:
    def fail_load() -> tuple[Any, Any, Any]:
        raise workflow.AgentDependencyError("LangGraph is required. Install with: pip install -e .[agent]")

    monkeypatch.setattr(workflow, "_load_langgraph", fail_load)

    with pytest.raises(workflow.AgentDependencyError) as exc_info:
        workflow.build_agent_graph()

    assert "pip install -e .[agent]" in str(exc_info.value)


@pytest.mark.skipif(importlib.util.find_spec("langgraph") is None, reason="LangGraph optional dependency not installed")
def test_langgraph_workflow_runs_expected_nodes_and_fake_ai(tmp_path: Path) -> None:
    _write_vulnerable_project(tmp_path)

    class FakeAIResult:
        is_true_positive = True
        confidence = 0.91
        risk_level = "High"
        explanation = "test"
        fix_suggestion = "Use a bound parameter."
        requires_review = False
        fixed_code = 'db.query("SELECT * FROM users WHERE id = ?", [id]);'
        fix_start_line = 3
        fix_end_line = 3
        error_code = None
        error_message = None

    class FakeAIAnalyzer:
        enabled = True

        def analyze_finding(self, *_args: Any, **_kwargs: Any) -> FakeAIResult:
            return FakeAIResult()

    report = workflow.run_agent_workflow(
        str(tmp_path),
        use_ai=True,
        no_cache=True,
        no_parallel=True,
        ai_analyzer=FakeAIAnalyzer(),  # type: ignore[arg-type]
    )

    assert report["workflow"]["nodes"] == ["scan", "analyze", "triage", "retrieve", "fix", "review", "summarize"]
    assert report["summary"]["total_findings"] >= 1
    assert report["summary"]["raw_findings"] >= report["summary"]["grouped_findings"]
    assert report["findings"][0]["fix"]["mode"] == "ai"
    assert "?" in report["findings"][0]["fix"]["fixed_code"]
    assert report["findings"][0]["fix"]["patch_preview"]["status"] == "preview"
    assert "generate_patch_preview" in {event["tool"] for event in report["workflow"]["tool_trace"]}


@pytest.mark.skipif(importlib.util.find_spec("langgraph") is None, reason="LangGraph optional dependency not installed")
def test_agent_e2e_groups_demo_and_applies_verified_sql_fix(tmp_path: Path) -> None:
    _write_agent_demo_project(tmp_path)

    report = workflow.run_agent_workflow(str(tmp_path), no_cache=True, no_parallel=True)

    assert report["summary"]["raw_findings"] >= 3
    assert report["summary"]["grouped_findings"] == 3
    assert report["summary"]["duplicates_collapsed"] == (
        report["summary"]["raw_findings"] - report["summary"]["grouped_findings"]
    )
    families = {finding["rule_family"] for finding in report["findings"]}
    assert families == {"SQL_INJECTION", "XSS", "SSRF"}
    assert "bypassSecurityTrustHtml" not in json.dumps(report)

    sql_finding = next(finding for finding in report["findings"] if finding["rule_family"] == "SQL_INJECTION")
    assert sql_finding["fix"]["kind"] == "applicable_preview"
    ssrf_finding = next(finding for finding in report["findings"] if finding["rule_family"] == "SSRF")
    assert ssrf_finding["fix"]["kind"] == "guidance_only"
    assert ssrf_finding["fix"]["patch_preview"]["kind"] == "guidance_only"
    assert "ALLOWED_HOSTS" in ssrf_finding["fix"]["guidance_code"]
    report_path = tmp_path / "agent-report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    dry_run = apply_patch_preview_tool(str(report_path), sql_finding["finding_id"])
    assert dry_run["status"] == "dry_run"
    assert "WHERE id = ?" not in (tmp_path / "app.js").read_text(encoding="utf-8")

    applied = apply_patch_preview_tool(str(report_path), sql_finding["finding_id"], confirm=True, rescan=True)
    assert applied["status"] == "applied"
    assert applied["rescan"]["status"] == "passed"
    assert applied["rescan"]["target_finding_present"] is False
    assert "WHERE id = ?" in (tmp_path / "app.js").read_text(encoding="utf-8")


@pytest.mark.skipif(importlib.util.find_spec("langgraph") is None, reason="LangGraph optional dependency not installed")
def test_agent_workflow_routes_partial_scan_to_summary_without_fixes(tmp_path: Path, monkeypatch: Any) -> None:
    _write_vulnerable_project(tmp_path)

    def fake_scan_project_tool(**_kwargs: Any) -> dict[str, Any]:
        return {
            "findings": [{"file": "app.js", "line": 1, "type": "SQL_INJECTION", "details": "partial"}],
            "stats": {"partial": True, "error_count": 1, "errors": [{"file": "app.js", "message": "parse failed"}]},
        }

    monkeypatch.setattr(workflow, "scan_project_tool", fake_scan_project_tool)

    report = workflow.run_agent_workflow(str(tmp_path), no_cache=True, no_parallel=True)

    assert report["workflow"]["triage_plan"]["mode"] == "scan_error"
    assert report["summary"]["total_findings"] == 1
    assert report["findings"][0]["diagnosis_status"] == "unverified_partial_scan"
    assert "partial scan" in report["findings"][0]["review_note"].lower()
    assert "generate_fix_suggestion" not in {event["tool"] for event in report["workflow"]["tool_trace"]}
