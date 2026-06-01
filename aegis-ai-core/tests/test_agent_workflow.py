from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

from src.agent import workflow


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

    assert report["workflow"]["nodes"] == ["scan", "analyze", "retrieve", "fix", "review", "summarize"]
    assert report["summary"]["total_findings"] >= 1
    assert report["findings"][0]["fix"]["mode"] == "ai"
    assert "?" in report["findings"][0]["fix"]["fixed_code"]
    assert report["findings"][0]["fix"]["patch_preview"]["status"] == "preview"
    assert "generate_patch_preview" in {event["tool"] for event in report["workflow"]["tool_trace"]}
