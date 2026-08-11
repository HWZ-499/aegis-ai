from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.agent.tools import (
    apply_patch_preview_tool,
    generate_fix_suggestion_tool,
    generate_patch_preview_tool,
    get_tool_schemas,
    group_findings_for_report,
    load_project_memory_tool,
    render_html_report,
    render_markdown_report,
    scan_project_tool,
    search_vulnerability_knowledge_tool,
)
from src.scanner.baseline import Baseline


def _write_vulnerable_project(tmp_path: Path) -> Path:
    app = tmp_path / "app.js"
    app.write_text(
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
    return app


def test_tool_registry_exposes_openai_style_schemas() -> None:
    schemas = get_tool_schemas()
    names = {schema["function"]["name"] for schema in schemas}
    assert {
        "scan_project",
        "get_finding_detail",
        "search_vulnerability_knowledge",
        "generate_fix_suggestion",
        "generate_patch_preview",
        "apply_patch_preview",
        "load_project_memory",
        "summarize_report",
    }.issubset(names)
    assert all(schema["type"] == "function" for schema in schemas)
    assert all(schema["function"]["parameters"]["type"] == "object" for schema in schemas)


def test_group_findings_keeps_nearby_sinks_from_same_detector_separate() -> None:
    findings = [
        {"file": "app.js", "line": 10, "rule_id": "SSRF_JS_AST", "severity": "High"},
        {"file": "app.js", "line": 12, "rule_id": "SSRF_JS_AST", "severity": "High"},
    ]

    grouped, stats = group_findings_for_report(findings)

    assert len(grouped) == 2
    assert stats["duplicates_collapsed"] == 0


def test_group_findings_collapses_nearby_evidence_from_different_detectors() -> None:
    findings = [
        {"file": "app.js", "line": 10, "rule_id": "SSRF_JS_AST", "severity": "High"},
        {"file": "app.js", "line": 12, "rule_id": "dsl.javascript.ssrf-fetch", "severity": "Medium"},
    ]

    grouped, stats = group_findings_for_report(findings)

    assert len(grouped) == 1
    assert grouped[0]["detection_sources"] == ["SSRF_JS_AST", "dsl.javascript.ssrf-fetch"]
    assert stats["duplicates_collapsed"] == 1


def test_scan_project_tool_preserves_stats_and_findings(tmp_path: Path) -> None:
    _write_vulnerable_project(tmp_path)

    result = scan_project_tool(str(tmp_path), no_cache=True, no_parallel=True)

    assert result["stats"]["partial"] is False
    assert result["stats"]["error_count"] == 0
    assert result["findings"]
    assert any(finding["type"] == "SQL_INJECTION" for finding in result["findings"])


def test_knowledge_search_returns_relevant_sql_xss_ssrf_context() -> None:
    sql = search_vulnerability_knowledge_tool("SQL injection prepared statement", top_k=2)
    xss = search_vulnerability_knowledge_tool("XSS innerHTML output encoding", top_k=2)
    ssrf = search_vulnerability_knowledge_tool("SSRF outbound HTTP allowlist", top_k=2)

    assert any("CWE-89" in hit["title"] for hit in sql["hits"])
    assert any("xss" in hit["tags"] or "Cross-Site" in hit["title"] for hit in xss["hits"])
    assert any("SSRF" in hit["title"] or "CWE-918" in hit["title"] for hit in ssrf["hits"])


def test_baseline_memory_marks_accepted_risk_without_mutating_baseline(tmp_path: Path) -> None:
    _write_vulnerable_project(tmp_path)
    scan = scan_project_tool(str(tmp_path), no_cache=True, no_parallel=True)
    finding = scan["findings"][0]
    baseline_path = tmp_path / ".aegis-baseline.json"
    baseline = Baseline()
    baseline.add_findings({finding["file"]: [finding]}, tmp_path)
    baseline.save(baseline_path, tmp_path)
    before = baseline_path.read_text(encoding="utf-8")

    memory = load_project_memory_tool(str(tmp_path), scan["findings"], ".aegis-baseline.json")

    assert memory["baseline_error"] == ""
    assert memory["accepted_risk_finding_ids"] == [finding["finding_id"]]
    assert memory["finding_status"][finding["finding_id"]] == "accepted_risk"
    assert baseline_path.read_text(encoding="utf-8") == before


def test_generate_fix_offline_does_not_call_ai_unless_requested(tmp_path: Path, monkeypatch: Any) -> None:
    _write_vulnerable_project(tmp_path)
    scan = scan_project_tool(str(tmp_path), no_cache=True, no_parallel=True)
    finding = scan["findings"][0]

    class ExplodingAI:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise AssertionError("AI should not be instantiated")

    monkeypatch.setattr("src.agent.tools.AIAnalyzer", ExplodingAI)

    fix = generate_fix_suggestion_tool(finding, str(tmp_path), use_ai=False)

    assert fix["mode"] == "offline"
    assert "parameter" in fix["fix_suggestion"].lower() or "参数化" in fix["fix_suggestion"]


def test_patch_preview_generates_unified_diff_without_mutating_file(tmp_path: Path) -> None:
    app = _write_vulnerable_project(tmp_path)
    before = app.read_text(encoding="utf-8")
    scan = scan_project_tool(str(tmp_path), no_cache=True, no_parallel=True)
    finding = scan["findings"][0]
    fix = generate_fix_suggestion_tool(finding, str(tmp_path), use_ai=False)

    preview = generate_patch_preview_tool(finding, fix, str(tmp_path))

    assert preview["status"] == "preview"
    assert preview["kind"] == "applicable_preview"
    assert preview["mutates_files"] is False
    assert preview["can_auto_apply"] is True
    assert "--- a/app.js" in preview["unified_diff"]
    assert "+++ b/app.js" in preview["unified_diff"]
    assert app.read_text(encoding="utf-8") == before


def test_ssrf_fix_stays_guidance_only_with_allowlist_template(tmp_path: Path) -> None:
    app = tmp_path / "app.js"
    app.write_text(
        "\n".join(
            [
                'const express = require("express");',
                "const app = express();",
                'app.get("/proxy", async (req, res) => {',
                "  const response = await fetch(req.query.url);",
                "  res.send(await response.text());",
                "});",
            ]
        ),
        encoding="utf-8",
    )
    finding = {
        "finding_id": "ssrf-1",
        "file": "app.js",
        "line": 4,
        "rule_id": "SSRF_JS_TAINT",
        "rule_family": "SSRF",
        "type": "SSRF",
    }

    fix = generate_fix_suggestion_tool(finding, str(tmp_path), use_ai=False)
    preview = generate_patch_preview_tool(finding, fix, str(tmp_path))

    assert fix["kind"] == "guidance_only"
    assert fix["can_auto_apply"] is False
    assert "ALLOWED_HOSTS" in fix["guidance_code"]
    assert "buildAllowedUrl" in fix["guidance_code"]
    assert preview["kind"] == "guidance_only"
    assert preview["can_auto_apply"] is False
    assert app.read_text(encoding="utf-8").count("fetch(req.query.url)") == 1


def _write_patch_report(tmp_path: Path, *, target_file: str = "app.js") -> Path:
    report = {
        "summary": {"project_path": str(tmp_path)},
        "findings": [
            {
                "finding_id": "finding-1",
                "file": target_file,
                "line": 1,
                "rule_id": "SQL_INJECTION",
                "fix": {
                    "patch_preview": {
                        "status": "preview",
                        "kind": "applicable_preview",
                        "can_auto_apply": True,
                        "file": target_file,
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
    report_path = tmp_path / "agent-report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    return report_path


def test_apply_patch_preview_dry_run_validates_without_mutating_file(tmp_path: Path) -> None:
    app = tmp_path / "app.js"
    app.write_text("bad()\n", encoding="utf-8")
    report_path = _write_patch_report(tmp_path)

    result = apply_patch_preview_tool(str(report_path), "finding-1")

    assert result["status"] == "dry_run"
    assert result["mutates_files"] is False
    assert result["dry_run"] is True
    assert result["file"] == "app.js"
    assert app.read_text(encoding="utf-8") == "bad()\n"


def test_apply_patch_preview_applies_after_explicit_confirmation(tmp_path: Path) -> None:
    app = tmp_path / "app.js"
    app.write_text("bad()\n", encoding="utf-8")
    report_path = _write_patch_report(tmp_path)

    result = apply_patch_preview_tool(str(report_path), "finding-1", confirm=True)

    assert result["status"] == "applied"
    assert result["mutates_files"] is True
    assert result["dry_run"] is False
    assert app.read_text(encoding="utf-8") == "safe()\n"


def test_apply_patch_preview_rescans_after_apply_and_reports_target_removed(tmp_path: Path) -> None:
    app = _write_vulnerable_project(tmp_path)
    report = {
        "summary": {"project_path": str(tmp_path)},
        "findings": [
            {
                "finding_id": "finding-1",
                "file": "app.js",
                "line": 3,
                "rule_id": "SQL_INJECTION",
                "fix": {
                    "patch_preview": {
                        "status": "preview",
                        "kind": "applicable_preview",
                        "can_auto_apply": True,
                        "file": "app.js",
                        "start_line": 3,
                        "end_line": 3,
                        "original_code": '  db.query("SELECT * FROM users WHERE id = " + id);',
                        "replacement_code": '  db.query("SELECT * FROM users WHERE id = ?", [id]);',
                        "unified_diff": "--- a/app.js\n+++ b/app.js\n",
                    }
                },
            }
        ],
    }
    report_path = tmp_path / "agent-report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    result = apply_patch_preview_tool(str(report_path), "finding-1", confirm=True, rescan=True)

    assert result["status"] == "applied"
    assert result["rescan"]["status"] == "passed"
    assert result["rescan"]["target_finding_present"] is False
    assert "WHERE id = ?" in app.read_text(encoding="utf-8")


def test_apply_patch_preview_rejects_stale_original_code(tmp_path: Path) -> None:
    app = tmp_path / "app.js"
    app.write_text("already_changed()\n", encoding="utf-8")
    report_path = _write_patch_report(tmp_path)

    result = apply_patch_preview_tool(str(report_path), "finding-1", confirm=True)

    assert result["status"] == "stale"
    assert result["mutates_files"] is False
    assert "does not match" in result["reason"]
    assert app.read_text(encoding="utf-8") == "already_changed()\n"


def test_apply_patch_preview_rejects_path_escape(tmp_path: Path) -> None:
    app = tmp_path / "app.js"
    app.write_text("bad()\n", encoding="utf-8")
    report_path = _write_patch_report(tmp_path, target_file="../outside.js")

    result = apply_patch_preview_tool(str(report_path), "finding-1", confirm=True)

    assert result["status"] == "error"
    assert "outside the project" in result["reason"]
    assert app.read_text(encoding="utf-8") == "bad()\n"


def test_apply_patch_preview_rejects_unsafe_preview_even_with_confirmation(tmp_path: Path) -> None:
    app = tmp_path / "app.js"
    app.write_text("bad()\n", encoding="utf-8")
    report_path = _write_patch_report(tmp_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    preview = report["findings"][0]["fix"]["patch_preview"]
    preview["kind"] = "preview"
    preview["can_auto_apply"] = False
    report_path.write_text(json.dumps(report), encoding="utf-8")

    result = apply_patch_preview_tool(str(report_path), "finding-1", confirm=True)

    assert result["status"] == "unsafe_preview"
    assert result["mutates_files"] is False
    assert app.read_text(encoding="utf-8") == "bad()\n"


def test_apply_patch_preview_returns_not_applicable_without_preview(tmp_path: Path) -> None:
    app = tmp_path / "app.js"
    app.write_text("bad()\n", encoding="utf-8")
    report_path = _write_patch_report(tmp_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["findings"][0]["fix"]["patch_preview"] = {
        "status": "guidance_only",
        "kind": "guidance_only",
        "can_auto_apply": False,
    }
    report_path.write_text(json.dumps(report), encoding="utf-8")

    result = apply_patch_preview_tool(str(report_path), "finding-1", confirm=True)

    assert result["status"] == "not_applicable"
    assert result["mutates_files"] is False
    assert app.read_text(encoding="utf-8") == "bad()\n"


def test_apply_patch_preview_accepts_utf8_bom_report(tmp_path: Path) -> None:
    app = tmp_path / "app.js"
    app.write_text("bad()\n", encoding="utf-8")
    report_path = _write_patch_report(tmp_path)
    report_path.write_text(report_path.read_text(encoding="utf-8"), encoding="utf-8-sig")

    result = apply_patch_preview_tool(str(report_path), "finding-1")

    assert result["status"] == "dry_run"
    assert app.read_text(encoding="utf-8") == "bad()\n"


def test_html_report_escapes_finding_and_knowledge_fields(tmp_path: Path) -> None:
    report = {
        "workflow": {
            "nodes": ["scan", "summarize<script>alert(1)</script>"],
            "tool_trace": [
                {
                    "node": "scan",
                    "tool": "scan_project",
                    "status": "ok",
                    "duration_ms": 1.0,
                    "detail": "<img src=x onerror=alert(1)>",
                }
            ],
            "partial": False,
            "error_count": 0,
            "errors": [],
        },
        "summary": {
            "project_path": str(tmp_path / "<script>project</script>"),
            "total_findings": 1,
            "new_findings": 1,
            "accepted_risk_findings": 0,
            "suppressed_by_source_markers": 0,
            "severity_counts": {"Critical": 0, "High": 1, "Medium": 0, "Low": 0},
            "status_counts": {"new": 1},
        },
        "findings": [
            {
                "file": "app<script>.js",
                "finding_id": "<script>alert('id')</script>",
                "line": 1,
                "rule_id": "<script>alert('rule')</script>",
                "severity": "High",
                "status": "new",
                "cwe": "CWE-79",
                "cause": "Payload <img src=x onerror=alert('cause')>",
                "knowledge": [{"title": "Use <b>encoding</b>", "snippet": "<script>alert('kb')</script>"}],
                "fix": {
                    "fix_suggestion": "Escape <b>HTML</b>",
                    "fixed_code": "res.send('<script>alert(1)</script>')",
                    "patch_preview": {
                        "status": "preview",
                        "kind": "applicable_preview",
                        "can_auto_apply": True,
                        "unified_diff": "- <script>alert(1)</script>\n+ safe()",
                    },
                },
                "review_note": "Review <img src=x onerror=alert(2)>",
            }
        ],
        "memory": {},
    }

    html = render_html_report(report)

    assert "<script>alert('rule')</script>" not in html
    assert "<script>alert('id')</script>" not in html
    assert "<img src=x onerror=alert('cause')>" not in html
    assert "<b>HTML</b>" not in html
    assert "- <script>alert(1)</script>" not in html
    assert "res.send('&lt;script&gt;" not in html
    assert "&lt;script&gt;alert(&#x27;rule&#x27;)&lt;/script&gt;" in html
    assert "&lt;script&gt;alert(&#x27;id&#x27;)&lt;/script&gt;" in html
    assert "aegis-agent apply-fix aegis-agent-report.json --finding-id" in html
    assert "--yes --rescan" in html
    assert "&lt;b&gt;HTML&lt;/b&gt;" in html
    assert "res.send(&#x27;&lt;script&gt;alert(1)&lt;/script&gt;&#x27;)" in html


def test_markdown_and_html_reports_show_grouped_snapshot_without_noise(tmp_path: Path) -> None:
    report = {
        "workflow": {
            "nodes": ["scan", "analyze", "triage", "retrieve", "fix", "review", "summarize"],
            "tool_trace": [
                {"node": "scan", "tool": "scan_project", "status": "ok", "duration_ms": 1.0, "detail": "5 files"},
                {
                    "node": "triage",
                    "tool": "group_findings",
                    "status": "ok",
                    "duration_ms": 1.0,
                    "detail": "5 raw -> 3 grouped",
                },
                {"node": "fix", "tool": "generate_patch_preview", "status": "ok", "duration_ms": 1.0},
            ],
            "partial": False,
            "error_count": 0,
            "errors": [],
        },
        "summary": {
            "project_path": str(tmp_path),
            "total_findings": 3,
            "raw_findings": 5,
            "grouped_findings": 3,
            "duplicates_collapsed": 2,
            "new_findings": 3,
            "accepted_risk_findings": 0,
            "suppressed_by_source_markers": 0,
            "severity_counts": {"Critical": 0, "High": 3, "Medium": 0, "Low": 0},
            "status_counts": {"new": 3},
        },
        "findings": [
            {
                "finding_id": "sql-1",
                "file": "app.js",
                "line": 7,
                "rule_id": "SQL_INJECTION_JS_AST",
                "primary_rule_id": "SQL_INJECTION_JS_AST",
                "rule_family": "SQL_INJECTION",
                "detection_sources": ["SQL_INJECTION_JS_AST", "dsl.javascript.sql-injection-concat"],
                "severity": "High",
                "status": "new",
                "cwe": "CWE-89",
                "cause": "query concatenates req.params.id",
                "knowledge_evidence": [
                    {
                        "title": "CWE-89 SQL Injection",
                        "snippet": "Use parameterized queries.",
                        "why_matched": {"terms": ["sql", "injection"], "tags": ["cwe-89"]},
                    }
                ],
                "fix": {
                    "kind": "applicable_preview",
                    "fix_suggestion": "Use a parameter placeholder.",
                    "fixed_code": 'db.query("SELECT * FROM users WHERE id = ?", [id]);',
                    "patch_preview": {
                        "status": "preview",
                        "kind": "applicable_preview",
                        "can_auto_apply": True,
                        "unified_diff": "- concat\n+ parameterized\n",
                    },
                },
            },
            {
                "finding_id": "xss-1",
                "file": "app.js",
                "line": 13,
                "rule_id": "XSS_RISK_JS_AST",
                "primary_rule_id": "XSS_RISK_JS_AST",
                "rule_family": "XSS",
                "detection_sources": ["XSS_RISK_JS_AST"],
                "severity": "High",
                "status": "new",
                "cwe": "CWE-79",
                "cause": "reflected query parameter in HTML",
                "fix": {
                    "kind": "applicable_preview",
                    "fix_suggestion": "HTML-encode reflected output.",
                    "fixed_code": "res.send(escapeHtml(req.query.name));",
                    "patch_preview": {
                        "status": "preview",
                        "kind": "applicable_preview",
                        "can_auto_apply": True,
                        "unified_diff": "- raw\n+ escaped\n",
                    },
                },
            },
            {
                "finding_id": "ssrf-1",
                "file": "app.js",
                "line": 18,
                "rule_id": "SSRF_JS_TAINT",
                "primary_rule_id": "SSRF_JS_TAINT",
                "rule_family": "SSRF",
                "detection_sources": ["SSRF_JS_TAINT"],
                "severity": "High",
                "status": "new",
                "cwe": "CWE-918",
                "cause": "server fetches req.query.url",
                "knowledge_evidence": [
                    {
                        "title": "CWE-918 Server-Side Request Forgery",
                        "snippet": "Use a strict destination allowlist.",
                        "why_matched": {"terms": ["ssrf"], "tags": ["cwe-918"]},
                    }
                ],
                "fix": {
                    "kind": "guidance_only",
                    "fix_suggestion": "Use a strict destination allowlist.",
                    "guidance_code": "const ALLOWED_HOSTS = new Set(['api.example.com']);",
                    "patch_preview": {
                        "status": "guidance_only",
                        "kind": "guidance_only",
                        "can_auto_apply": False,
                    },
                },
            },
        ],
        "memory": {},
    }

    markdown = render_markdown_report(report)
    html = render_html_report(report)

    assert markdown.count("### SQL_INJECTION") == 1
    assert markdown.count("### SSRF") == 1
    assert html.count("<h3>SQL_INJECTION</h3>") == 1
    assert html.count("<h3>SSRF</h3>") == 1
    assert "Duplicates collapsed: 2" in markdown
    assert "Collapsed duplicates" in html
    assert "## Workflow Trace" in markdown
    assert "Workflow Trace" in html
    assert "## Tool Calls" in markdown
    assert "Tool Calls" in html
    assert "group_findings" in markdown
    assert "group_findings" in html
    assert "Knowledge evidence" in markdown
    assert "Knowledge evidence" in html
    assert "bypassSecurityTrustHtml" not in markdown
    assert "bypassSecurityTrustHtml" not in html
