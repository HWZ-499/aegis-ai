"""Callable tools used by the Aegis Agent workflow."""

from __future__ import annotations

import hashlib
import html as html_lib
import json
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from difflib import unified_diff
from pathlib import Path
from typing import Any, cast

from src.agent.knowledge_base import MarkdownKnowledgeBase
from src.scanner.ai_analyzer import AIAnalyzer
from src.scanner.baseline import AEGIS_IGNORE_RE, Baseline, BaselineLoadError
from src.scanner.project_scanner import ProjectScanner
from src.scanner.rag_enhancer import BUILTIN_REMEDIATION
from src.scanner.smart_remediation import generate_smart_remediation

Finding = dict[str, Any]
ToolPayload = dict[str, Any]
ToolHandler = Callable[..., ToolPayload]


@dataclass(frozen=True)
class AgentTool:
    """Tool metadata plus the local callable implementation."""

    name: str
    description: str
    parameters: dict[str, Any]
    handler: ToolHandler

    def to_openai_schema(self) -> dict[str, Any]:
        """Return an OpenAI-style function tool schema."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


def _finding_rule_id(finding: Finding) -> str:
    return str(finding.get("rule_id") or finding.get("type") or "UNKNOWN")


def _finding_file(finding: Finding) -> str:
    return str(finding.get("file") or finding.get("file_path") or "")


def make_finding_id(finding: Finding) -> str:
    """Create a stable finding id for reports."""
    raw = "|".join(
        [
            _finding_rule_id(finding),
            _finding_file(finding),
            str(finding.get("line") or finding.get("start_line") or 0),
            str(finding.get("details") or finding.get("message") or ""),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _flatten_scan_results(results: dict[str, list[Finding]]) -> list[Finding]:
    flattened: list[Finding] = []
    for file_path, findings in sorted(results.items()):
        for finding in findings:
            item = dict(finding)
            item.setdefault("file", file_path)
            item.setdefault("finding_id", make_finding_id(item))
            flattened.append(item)
    return flattened


def _resolve_project_file(project_path: Path, finding: Finding) -> Path | None:
    raw = _finding_file(finding)
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = project_path / path
    try:
        resolved = path.resolve()
        resolved.relative_to(project_path)
        return resolved
    except (OSError, ValueError):
        return None


def _read_source_for_finding(project_path: Path, finding: Finding) -> str:
    file_path = _resolve_project_file(project_path, finding)
    if file_path is None or not file_path.is_file():
        return ""
    try:
        return file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _collect_extra_rule_dirs(project_path: Path, rules_dirs: list[str] | None) -> list[Path]:
    extra_rule_dirs: list[Path] = []
    for raw in rules_dirs or []:
        path = Path(raw)
        if not path.is_absolute():
            path = project_path / path
        if path.is_dir():
            extra_rule_dirs.append(path)
    aegis_rules = project_path / ".aegis" / "rules"
    if aegis_rules.is_dir():
        extra_rule_dirs.append(aegis_rules)
    return extra_rule_dirs


def scan_project_tool(
    project_path: str,
    ignore_patterns: list[str] | None = None,
    no_cache: bool = False,
    no_parallel: bool = False,
    max_workers: int | None = None,
    engine: str = "new",
    rules_dirs: list[str] | None = None,
) -> ToolPayload:
    """Run the existing ProjectScanner and return raw plus flattened findings."""
    started = time.perf_counter()
    root = Path(project_path).resolve()
    extra_rule_dirs = _collect_extra_rule_dirs(root, rules_dirs)
    scanner = ProjectScanner(
        str(root),
        ignore_patterns=ignore_patterns,
        use_cache=not no_cache,
        use_parallel=not no_parallel,
        max_workers=max_workers,
        engine=engine,
        extra_rule_dirs=extra_rule_dirs or None,
    )
    results = scanner.scan_project(verbose=False)
    stats = scanner.get_stats()
    return {
        "project_path": str(root),
        "results": results,
        "findings": _flatten_scan_results(results),
        "stats": stats,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
    }


def get_finding_detail_tool(
    finding: Finding,
    project_path: str | None = None,
    status: str = "new",
) -> ToolPayload:
    """Normalize a raw scanner finding for report and workflow use."""
    rule_id = _finding_rule_id(finding)
    remediation = cast(dict[str, Any], BUILTIN_REMEDIATION.get(rule_id, {}))
    cwe = finding.get("cwe") or finding.get("cwe_id") or remediation.get("cwe") or ""
    details = str(finding.get("details") or finding.get("message") or "")
    normalized = {
        "finding_id": str(finding.get("finding_id") or make_finding_id(finding)),
        "file": _finding_file(finding),
        "line": int(finding.get("line") or finding.get("start_line") or 0),
        "column": int(finding.get("column") or finding.get("start_character") or 0),
        "rule_id": rule_id,
        "severity": str(finding.get("severity") or "Medium"),
        "confidence": finding.get("confidence", ""),
        "cwe": cwe,
        "cause": details,
        "language": str(finding.get("language") or ""),
        "status": status,
        "source": str(finding.get("source") or "ProjectScanner"),
    }
    if project_path:
        source = _read_source_for_finding(Path(project_path).resolve(), finding)
        if source:
            line_number = max(1, normalized["line"])
            lines = source.splitlines()
            start = max(0, line_number - 3)
            end = min(len(lines), line_number + 2)
            normalized["code_context"] = "\n".join(lines[start:end])
    return normalized


def search_vulnerability_knowledge_tool(
    query: str,
    vuln_type: str | None = None,
    cwe: str | None = None,
    top_k: int = 3,
    knowledge_base: MarkdownKnowledgeBase | None = None,
) -> ToolPayload:
    """Retrieve bundled Markdown knowledge for a finding."""
    kb = knowledge_base or MarkdownKnowledgeBase()
    terms = " ".join(part for part in [query, vuln_type or "", cwe or ""] if part)
    hits = kb.search(terms, top_k=top_k)
    return {
        "query": terms,
        "hits": [hit.to_dict() for hit in hits],
    }


def generate_fix_suggestion_tool(
    finding: Finding,
    project_path: str,
    use_ai: bool = False,
    ai_analyzer: AIAnalyzer | None = None,
) -> ToolPayload:
    """Generate an offline fix suggestion, with optional explicit AI enhancement."""
    root = Path(project_path).resolve()
    source = _read_source_for_finding(root, finding)
    rule_id = _finding_rule_id(finding)
    response: ToolPayload = {
        "mode": "offline",
        "fix_suggestion": "",
        "fixed_code": "",
        "confidence": None,
        "requires_review": True,
        "ai_error": "",
    }

    if source:
        try:
            smart = generate_smart_remediation(finding, source, str(_resolve_project_file(root, finding) or ""))
            response.update(
                {
                    "fix_suggestion": smart.message,
                    "fixed_code": smart.suggested_code,
                    "framework": smart.framework or "",
                    "replacements": smart.replacements or {},
                }
            )
        except (RuntimeError, ValueError, KeyError) as exc:
            response["ai_error"] = f"smart remediation failed: {exc}"

    if not response.get("fix_suggestion"):
        remediation = cast(dict[str, Any], BUILTIN_REMEDIATION.get(rule_id, {}))
        suggestions = remediation.get("remediation") or []
        response["fix_suggestion"] = suggestions[0] if suggestions else remediation.get("description", "")
        response["fixed_code"] = remediation.get("suggested_code", "")

    if not use_ai:
        return response

    analyzer = ai_analyzer or AIAnalyzer(enabled=True)
    if not getattr(analyzer, "enabled", False):
        response["ai_error"] = "AI provider is not configured; offline remediation was used."
        return response

    try:
        result = analyzer.analyze_finding(
            finding,
            language=str(finding.get("language") or ""),
            source_code=source,
        )
    except (RuntimeError, KeyError, ValueError) as exc:
        response["ai_error"] = f"AI provider request failed: {exc}"
        return response

    response["mode"] = "ai"
    response["confidence"] = result.confidence
    response["requires_review"] = result.requires_review
    if result.fix_suggestion:
        response["fix_suggestion"] = result.fix_suggestion
    if result.fixed_code:
        response["fixed_code"] = result.fixed_code
    if result.error_code:
        response["ai_error"] = str(result.error_message or result.error_code)
    return response


def _normalize_replacement_lines(fixed_code: str, original_line: str) -> list[str]:
    replacement = fixed_code.strip("\n")
    if not replacement.strip():
        return []

    lines = replacement.splitlines()
    original_indent = original_line[: len(original_line) - len(original_line.lstrip())]
    if not original_indent:
        return lines

    nonblank = [line for line in lines if line.strip()]
    if not nonblank:
        return lines

    min_indent = min(len(line) - len(line.lstrip()) for line in nonblank)
    if min_indent > 0:
        return lines

    return [original_indent + line if line.strip() else line for line in lines]


def generate_patch_preview_tool(
    finding: Finding,
    fix: dict[str, Any],
    project_path: str,
) -> ToolPayload:
    """Create a non-mutating unified diff preview for a suggested fix."""
    fixed_code = str(fix.get("fixed_code") or "").strip()
    base_payload: ToolPayload = {
        "status": "unavailable",
        "mutates_files": False,
        "can_auto_apply": False,
        "reason": "No concrete replacement code was generated for this finding.",
    }
    if not fixed_code:
        return base_payload

    root = Path(project_path).resolve()
    file_path = _resolve_project_file(root, finding)
    if file_path is None or not file_path.is_file():
        base_payload["reason"] = "Finding file could not be resolved inside the project."
        return base_payload

    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        base_payload["reason"] = f"Finding file could not be read: {exc}"
        return base_payload

    source_lines = source.splitlines()
    line_number = int(finding.get("line") or finding.get("start_line") or 0)
    if line_number < 1 or line_number > len(source_lines):
        base_payload["reason"] = "Finding line is outside the current file."
        return base_payload

    original_line = source_lines[line_number - 1]
    replacement_lines = _normalize_replacement_lines(fixed_code, original_line)
    if not replacement_lines:
        return base_payload

    relative_file = str(file_path.relative_to(root).as_posix())
    proposed_lines = source_lines[: line_number - 1] + replacement_lines + source_lines[line_number:]
    diff = "\n".join(
        unified_diff(
            source_lines,
            proposed_lines,
            fromfile=f"a/{relative_file}",
            tofile=f"b/{relative_file}",
            lineterm="",
        )
    )
    if diff:
        diff += "\n"

    return {
        "status": "preview",
        "mutates_files": False,
        "can_auto_apply": False,
        "reason": "Preview only. Review, apply explicitly, then rescan before trusting the change.",
        "file": relative_file,
        "start_line": line_number,
        "end_line": line_number,
        "original_code": original_line,
        "replacement_code": "\n".join(replacement_lines),
        "unified_diff": diff,
    }


def _load_report(report_path: Path) -> tuple[dict[str, Any] | None, str]:
    try:
        loaded = json.loads(report_path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        return None, "Report file does not exist."
    except json.JSONDecodeError as exc:
        return None, f"Report file is not valid JSON: {exc.msg}."
    except OSError as exc:
        return None, f"Report file could not be read: {exc}."
    if not isinstance(loaded, dict):
        return None, "Report root must be a JSON object."
    return loaded, ""


def _resolve_report_project_root(report: dict[str, Any], project_path: str | None) -> tuple[Path | None, str]:
    summary = report.get("summary", {})
    report_project_path = str(summary.get("project_path") or "") if isinstance(summary, dict) else ""
    if not project_path and not report_project_path:
        return None, "Project path is missing; pass --project-path or use a report with summary.project_path."

    root = Path(project_path or report_project_path).resolve()
    if project_path and report_project_path:
        report_root = Path(report_project_path).resolve()
        if report_root != root:
            return None, "Report project_path does not match the requested project_path."
    if not root.is_dir():
        return None, f"Project path is not a directory: {root}"
    return root, ""


def _find_report_finding(report: dict[str, Any], finding_id: str) -> Finding | None:
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        return None
    for finding in findings:
        if isinstance(finding, dict) and str(finding.get("finding_id") or "") == finding_id:
            return cast(Finding, finding)
    return None


def _apply_status(
    status: str,
    reason: str,
    *,
    finding_id: str,
    mutates_files: bool = False,
    dry_run: bool = True,
    extra: dict[str, Any] | None = None,
) -> ToolPayload:
    payload: ToolPayload = {
        "status": status,
        "reason": reason,
        "finding_id": finding_id,
        "mutates_files": mutates_files,
        "dry_run": dry_run,
    }
    if extra:
        payload.update(extra)
    return payload


def _matches_report_finding(report_finding: Finding, scan_finding: Finding, project_root: Path) -> bool:
    expected_file = _finding_file(report_finding)
    actual_file = _finding_file(scan_finding)
    if expected_file:
        expected_path = Path(expected_file)
        if expected_path.is_absolute():
            try:
                expected_file = expected_path.resolve().relative_to(project_root).as_posix()
            except ValueError:
                expected_file = expected_path.name
        else:
            expected_file = expected_path.as_posix()
    if actual_file:
        actual_path = Path(actual_file)
        if actual_path.is_absolute():
            try:
                actual_file = actual_path.resolve().relative_to(project_root).as_posix()
            except ValueError:
                actual_file = actual_path.name
        else:
            actual_file = actual_path.as_posix()

    return (
        _finding_rule_id(report_finding) == _finding_rule_id(scan_finding)
        and expected_file == actual_file
        and int(report_finding.get("line") or report_finding.get("start_line") or 0)
        == int(scan_finding.get("line") or scan_finding.get("start_line") or 0)
    )


def _rescan_after_apply(
    *,
    project_path: Path,
    finding: Finding,
) -> ToolPayload:
    started = time.perf_counter()
    try:
        scan = scan_project_tool(
            str(project_path),
            no_cache=True,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        return {
            "status": "error",
            "reason": f"Rescan failed: {exc}",
            "target_finding_present": None,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        }

    findings = cast(list[Finding], scan.get("findings", []))
    stats = cast(dict[str, Any], scan.get("stats", {}))
    matches = [item for item in findings if _matches_report_finding(finding, item, project_path)]
    partial = bool(stats.get("partial", False))
    error_count = int(stats.get("error_count", 0))
    if partial or error_count:
        status = "partial"
        reason = "Rescan completed with scan errors; fix verification is not fully trusted."
    elif matches:
        status = "failed"
        reason = "Target finding is still present after applying the patch preview."
    else:
        status = "passed"
        reason = "Target finding was not detected after applying the patch preview."

    return {
        "status": status,
        "reason": reason,
        "target_finding_present": bool(matches),
        "total_findings": len(findings),
        "matching_findings": [
            {
                "finding_id": str(item.get("finding_id") or make_finding_id(item)),
                "file": _finding_file(item),
                "line": int(item.get("line") or item.get("start_line") or 0),
                "rule_id": _finding_rule_id(item),
                "severity": str(item.get("severity") or "Medium"),
            }
            for item in matches[:5]
        ],
        "partial": partial,
        "error_count": error_count,
        "errors": stats.get("errors", []),
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
    }


def apply_patch_preview_tool(
    report_path: str,
    finding_id: str,
    project_path: str | None = None,
    confirm: bool = False,
    rescan: bool = False,
) -> ToolPayload:
    """Apply one report patch preview only after explicit confirmation."""
    report_file = Path(report_path).resolve()
    report, error = _load_report(report_file)
    if report is None:
        return _apply_status("error", error, finding_id=finding_id)

    root, error = _resolve_report_project_root(report, project_path)
    if root is None:
        return _apply_status("error", error, finding_id=finding_id)

    finding = _find_report_finding(report, finding_id)
    if finding is None:
        return _apply_status("not_found", "Finding id was not found in the Agent report.", finding_id=finding_id)

    fix = finding.get("fix", {})
    patch_preview = fix.get("patch_preview", {}) if isinstance(fix, dict) else {}
    if not isinstance(patch_preview, dict) or patch_preview.get("status") != "preview":
        return _apply_status(
            "unavailable",
            "Finding does not contain an applicable patch preview.",
            finding_id=finding_id,
        )

    raw_file = str(patch_preview.get("file") or "")
    if not raw_file:
        return _apply_status("error", "Patch preview is missing the target file.", finding_id=finding_id)

    raw_target = Path(raw_file)
    target = (raw_target if raw_target.is_absolute() else root / raw_target).resolve()
    try:
        relative_file = target.relative_to(root).as_posix()
    except ValueError:
        return _apply_status("error", "Patch preview target is outside the project path.", finding_id=finding_id)
    if not target.is_file():
        return _apply_status(
            "stale",
            "Patch preview target file no longer exists.",
            finding_id=finding_id,
            extra={"file": relative_file},
        )

    try:
        source = target.read_text(encoding="utf-8")
    except OSError as exc:
        return _apply_status(
            "error",
            f"Patch preview target could not be read: {exc}",
            finding_id=finding_id,
            extra={"file": relative_file},
        )

    try:
        start_line = int(patch_preview.get("start_line") or 0)
        end_line = int(patch_preview.get("end_line") or start_line)
    except (TypeError, ValueError):
        return _apply_status("error", "Patch preview line range is invalid.", finding_id=finding_id)
    source_lines = source.splitlines()
    if start_line < 1 or end_line < start_line or end_line > len(source_lines):
        return _apply_status(
            "stale",
            "Patch preview line range no longer matches the current file.",
            finding_id=finding_id,
            extra={"file": relative_file, "start_line": start_line, "end_line": end_line},
        )

    if "original_code" not in patch_preview or "replacement_code" not in patch_preview:
        return _apply_status("error", "Patch preview is missing original or replacement code.", finding_id=finding_id)
    expected = str(patch_preview.get("original_code") or "")
    replacement = str(patch_preview.get("replacement_code") or "")
    if not replacement.strip():
        return _apply_status("error", "Patch preview replacement code is empty.", finding_id=finding_id)

    current = "\n".join(source_lines[start_line - 1 : end_line])
    common: dict[str, Any] = {
        "report_path": str(report_file),
        "project_path": str(root),
        "file": relative_file,
        "start_line": start_line,
        "end_line": end_line,
        "original_code": expected,
        "replacement_code": replacement,
        "unified_diff": str(patch_preview.get("unified_diff") or ""),
    }
    if current != expected:
        common["current_code"] = current
        return _apply_status(
            "stale",
            "Current file content does not match the patch preview original_code.",
            finding_id=finding_id,
            extra=common,
        )

    replacement_lines = replacement.splitlines()
    proposed_lines = source_lines[: start_line - 1] + replacement_lines + source_lines[end_line:]
    newline = "\r\n" if "\r\n" in source else "\n"
    proposed = newline.join(proposed_lines)
    if source.endswith(("\n", "\r")):
        proposed += newline

    if not confirm:
        if rescan:
            common["rescan"] = {
                "status": "skipped",
                "reason": "Rescan is skipped for dry-run apply-fix; pass --yes to apply before rescanning.",
            }
        return _apply_status(
            "dry_run",
            "Patch preview was validated but not applied. Re-run with --yes to write the file.",
            finding_id=finding_id,
            extra=common,
        )

    try:
        target.write_text(proposed, encoding="utf-8")
    except OSError as exc:
        return _apply_status(
            "error",
            f"Patch preview target could not be written: {exc}",
            finding_id=finding_id,
            extra=common,
        )

    if rescan:
        common["rescan"] = _rescan_after_apply(project_path=root, finding=finding)

    return _apply_status(
        "applied",
        (
            "Patch preview applied and rescan completed."
            if rescan
            else "Patch preview applied. Rescan the project before trusting the fix."
        ),
        finding_id=finding_id,
        mutates_files=True,
        dry_run=False,
        extra=common,
    )


def _resolve_baseline_path(project_path: Path, baseline_path: str | None) -> Path:
    if baseline_path:
        path = Path(baseline_path)
        return path if path.is_absolute() else project_path / path
    return project_path / ".aegis-baseline.json"


def _source_suppression_markers(project_path: Path) -> list[dict[str, Any]]:
    markers: list[dict[str, Any]] = []
    skipped_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", "dist", "build"}
    supported = {".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".php", ".java", ".go"}
    for path in project_path.rglob("*"):
        if not path.is_file() or path.suffix not in supported:
            continue
        if any(part in skipped_dirs for part in path.relative_to(project_path).parts):
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for index, line in enumerate(lines, 1):
            match = AEGIS_IGNORE_RE.search(line)
            if match:
                markers.append(
                    {
                        "file": str(path.relative_to(project_path).as_posix()),
                        "line": index,
                        "rule_id": (match.group(1) or "").upper(),
                    }
                )
    return markers


def load_project_memory_tool(
    project_path: str,
    findings: list[Finding] | None = None,
    baseline_path: str | None = None,
) -> ToolPayload:
    """Load baseline and inline suppression metadata without mutating project files."""
    root = Path(project_path).resolve()
    path = _resolve_baseline_path(root, baseline_path)
    baseline_error = ""
    baseline = Baseline()
    if path.exists():
        try:
            baseline = Baseline.load(path)
        except BaselineLoadError as exc:
            baseline_error = str(exc)

    status_by_id: dict[str, str] = {}
    accepted: list[str] = []
    for finding in findings or []:
        finding_id = str(finding.get("finding_id") or make_finding_id(finding))
        if not baseline_error and baseline.contains(finding, root):
            status_by_id[finding_id] = "accepted_risk"
            accepted.append(finding_id)
        else:
            status_by_id[finding_id] = "new"

    suppression_markers = _source_suppression_markers(root)
    return {
        "baseline_path": str(path),
        "baseline_error": baseline_error,
        "baseline_entries": [entry.model_dump(by_alias=True) for entry in baseline.list_entries()],
        "accepted_risk_finding_ids": accepted,
        "finding_status": status_by_id,
        "source_suppression_markers": suppression_markers,
        "source_suppression_count": len(suppression_markers),
    }


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for finding in findings:
        counts[str(finding.get("severity") or "Medium")] += 1
    return {severity: counts.get(severity, 0) for severity in ["Critical", "High", "Medium", "Low"]}


def summarize_report_tool(
    project_path: str,
    findings: list[Finding],
    stats: dict[str, Any],
    memory: dict[str, Any],
    workflow_nodes: list[str],
    tool_trace: list[dict[str, Any]],
) -> ToolPayload:
    """Build the structured Aegis Agent diagnosis report."""
    status_counts = Counter(str(finding.get("status", "new")) for finding in findings)
    report_findings = sorted(
        findings,
        key=lambda finding: (
            str(finding.get("file", "")),
            int(finding.get("line", 0)),
            str(finding.get("rule_id", "")),
        ),
    )
    return {
        "workflow": {
            "nodes": workflow_nodes,
            "tool_trace": tool_trace,
            "partial": bool(stats.get("partial", False)),
            "error_count": int(stats.get("error_count", 0)),
            "errors": stats.get("errors", []),
        },
        "summary": {
            "project_path": str(Path(project_path).resolve()),
            "total_findings": len(findings),
            "severity_counts": _severity_counts(findings),
            "status_counts": dict(status_counts),
            "new_findings": int(status_counts.get("new", 0)),
            "accepted_risk_findings": int(status_counts.get("accepted_risk", 0)),
            "suppressed_by_source_markers": int(memory.get("source_suppression_count", 0)),
            "scan_time": stats.get("scan_time"),
        },
        "findings": report_findings,
        "memory": memory,
    }


def render_markdown_report(report: dict[str, Any]) -> str:
    """Render the structured Agent report as Markdown."""
    summary = report.get("summary", {})
    workflow = report.get("workflow", {})
    findings = report.get("findings", [])
    lines = [
        "# Aegis Agent Diagnosis Report",
        "",
        "## Summary",
        "",
        f"- Project: `{summary.get('project_path', '')}`",
        f"- Total findings: {summary.get('total_findings', 0)}",
        f"- New findings: {summary.get('new_findings', 0)}",
        f"- Accepted risk findings: {summary.get('accepted_risk_findings', 0)}",
        f"- Source suppression markers: {summary.get('suppressed_by_source_markers', 0)}",
        f"- Partial scan: {str(workflow.get('partial', False)).lower()}",
        "",
        "## Workflow Trace",
        "",
    ]
    for node in workflow.get("nodes", []):
        lines.append(f"- {node}")
    lines.extend(["", "## Vulnerability List", ""])

    if not findings:
        lines.append("No active findings were returned by the scanner.")
    for finding in findings:
        lines.extend(
            [
                f"### {finding.get('rule_id', 'UNKNOWN')} - {finding.get('file', '')}:{finding.get('line', 0)}",
                "",
                f"- Severity: {finding.get('severity', 'Medium')}",
                f"- Status: {finding.get('status', 'new')}",
                f"- CWE: {finding.get('cwe', '') or 'n/a'}",
                f"- Cause: {finding.get('cause', '')}",
            ]
        )
        knowledge = finding.get("knowledge", [])
        if knowledge:
            lines.append("- Retrieved knowledge:")
            for hit in knowledge[:3]:
                lines.append(f"  - {hit.get('title', '')}: {hit.get('snippet', '')}")
        fix = finding.get("fix", {})
        if fix:
            lines.append(f"- Fix suggestion: {fix.get('fix_suggestion', '')}")
            fixed_code = str(fix.get("fixed_code") or "").strip()
            if fixed_code:
                lines.extend(["", "```", fixed_code, "```"])
            patch_preview = fix.get("patch_preview", {})
            if patch_preview.get("status") == "preview":
                lines.extend(
                    [
                        "",
                        "- Patch preview: review only; not applied by Aegis Agent.",
                        "",
                        "```diff",
                        str(patch_preview.get("unified_diff", "")).rstrip(),
                        "```",
                    ]
                )
        review_note = finding.get("review_note", "")
        if review_note:
            lines.append(f"- Review: {review_note}")
        lines.append("")

    lines.extend(["## Tool Calls", ""])
    for event in workflow.get("tool_trace", []):
        lines.append(
            f"- {event.get('node', '')}: `{event.get('tool', '')}` "
            f"({event.get('status', '')}, {event.get('duration_ms', 0)} ms)"
        )
    return "\n".join(lines).rstrip() + "\n"


def _html_escape(value: Any) -> str:
    return html_lib.escape(str(value), quote=True) if value is not None else ""


def _severity_class(value: Any) -> str:
    severity = str(value or "medium").lower()
    return severity if severity in {"critical", "high", "medium", "low"} else "medium"


def render_html_report(report: dict[str, Any]) -> str:
    """Render the structured Agent report as a self-contained, escaped HTML report."""
    summary = report.get("summary", {})
    workflow = report.get("workflow", {})
    findings = report.get("findings", [])
    severity_counts = summary.get("severity_counts", {})
    status_counts = summary.get("status_counts", {})

    severity_rows = "\n".join(
        f"""
            <tr>
                <td><span class="severity {_severity_class(severity)}">{_html_escape(severity)}</span></td>
                <td>{_html_escape(severity_counts.get(severity, 0))}</td>
            </tr>"""
        for severity in ["Critical", "High", "Medium", "Low"]
    )
    status_rows = "\n".join(
        f"""
            <tr>
                <td>{_html_escape(status)}</td>
                <td>{_html_escape(count)}</td>
            </tr>"""
        for status, count in sorted(status_counts.items())
    )
    workflow_steps = "\n".join(
        f'<li><span class="step-index">{index}</span>{_html_escape(node)}</li>'
        for index, node in enumerate(workflow.get("nodes", []), 1)
    )
    tool_rows = "\n".join(
        f"""
            <tr>
                <td>{_html_escape(event.get("node", ""))}</td>
                <td><code>{_html_escape(event.get("tool", ""))}</code></td>
                <td>{_html_escape(event.get("status", ""))}</td>
                <td>{_html_escape(event.get("duration_ms", 0))} ms</td>
                <td>{_html_escape(event.get("detail", ""))}</td>
            </tr>"""
        for event in workflow.get("tool_trace", [])
    )

    if findings:
        finding_sections = "\n".join(_render_html_finding(finding) for finding in findings)
    else:
        finding_sections = '<p class="empty-state">No active findings were returned by the scanner.</p>'

    errors = workflow.get("errors", [])
    if errors:
        error_items = "\n".join(
            f"<li><code>{_html_escape(error.get('file', '<unknown>'))}</code>: "
            f"{_html_escape(error.get('message', ''))}</li>"
            for error in errors[:20]
            if isinstance(error, dict)
        )
        errors_block = f"""
        <section>
            <h2>Scan Errors</h2>
            <ul class="errors">{error_items}</ul>
        </section>
        """
    else:
        errors_block = ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Aegis Agent Diagnosis Report</title>
    <style>
        :root {{
            color-scheme: light;
            --bg: #f6f7f9;
            --panel: #ffffff;
            --text: #1f2933;
            --muted: #5f6b7a;
            --border: #d9dee7;
            --accent: #146eb4;
            --critical: #b42318;
            --high: #c2410c;
            --medium: #936316;
            --low: #166534;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            background: var(--bg);
            color: var(--text);
            font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }}
        .container {{
            max-width: 1180px;
            margin: 0 auto;
            padding: 32px 20px 48px;
        }}
        header {{
            border-bottom: 1px solid var(--border);
            margin-bottom: 24px;
            padding-bottom: 18px;
        }}
        h1, h2, h3 {{ margin: 0; line-height: 1.25; }}
        h1 {{ font-size: 30px; }}
        h2 {{ font-size: 20px; margin-bottom: 12px; }}
        h3 {{ font-size: 16px; }}
        .subtitle {{ color: var(--muted); margin: 8px 0 0; }}
        section {{
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-top: 18px;
            padding: 18px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
        }}
        .metric {{
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            background: #fbfcfe;
        }}
        .metric-label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; }}
        .metric-value {{ display: block; font-size: 24px; font-weight: 700; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{
            border-bottom: 1px solid var(--border);
            padding: 9px 8px;
            text-align: left;
            vertical-align: top;
        }}
        th {{ color: var(--muted); font-size: 12px; text-transform: uppercase; }}
        code, pre {{
            background: #f0f3f7;
            border-radius: 6px;
            font-family: "SFMono-Regular", Consolas, monospace;
            font-size: 12px;
        }}
        code {{ padding: 2px 5px; }}
        pre {{
            overflow-x: auto;
            padding: 12px;
            white-space: pre-wrap;
        }}
        .workflow {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            list-style: none;
            padding: 0;
            margin: 0;
        }}
        .workflow li {{
            border: 1px solid var(--border);
            border-radius: 999px;
            padding: 6px 10px;
            background: #fbfcfe;
        }}
        .step-index {{
            color: var(--accent);
            font-weight: 700;
            margin-right: 6px;
        }}
        .finding {{
            border-top: 1px solid var(--border);
            margin-top: 16px;
            padding-top: 16px;
        }}
        .finding:first-child {{ border-top: 0; margin-top: 0; padding-top: 0; }}
        .finding-meta {{
            color: var(--muted);
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 8px 0 12px;
        }}
        .severity {{
            border-radius: 999px;
            color: #fff;
            display: inline-block;
            font-weight: 700;
            padding: 2px 8px;
        }}
        .critical {{ background: var(--critical); }}
        .high {{ background: var(--high); }}
        .medium {{ background: var(--medium); }}
        .low {{ background: var(--low); }}
        .knowledge {{
            border-left: 3px solid var(--accent);
            margin: 10px 0;
            padding-left: 12px;
        }}
        .knowledge-title {{ font-weight: 700; }}
        .empty-state {{ color: var(--muted); }}
        .errors {{ color: var(--critical); }}
        @media (max-width: 700px) {{
            .container {{ padding: 20px 12px 32px; }}
            h1 {{ font-size: 24px; }}
            section {{ padding: 14px; }}
            th, td {{ padding: 8px 4px; }}
        }}
    </style>
</head>
<body>
    <main class="container">
        <header>
            <h1>Aegis Agent Diagnosis Report</h1>
            <p class="subtitle">Project: <code>{_html_escape(summary.get("project_path", ""))}</code></p>
        </header>

        <section>
            <h2>Summary</h2>
            <div class="summary-grid">
                <div class="metric"><span class="metric-label">Total findings</span><span class="metric-value">{_html_escape(summary.get("total_findings", 0))}</span></div>
                <div class="metric"><span class="metric-label">New findings</span><span class="metric-value">{_html_escape(summary.get("new_findings", 0))}</span></div>
                <div class="metric"><span class="metric-label">Accepted risk</span><span class="metric-value">{_html_escape(summary.get("accepted_risk_findings", 0))}</span></div>
                <div class="metric"><span class="metric-label">Partial scan</span><span class="metric-value">{_html_escape(str(workflow.get("partial", False)).lower())}</span></div>
            </div>
        </section>

        <section>
            <h2>Severity</h2>
            <table>
                <thead><tr><th>Severity</th><th>Count</th></tr></thead>
                <tbody>{severity_rows}</tbody>
            </table>
        </section>

        <section>
            <h2>Memory Status</h2>
            <table>
                <thead><tr><th>Status</th><th>Count</th></tr></thead>
                <tbody>{status_rows}</tbody>
            </table>
            <p class="subtitle">Source suppression markers: {_html_escape(summary.get("suppressed_by_source_markers", 0))}</p>
        </section>

        <section>
            <h2>Workflow Trace</h2>
            <ol class="workflow">{workflow_steps}</ol>
        </section>

        {errors_block}

        <section>
            <h2>Vulnerability List</h2>
            {finding_sections}
        </section>

        <section>
            <h2>Tool Calls</h2>
            <table>
                <thead><tr><th>Node</th><th>Tool</th><th>Status</th><th>Duration</th><th>Detail</th></tr></thead>
                <tbody>{tool_rows}</tbody>
            </table>
        </section>
    </main>
</body>
</html>
"""


def _render_html_finding(finding: Finding) -> str:
    knowledge = finding.get("knowledge", [])
    knowledge_html = ""
    if knowledge:
        knowledge_html = "\n".join(
            f"""
            <div class="knowledge">
                <div class="knowledge-title">{_html_escape(hit.get("title", ""))}</div>
                <div>{_html_escape(hit.get("snippet", ""))}</div>
            </div>"""
            for hit in knowledge[:3]
        )
    fix = finding.get("fix", {})
    fixed_code = str(fix.get("fixed_code") or "").strip() if isinstance(fix, dict) else ""
    fixed_code_html = f"<pre>{_html_escape(fixed_code)}</pre>" if fixed_code else ""
    fix_suggestion = fix.get("fix_suggestion", "") if isinstance(fix, dict) else ""
    patch_preview = fix.get("patch_preview", {}) if isinstance(fix, dict) else {}
    patch_html = ""
    apply_html = ""
    finding_id = str(finding.get("finding_id") or "")
    if isinstance(patch_preview, dict) and patch_preview.get("status") == "preview":
        if finding_id:
            dry_run_command = f"aegis-agent apply-fix aegis-agent-report.json --finding-id {finding_id}"
            apply_command = f"{dry_run_command} --yes --rescan"
            apply_html = f"""
            <p><strong>Apply command dry-run:</strong></p>
            <pre>{_html_escape(dry_run_command)}</pre>
            <p><strong>Apply and rescan:</strong></p>
            <pre>{_html_escape(apply_command)}</pre>
            """
        patch_html = f"""
            <p><strong>Patch preview:</strong> review only; not applied by Aegis Agent.</p>
            <pre>{_html_escape(patch_preview.get("unified_diff", ""))}</pre>
        """
    review_note = finding.get("review_note", "")
    review_html = f"<p><strong>Review:</strong> {_html_escape(review_note)}</p>" if review_note else ""
    cwe = finding.get("cwe") or "n/a"
    return f"""
        <article class="finding">
            <h3>{_html_escape(finding.get("rule_id", "UNKNOWN"))}</h3>
            <div class="finding-meta">
                <span><span class="severity {_severity_class(finding.get("severity"))}">{_html_escape(finding.get("severity", "Medium"))}</span></span>
                <span>{_html_escape(finding.get("file", ""))}:{_html_escape(finding.get("line", 0))}</span>
                <span>Finding ID: <code>{_html_escape(finding_id)}</code></span>
                <span>Status: {_html_escape(finding.get("status", "new"))}</span>
                <span>CWE: {_html_escape(cwe)}</span>
            </div>
            <p><strong>Cause:</strong> {_html_escape(finding.get("cause", ""))}</p>
            {knowledge_html}
            <p><strong>Fix suggestion:</strong> {_html_escape(fix_suggestion)}</p>
            {fixed_code_html}
            {patch_html}
            {apply_html}
            {review_html}
        </article>
    """


TOOL_REGISTRY: dict[str, AgentTool] = {
    "scan_project": AgentTool(
        name="scan_project",
        description="Run the local Aegis ProjectScanner over a project and return findings plus scan stats.",
        parameters={
            "type": "object",
            "properties": {
                "project_path": {"type": "string"},
                "ignore_patterns": {"type": "array", "items": {"type": "string"}},
                "engine": {"type": "string", "enum": ["new", "legacy"]},
            },
            "required": ["project_path"],
        },
        handler=cast(ToolHandler, scan_project_tool),
    ),
    "get_finding_detail": AgentTool(
        name="get_finding_detail",
        description="Normalize one scanner finding into report fields such as rule, CWE, file, cause, and status.",
        parameters={"type": "object", "properties": {"finding": {"type": "object"}}, "required": ["finding"]},
        handler=cast(ToolHandler, get_finding_detail_tool),
    ),
    "search_vulnerability_knowledge": AgentTool(
        name="search_vulnerability_knowledge",
        description="Search the bundled Markdown vulnerability knowledge base for CWE, OWASP, and fix context.",
        parameters={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
        handler=cast(ToolHandler, search_vulnerability_knowledge_tool),
    ),
    "generate_fix_suggestion": AgentTool(
        name="generate_fix_suggestion",
        description="Generate an offline smart remediation suggestion and optionally call the configured AI provider.",
        parameters={
            "type": "object",
            "properties": {
                "finding": {"type": "object"},
                "project_path": {"type": "string"},
                "use_ai": {"type": "boolean"},
            },
            "required": ["finding", "project_path"],
        },
        handler=cast(ToolHandler, generate_fix_suggestion_tool),
    ),
    "generate_patch_preview": AgentTool(
        name="generate_patch_preview",
        description="Create a non-mutating unified diff preview for a suggested fix.",
        parameters={
            "type": "object",
            "properties": {
                "finding": {"type": "object"},
                "fix": {"type": "object"},
                "project_path": {"type": "string"},
            },
            "required": ["finding", "fix", "project_path"],
        },
        handler=cast(ToolHandler, generate_patch_preview_tool),
    ),
    "apply_patch_preview": AgentTool(
        name="apply_patch_preview",
        description=(
            "Validate and apply one report patch preview after explicit confirmation; "
            "dry-run by default and refuses stale or out-of-project targets."
        ),
        parameters={
            "type": "object",
            "properties": {
                "report_path": {"type": "string"},
                "finding_id": {"type": "string"},
                "project_path": {"type": "string"},
                "confirm": {"type": "boolean"},
                "rescan": {"type": "boolean"},
            },
            "required": ["report_path", "finding_id"],
        },
        handler=cast(ToolHandler, apply_patch_preview_tool),
    ),
    "load_project_memory": AgentTool(
        name="load_project_memory",
        description="Load baseline and source suppression state as project-level memory without writing files.",
        parameters={"type": "object", "properties": {"project_path": {"type": "string"}}, "required": ["project_path"]},
        handler=cast(ToolHandler, load_project_memory_tool),
    ),
    "summarize_report": AgentTool(
        name="summarize_report",
        description="Create the final structured Aegis Agent diagnosis report.",
        parameters={"type": "object", "properties": {"project_path": {"type": "string"}}, "required": ["project_path"]},
        handler=cast(ToolHandler, summarize_report_tool),
    ),
}


def get_tool_schemas() -> list[dict[str, Any]]:
    """Return OpenAI-style schemas for all Agent tools."""
    return [tool.to_openai_schema() for tool in TOOL_REGISTRY.values()]


def render_tool_schemas_markdown() -> str:
    """Render Agent tool metadata as Markdown for demos and documentation."""
    lines = [
        "# Aegis Agent Tool Schemas",
        "",
        "These tools are exposed as OpenAI-style function-calling schemas.",
        "",
    ]
    for tool in TOOL_REGISTRY.values():
        required = tool.parameters.get("required", [])
        properties = tool.parameters.get("properties", {})
        lines.extend(
            [
                f"## `{tool.name}`",
                "",
                tool.description,
                "",
                f"- Required: {', '.join(f'`{item}`' for item in required) if required else 'none'}",
                "- Parameters:",
            ]
        )
        if properties:
            for name, schema in properties.items():
                schema_type = schema.get("type", "object") if isinstance(schema, dict) else "object"
                lines.append(f"  - `{name}`: `{schema_type}`")
        else:
            lines.append("  - none")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_patch_apply_result_markdown(result: dict[str, Any]) -> str:
    """Render the guarded patch application result for CLI use."""
    lines = [
        "# Aegis Agent Apply Fix",
        "",
        f"- Status: `{result.get('status', '')}`",
        f"- Finding: `{result.get('finding_id', '')}`",
        f"- Mutates files: {str(result.get('mutates_files', False)).lower()}",
        f"- Dry run: {str(result.get('dry_run', True)).lower()}",
        f"- Reason: {result.get('reason', '')}",
    ]
    if result.get("file"):
        lines.extend(
            [
                f"- File: `{result.get('file', '')}`",
                f"- Lines: {result.get('start_line', '')}-{result.get('end_line', '')}",
            ]
        )
    diff = str(result.get("unified_diff") or "").rstrip()
    if diff:
        lines.extend(["", "```diff", diff, "```"])
    rescan = result.get("rescan", {})
    if isinstance(rescan, dict) and rescan:
        lines.extend(
            [
                "",
                "## Rescan Verification",
                "",
                f"- Status: `{rescan.get('status', '')}`",
                f"- Target finding present: {str(rescan.get('target_finding_present', 'n/a')).lower()}",
                f"- Total findings: {rescan.get('total_findings', 'n/a')}",
                f"- Partial scan: {str(rescan.get('partial', False)).lower()}",
                f"- Scan errors: {rescan.get('error_count', 0)}",
                f"- Reason: {rescan.get('reason', '')}",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def dumps_report_json(report: dict[str, Any]) -> str:
    """Render report JSON consistently."""
    return json.dumps(report, indent=2, ensure_ascii=False, sort_keys=False)


__all__ = [
    "AgentTool",
    "TOOL_REGISTRY",
    "apply_patch_preview_tool",
    "dumps_report_json",
    "generate_fix_suggestion_tool",
    "generate_patch_preview_tool",
    "get_finding_detail_tool",
    "get_tool_schemas",
    "load_project_memory_tool",
    "render_patch_apply_result_markdown",
    "make_finding_id",
    "render_tool_schemas_markdown",
    "render_markdown_report",
    "render_html_report",
    "scan_project_tool",
    "search_vulnerability_knowledge_tool",
    "summarize_report_tool",
]
