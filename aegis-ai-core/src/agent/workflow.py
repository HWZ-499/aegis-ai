"""LangGraph workflow for Aegis Agent diagnosis."""

from __future__ import annotations

import time
from typing import Any, TypedDict, cast

from src.agent.tools import (
    Finding,
    generate_fix_suggestion_tool,
    generate_patch_preview_tool,
    get_finding_detail_tool,
    load_project_memory_tool,
    scan_project_tool,
    search_vulnerability_knowledge_tool,
    summarize_report_tool,
)
from src.scanner.ai_analyzer import AIAnalyzer

WORKFLOW_NODES = ["scan", "analyze", "retrieve", "fix", "review", "summarize"]
WORKFLOW_EDGES = [
    ("START", "scan"),
    ("scan", "analyze"),
    ("analyze", "retrieve"),
    ("retrieve", "fix"),
    ("fix", "review"),
    ("review", "summarize"),
    ("summarize", "END"),
]
WORKFLOW_NODE_TOOLS = {
    "scan": ["scan_project"],
    "analyze": ["load_project_memory", "get_finding_detail"],
    "retrieve": ["search_vulnerability_knowledge"],
    "fix": ["generate_fix_suggestion", "generate_patch_preview"],
    "review": ["review_safety_notes"],
    "summarize": ["summarize_report"],
}


class AgentDependencyError(RuntimeError):
    """Raised when optional Agent dependencies are missing."""


class AgentState(TypedDict, total=False):
    """State passed through the LangGraph workflow."""

    project_path: str
    baseline_path: str | None
    top_k: int
    use_ai: bool
    ignore_patterns: list[str] | None
    no_cache: bool
    no_parallel: bool
    max_workers: int | None
    engine: str
    rules_dirs: list[str] | None
    ai_analyzer: AIAnalyzer | None
    scan: dict[str, Any]
    stats: dict[str, Any]
    findings: list[Finding]
    memory: dict[str, Any]
    workflow_nodes: list[str]
    tool_trace: list[dict[str, Any]]
    report: dict[str, Any]


def _load_langgraph() -> tuple[Any, Any, Any]:
    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError as exc:
        raise AgentDependencyError("LangGraph is required. Install with: pip install -e .[agent]") from exc
    return StateGraph, START, END


def _copy_state(state: AgentState) -> AgentState:
    copied = dict(state)
    copied["workflow_nodes"] = list(state.get("workflow_nodes", []))
    copied["tool_trace"] = list(state.get("tool_trace", []))
    copied["findings"] = [dict(finding) for finding in state.get("findings", [])]
    return cast(AgentState, copied)


def _trace(
    state: AgentState,
    node: str,
    tool: str,
    started: float,
    status: str = "ok",
    detail: str = "",
) -> None:
    state.setdefault("tool_trace", []).append(
        {
            "node": node,
            "tool": tool,
            "status": status,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "detail": detail,
        }
    )


def _record_node(state: AgentState, node: str) -> None:
    state.setdefault("workflow_nodes", []).append(node)


def _scan_node(state: AgentState) -> AgentState:
    next_state = _copy_state(state)
    _record_node(next_state, "scan")
    started = time.perf_counter()
    scan = scan_project_tool(
        project_path=next_state["project_path"],
        ignore_patterns=next_state.get("ignore_patterns"),
        no_cache=bool(next_state.get("no_cache", False)),
        no_parallel=bool(next_state.get("no_parallel", False)),
        max_workers=next_state.get("max_workers"),
        engine=str(next_state.get("engine", "new")),
        rules_dirs=next_state.get("rules_dirs"),
    )
    _trace(next_state, "scan", "scan_project", started, detail=f"{len(scan.get('findings', []))} findings")
    next_state["scan"] = scan
    next_state["stats"] = cast(dict[str, Any], scan.get("stats", {}))
    next_state["findings"] = cast(list[Finding], scan.get("findings", []))
    return next_state


def _analyze_node(state: AgentState) -> AgentState:
    next_state = _copy_state(state)
    _record_node(next_state, "analyze")

    started = time.perf_counter()
    memory = load_project_memory_tool(
        project_path=next_state["project_path"],
        findings=next_state.get("findings", []),
        baseline_path=next_state.get("baseline_path"),
    )
    _trace(next_state, "analyze", "load_project_memory", started, detail=memory.get("baseline_path", ""))
    next_state["memory"] = memory

    detailed: list[Finding] = []
    statuses = cast(dict[str, str], memory.get("finding_status", {}))
    for finding in next_state.get("findings", []):
        status = statuses.get(str(finding.get("finding_id", "")), "new")
        started = time.perf_counter()
        detail = get_finding_detail_tool(finding, project_path=next_state["project_path"], status=status)
        _trace(next_state, "analyze", "get_finding_detail", started, detail=detail.get("finding_id", ""))
        detailed.append(detail)
    next_state["findings"] = detailed
    return next_state


def _retrieve_node(state: AgentState) -> AgentState:
    next_state = _copy_state(state)
    _record_node(next_state, "retrieve")
    enriched: list[Finding] = []
    top_k = int(next_state.get("top_k", 3))
    for finding in next_state.get("findings", []):
        query = " ".join(
            str(part)
            for part in [
                finding.get("rule_id", ""),
                finding.get("cwe", ""),
                finding.get("cause", ""),
                finding.get("language", ""),
            ]
            if part
        )
        started = time.perf_counter()
        result = search_vulnerability_knowledge_tool(
            query=query,
            vuln_type=str(finding.get("rule_id", "")),
            cwe=str(finding.get("cwe", "")),
            top_k=top_k,
        )
        _trace(next_state, "retrieve", "search_vulnerability_knowledge", started, detail=finding["finding_id"])
        item = dict(finding)
        item["knowledge"] = result.get("hits", [])
        enriched.append(item)
    next_state["findings"] = enriched
    return next_state


def _fix_node(state: AgentState) -> AgentState:
    next_state = _copy_state(state)
    _record_node(next_state, "fix")
    fixed: list[Finding] = []
    for finding in next_state.get("findings", []):
        started = time.perf_counter()
        fix = generate_fix_suggestion_tool(
            finding=finding,
            project_path=next_state["project_path"],
            use_ai=bool(next_state.get("use_ai", False)),
            ai_analyzer=next_state.get("ai_analyzer"),
        )
        _trace(next_state, "fix", "generate_fix_suggestion", started, detail=finding["finding_id"])
        started = time.perf_counter()
        patch_preview = generate_patch_preview_tool(
            finding=finding,
            fix=fix,
            project_path=next_state["project_path"],
        )
        _trace(
            next_state,
            "fix",
            "generate_patch_preview",
            started,
            detail=f"{finding['finding_id']}:{patch_preview.get('status', 'unavailable')}",
        )
        fix["patch_preview"] = patch_preview
        item = dict(finding)
        item["fix"] = fix
        fixed.append(item)
    next_state["findings"] = fixed
    return next_state


def _review_node(state: AgentState) -> AgentState:
    next_state = _copy_state(state)
    _record_node(next_state, "review")
    reviewed: list[Finding] = []
    for finding in next_state.get("findings", []):
        item = dict(finding)
        if item.get("status") == "accepted_risk":
            item["review_note"] = "Finding matches the project baseline; keep or re-review accepted risk."
        elif item.get("fix", {}).get("mode") == "ai":
            item["review_note"] = "AI generated code is a suggestion. Preview, apply explicitly, then rescan."
        else:
            item["review_note"] = "Offline remediation guidance generated. Apply manually or use existing fix preview."
        reviewed.append(item)
    next_state["findings"] = reviewed
    return next_state


def _summarize_node(state: AgentState) -> AgentState:
    next_state = _copy_state(state)
    _record_node(next_state, "summarize")
    started = time.perf_counter()
    report = summarize_report_tool(
        project_path=next_state["project_path"],
        findings=next_state.get("findings", []),
        stats=next_state.get("stats", {}),
        memory=next_state.get("memory", {}),
        workflow_nodes=next_state.get("workflow_nodes", []),
        tool_trace=next_state.get("tool_trace", []),
    )
    _trace(next_state, "summarize", "summarize_report", started, detail="report")
    report["workflow"]["tool_trace"] = next_state.get("tool_trace", [])
    next_state["report"] = report
    return next_state


def build_agent_graph() -> Any:
    """Build the LangGraph StateGraph for Aegis Agent."""
    StateGraph, START, END = _load_langgraph()
    graph = StateGraph(AgentState)
    graph.add_node("scan", _scan_node)
    graph.add_node("analyze", _analyze_node)
    graph.add_node("retrieve", _retrieve_node)
    graph.add_node("fix", _fix_node)
    graph.add_node("review", _review_node)
    graph.add_node("summarize", _summarize_node)
    graph.add_edge(START, "scan")
    graph.add_edge("scan", "analyze")
    graph.add_edge("analyze", "retrieve")
    graph.add_edge("retrieve", "fix")
    graph.add_edge("fix", "review")
    graph.add_edge("review", "summarize")
    graph.add_edge("summarize", END)
    return graph.compile()


def get_workflow_spec() -> dict[str, Any]:
    """Return a static workflow specification without requiring LangGraph import."""
    return {
        "name": "Aegis Agent Diagnosis Workflow",
        "nodes": WORKFLOW_NODES,
        "edges": [{"from": source, "to": target} for source, target in WORKFLOW_EDGES],
        "node_tools": WORKFLOW_NODE_TOOLS,
        "notes": [
            "LangGraph StateGraph runtime: START -> scan -> analyze -> retrieve -> fix -> review -> summarize -> END.",
            "The workflow generates diagnosis reports and review-only patch previews; it does not auto-edit code.",
        ],
    }


def render_workflow_mermaid() -> str:
    """Render the workflow as a Mermaid graph for docs and screenshots."""
    labels = {
        "START": "START",
        "scan": "Scan Node\\nscan_project",
        "analyze": "Analyze Node\\nfinding detail + memory",
        "retrieve": "Retrieve Node\\nknowledge search",
        "fix": "Fix Node\\nfix suggestion + patch preview",
        "review": "Review Node\\nsafety notes",
        "summarize": "Summarize Node\\nJSON / Markdown / HTML report",
        "END": "END",
    }
    lines = ["flowchart LR"]
    for source, target in WORKFLOW_EDGES:
        lines.append(f'    {source}["{labels[source]}"] --> {target}["{labels[target]}"]')
    return "\n".join(lines) + "\n"


def render_workflow_markdown() -> str:
    """Render static workflow evidence as Markdown."""
    spec = get_workflow_spec()
    lines = [
        "# Aegis Agent Workflow",
        "",
        str(spec["notes"][0]),
        str(spec["notes"][1]),
        "",
        "## Nodes",
        "",
    ]
    node_tools = cast(dict[str, list[str]], spec["node_tools"])
    for node in spec["nodes"]:
        tools = ", ".join(f"`{tool}`" for tool in node_tools.get(node, []))
        lines.append(f"- `{node}`: {tools}")
    lines.extend(["", "## Mermaid", "", "```mermaid", render_workflow_mermaid().rstrip(), "```", ""])
    return "\n".join(lines)


def run_agent_workflow(
    project_path: str,
    *,
    baseline_path: str | None = None,
    top_k: int = 3,
    use_ai: bool = False,
    ignore_patterns: list[str] | None = None,
    no_cache: bool = False,
    no_parallel: bool = False,
    max_workers: int | None = None,
    engine: str = "new",
    rules_dirs: list[str] | None = None,
    ai_analyzer: AIAnalyzer | None = None,
) -> dict[str, Any]:
    """Run the complete Agent workflow and return the structured report."""
    app = build_agent_graph()
    final_state = app.invoke(
        {
            "project_path": project_path,
            "baseline_path": baseline_path,
            "top_k": top_k,
            "use_ai": use_ai,
            "ignore_patterns": ignore_patterns,
            "no_cache": no_cache,
            "no_parallel": no_parallel,
            "max_workers": max_workers,
            "engine": engine,
            "rules_dirs": rules_dirs,
            "ai_analyzer": ai_analyzer,
            "workflow_nodes": [],
            "tool_trace": [],
            "findings": [],
        }
    )
    return cast(dict[str, Any], final_state["report"])


__all__ = [
    "AgentDependencyError",
    "AgentState",
    "build_agent_graph",
    "get_workflow_spec",
    "render_workflow_markdown",
    "render_workflow_mermaid",
    "run_agent_workflow",
]
