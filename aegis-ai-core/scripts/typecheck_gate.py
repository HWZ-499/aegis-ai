"""Layered mypy gate for CI.

This keeps release-blocking type checks focused on maintained surfaces while
still producing a visibility report for older modules with known type debt.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

TYPECHECK_GROUPS: dict[str, list[str]] = {
    "ci": [
        "src/lsp/",
        "src/analysis/base/",
        "src/analysis/dependency_tracker.py",
        "src/analysis/rule_engine.py",
        "src/analysis/incremental_analyzer.py",
        "src/core/models.py",
        "src/scanner/cli.py",
        "src/scanner/project_scanner.py",
        "src/scanner/baseline.py",
        "src/scanner/ai_analyzer.py",
        "src/scanner/report_generator.py",
    ],
    "legacy-report": [
        "src/analysis/security_rules.py",
        "src/analysis/multi_language_ast.py",
        "src/analysis/cfg/dominator_tree.py",
        "src/analysis/taint/taint_graph.py",
        "src/analysis/taint/taint_analyzer.py",
        "src/analysis/taint/cross_file_analyzer.py",
        "src/core/models.py",
        "src/scanner/report_generator.py",
        "src/scanner/taint_enhancer.py",
        "src/scanner/cli.py",
        "src/scanner/smart_remediation.py",
        "src/scanner/rag_enhancer.py",
    ],
}


def resolve_typecheck_targets(group: str) -> list[str]:
    """Return a validated target list for a named typecheck group."""
    if group not in TYPECHECK_GROUPS:
        valid = ", ".join(sorted(TYPECHECK_GROUPS))
        raise ValueError(f"Unknown typecheck group: {group}. Valid groups: {valid}")
    return list(TYPECHECK_GROUPS[group])


def run_typecheck(group: str, report_file: Path | None = None) -> int:
    """Run mypy for the requested group and optionally persist the output."""
    repo_root = Path(__file__).resolve().parents[1]
    targets = resolve_typecheck_targets(group)
    command = [
        sys.executable,
        "-m",
        "mypy",
        "--config-file",
        "pyproject.toml",
        "--follow-imports=skip",
        *targets,
    ]

    completed = subprocess.run(
        command,
        cwd=repo_root,
        text=True,
        capture_output=report_file is not None,
        check=False,
    )

    if report_file is not None:
        report_file.parent.mkdir(parents=True, exist_ok=True)
        report_file.write_text((completed.stdout or "") + (completed.stderr or ""), encoding="utf-8")

    return completed.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Run layered mypy checks for Aegis.")
    parser.add_argument("--group", default="ci", choices=sorted(TYPECHECK_GROUPS))
    parser.add_argument("--report-file", type=Path, default=None)
    args = parser.parse_args()
    return run_typecheck(args.group, report_file=args.report_file)


if __name__ == "__main__":
    raise SystemExit(main())
