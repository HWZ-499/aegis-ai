"""Repository-wide mypy gate for CI."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

TYPECHECK_GROUPS: dict[str, list[str]] = {
    "ci": ["src/"],
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
