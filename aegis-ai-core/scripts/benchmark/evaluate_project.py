#!/usr/bin/env python3
"""
阶段四：真实项目基准评估脚本。

对指定项目目录扫描，与 ground-truth（预期漏洞列表）对比，
输出 Recall / Precision / F1 及与自建基准同格式的 Markdown/JSON 报告。

Ground-truth JSON 格式：
  [
    { "file": "路径或后缀，如 login.js 或 *route*", "line": 行号, "type": "NOSQL_INJECTION" },
    ...
  ]

用法（在 aegis-ai-core 目录）:
  python scripts/evaluate_project.py --project-dir C:\\NodeGoat --ground-truth scripts/ground_truth_nodegoat_example.json
  python scripts/evaluate_project.py --project-dir C:\\NodeGoat --ground-truth scripts/ground_truth_nodegoat_example.json --output-dir reports
"""

import argparse
import fnmatch
import hashlib
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.scanner.benchmark import (
    _expected_ground_truth_lines,
    evaluate_project_against_ground_truth,
    format_report_json,
    format_report_md,
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_revision(path: Path) -> str | None:
    """Return the checked-out revision for a local Git repository, if available."""
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    revision = result.stdout.strip()
    return revision or None


def _display_path(path: Path) -> str:
    """Prefer a repository-relative ground-truth path in published reports."""
    try:
        return path.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError:
        return path.name


def build_provenance(project_dir: Path, ground_truth_path: Path, engine: str) -> dict[str, str | None]:
    """Capture the immutable inputs needed to reproduce a project-quality report."""
    return {
        "engine": engine,
        "scanner_revision": _git_revision(PROJECT_ROOT),
        "target_revision": _git_revision(project_dir),
        "ground_truth": _display_path(ground_truth_path),
        "ground_truth_sha256": _sha256_file(ground_truth_path),
    }


def format_provenance_md(provenance: dict[str, str | None]) -> str:
    def value(key: str) -> str:
        return provenance.get(key) or "unavailable"

    return "\n".join(
        [
            "---",
            "",
            "## Reproducibility",
            "",
            f"- Engine: `{value('engine')}`",
            f"- Scanner revision: `{value('scanner_revision')}`",
            f"- Target revision: `{value('target_revision')}`",
            f"- Ground truth: `{value('ground_truth')}`",
            f"- Ground truth SHA-256: `{value('ground_truth_sha256')}`",
            "",
        ]
    )


def split_ground_truth_scope(
    ground_truth: list[dict[str, Any]],
    *,
    include_out_of_scope: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Separate advertised-coverage cases from explicitly out-of-scope ones."""
    evaluated: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    for entry in ground_truth:
        if include_out_of_scope or entry.get("in_scope", True):
            evaluated.append(entry)
            continue
        excluded.append(
            {
                "file": str(entry.get("file", "unknown")),
                "type": str(entry.get("type", "UNKNOWN")),
                "reason": str(entry.get("scope_reason", "Not in advertised product coverage.")),
            }
        )
    return evaluated, excluded


def validate_ground_truth_locations(
    project_dir: Path,
    ground_truth: list[dict[str, Any]],
    *,
    include_invalid: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Exclude explicitly stale file/line/pattern entries while preserving their audit trail."""
    files = [
        path
        for path in project_dir.rglob("*")
        if path.is_file() and not {".git", "node_modules", "vendor"}.intersection(path.parts)
    ]
    validated: list[dict[str, Any]] = []
    invalid: list[dict[str, str]] = []

    for entry in ground_truth:
        expected_file = str(entry.get("file", ""))
        matching_files = [
            path
            for path in files
            if _ground_truth_file_matches(path.relative_to(project_dir).as_posix(), expected_file)
        ]
        reason = _ground_truth_location_error(entry, matching_files)
        if reason is None or include_invalid:
            validated.append(entry)
        if reason is not None:
            invalid.append(
                {
                    "file": expected_file or "unknown",
                    "type": str(entry.get("type", "UNKNOWN")),
                    "reason": reason,
                }
            )
    return validated, invalid


def _ground_truth_file_matches(candidate: str, expected: str) -> bool:
    normalized_expected = expected.replace("\\", "/")
    if not normalized_expected:
        return False
    if "*" in normalized_expected:
        return fnmatch.fnmatch(candidate, normalized_expected) or normalized_expected in candidate
    return candidate.endswith(normalized_expected) or normalized_expected in candidate


def _ground_truth_location_error(entry: dict[str, Any], matching_files: list[Path]) -> str | None:
    if not matching_files:
        return "No matching project file exists at this target revision."

    expected_lines = _expected_ground_truth_lines(entry)
    if not expected_lines:
        return None

    source_by_file = {path: path.read_text(encoding="utf-8", errors="replace").splitlines() for path in matching_files}
    lines_in_range = [
        (path, line)
        for path, source_lines in source_by_file.items()
        for line in expected_lines
        if 1 <= line <= len(source_lines)
    ]
    if not lines_in_range:
        return f"Expected line {expected_lines} is outside every matching file."

    expected_pattern = entry.get("expected_pattern")
    if not isinstance(expected_pattern, str) or not expected_pattern:
        return None

    line_tolerance = 3
    for path, line in lines_in_range:
        source_lines = source_by_file[path]
        start = max(0, line - 1 - line_tolerance)
        end = min(len(source_lines), line + line_tolerance)
        if any(expected_pattern in source_line for source_line in source_lines[start:end]):
            return None
    return f"Expected pattern '{expected_pattern}' is absent within {line_tolerance} lines of the annotated line."


def format_scope_md(
    input_count: int,
    evaluated_count: int,
    excluded: list[dict[str, str]],
    invalid: list[dict[str, str]] | None = None,
) -> str:
    invalid = invalid or []
    lines = [
        "---",
        "",
        "## Evaluation scope",
        "",
        f"- Ground-truth entries supplied: {input_count}",
        f"- Entries evaluated: {evaluated_count}",
        f"- Explicitly out of scope: {len(excluded)}",
        f"- Invalid at this target revision: {len(invalid)}",
    ]
    if excluded:
        lines.extend(["", "### Excluded entries"])
        for entry in excluded:
            lines.append(f"- `{entry['type']}` in `{entry['file']}`: {entry['reason']}")
    if invalid:
        lines.extend(["", "### Invalid entries"])
        for entry in invalid:
            lines.append(f"- `{entry['type']}` in `{entry['file']}`: {entry['reason']}")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="阶段四：对真实项目扫描结果与 ground-truth 对比，输出评估报告",
    )
    parser.add_argument("--project-dir", type=Path, required=True, help="项目根目录")
    parser.add_argument("--ground-truth", type=Path, required=True, help="ground-truth JSON 文件路径")
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "reports", help="报告输出目录")
    parser.add_argument("--target-name", type=str, default=None, help="报告中的目标名称，默认用项目目录名")
    parser.add_argument("--engine", choices=["new"], default="new", help="兼容参数；当前仅支持 new")
    parser.add_argument(
        "--include-out-of-scope",
        action="store_true",
        help="将 ground truth 中明确标为 in_scope=false 的条目也纳入指标（默认仅评估产品承诺覆盖范围）",
    )
    parser.add_argument(
        "--include-invalid-ground-truth",
        action="store_true",
        help="将文件、行号或 expected_pattern 已与当前靶场不匹配的标注也纳入指标（默认单列并排除）",
    )
    args = parser.parse_args()

    project_dir = Path(args.project_dir)
    gt_path = Path(args.ground_truth)
    if not project_dir.is_dir():
        print(f"错误: 项目目录不存在: {project_dir}")
        sys.exit(1)
    if not gt_path.is_file():
        print(f"错误: ground-truth 文件不存在: {gt_path}")
        sys.exit(1)

    with open(gt_path, encoding="utf-8") as f:
        ground_truth = json.load(f)
    if not isinstance(ground_truth, list):
        ground_truth = ground_truth.get("expected", ground_truth) if isinstance(ground_truth, dict) else []
    target_name = args.target_name or project_dir.name
    provenance = build_provenance(project_dir, gt_path, args.engine)
    scoped_ground_truth, excluded_entries = split_ground_truth_scope(
        ground_truth,
        include_out_of_scope=args.include_out_of_scope,
    )
    evaluated_ground_truth, invalid_entries = validate_ground_truth_locations(
        project_dir,
        scoped_ground_truth,
        include_invalid=args.include_invalid_ground_truth,
    )
    scope = {
        "input_entries": len(ground_truth),
        "evaluated_entries": len(evaluated_ground_truth),
        "include_out_of_scope": args.include_out_of_scope,
        "include_invalid_ground_truth": args.include_invalid_ground_truth,
        "excluded_entries": excluded_entries,
        "invalid_entries": invalid_entries,
    }

    print(f"扫描项目: {project_dir}")
    print(
        f"Ground-truth: {gt_path} ({len(ground_truth)} 条输入，{len(excluded_entries)} 条超出产品范围，"
        f"{len(invalid_entries)} 条与当前靶场不匹配)"
    )
    result = evaluate_project_against_ground_truth(project_dir, evaluated_ground_truth, engine=args.engine)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")
    md_path = args.output_dir / f"evaluate_{target_name}_{date_str}.md"
    json_path = args.output_dir / f"evaluate_{target_name}_{date_str}.json"

    md_path.write_text(
        "\n".join(
            [
                format_report_md(result, target_name=target_name, date_str=date_str),
                format_scope_md(len(ground_truth), len(evaluated_ground_truth), excluded_entries, invalid_entries),
                format_provenance_md(provenance),
            ]
        ),
        encoding="utf-8",
    )
    report_json = format_report_json(result, target_name=target_name, date_str=date_str)
    report_json["scope"] = scope
    report_json["provenance"] = provenance
    json_path.write_text(
        json.dumps(report_json, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"报告: {md_path}")
    print(f"JSON: {json_path}")
    print(f"Recall: {result.recall:.1%}, Precision: {result.precision:.1%}, F1: {result.f1:.2f}")


if __name__ == "__main__":
    main()
