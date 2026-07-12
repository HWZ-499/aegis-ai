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
import os
import platform
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_REPORT_DIR = PROJECT_ROOT / "scripts" / "reports"
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


@dataclass(frozen=True)
class GitWorktreeState:
    revision: str | None
    dirty: bool | None
    diff_sha256: str | None


def _git_output(path: Path, args: list[str], *, text: bool) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(path), *args],
        check=False,
        capture_output=True,
        text=text,
    )


def _is_scanner_cache_path(raw_relative_path: bytes) -> bool:
    """Return whether an untracked path is scanner-owned cache, not target source."""
    normalized = os.fsdecode(raw_relative_path).replace("\\", "/")
    return ".aegis-cache" in PurePosixPath(normalized).parts


def _meaningful_untracked_paths(repository_root: Path) -> list[bytes] | None:
    untracked = _git_output(
        repository_root,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        text=False,
    )
    if untracked.returncode != 0:
        return None
    return sorted(
        raw_path
        for raw_path in filter(None, (untracked.stdout or b"").split(b"\0"))
        if not _is_scanner_cache_path(raw_path)
    )


def _git_worktree_diff_sha256(repository_root: Path, untracked_paths: list[bytes]) -> str | None:
    """Fingerprint tracked changes plus meaningful untracked paths and contents."""
    digest = hashlib.sha256()
    diff = _git_output(repository_root, ["diff", "--binary", "--no-ext-diff", "HEAD", "--"], text=False)
    if diff.returncode != 0:
        return None
    digest.update(diff.stdout or b"")
    for raw_relative_path in untracked_paths:
        digest.update(b"\0untracked\0")
        digest.update(raw_relative_path)
        candidate = repository_root / os.fsdecode(raw_relative_path)
        if candidate.is_file():
            digest.update(b"\0content\0")
            digest.update(candidate.read_bytes())
    return digest.hexdigest()


def _git_worktree_state(path: Path, *, allow_parent_repository: bool) -> GitWorktreeState:
    """Return revision and dirty fingerprint, rejecting accidental parent repos for targets."""
    try:
        root_result = _git_output(path, ["rev-parse", "--show-toplevel"], text=True)
        revision_result = _git_output(path, ["rev-parse", "HEAD"], text=True)
    except OSError:
        return GitWorktreeState(None, None, None)
    if root_result.returncode != 0 or revision_result.returncode != 0:
        return GitWorktreeState(None, None, None)

    repository_root = Path(root_result.stdout.strip()).resolve()
    if not allow_parent_repository and repository_root != path.resolve():
        return GitWorktreeState(None, None, None)

    tracked_diff = _git_output(repository_root, ["diff", "--quiet", "HEAD", "--"], text=False)
    untracked_paths = _meaningful_untracked_paths(repository_root)
    if tracked_diff.returncode not in {0, 1} or untracked_paths is None:
        return GitWorktreeState(revision_result.stdout.strip() or None, None, None)
    dirty = tracked_diff.returncode == 1 or bool(untracked_paths)
    return GitWorktreeState(
        revision=revision_result.stdout.strip() or None,
        dirty=dirty,
        diff_sha256=_git_worktree_diff_sha256(repository_root, untracked_paths) if dirty else None,
    )


def _git_revision(path: Path) -> str | None:
    """Compatibility helper returning the nearest checked-out revision."""
    return _git_worktree_state(path, allow_parent_repository=True).revision


def _display_path(path: Path) -> str:
    """Prefer a repository-relative ground-truth path in published reports."""
    try:
        return path.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError:
        return path.name


def build_provenance(
    project_dir: Path,
    ground_truth_path: Path,
    engine: str,
    *,
    target_repository_root: Path | None = None,
) -> dict[str, str | bool | None]:
    """Capture revisions and dirty-state fingerprints for every report input."""
    scanner_state = _git_worktree_state(PROJECT_ROOT, allow_parent_repository=True)
    provenance_root = target_repository_root or project_dir
    target_state = _git_worktree_state(provenance_root, allow_parent_repository=False)
    try:
        target_subdir = project_dir.resolve().relative_to(provenance_root.resolve()).as_posix() or "."
    except ValueError:
        target_subdir = None
    reproducible = bool(
        scanner_state.revision
        and scanner_state.dirty is False
        and target_state.revision
        and target_state.dirty is False
    )
    return {
        "engine": engine,
        "reproducible": reproducible,
        "scanner_revision": scanner_state.revision,
        "scanner_dirty": scanner_state.dirty,
        "scanner_diff_sha256": scanner_state.diff_sha256,
        "target_revision": target_state.revision,
        "target_subdir": target_subdir,
        "target_dirty": target_state.dirty,
        "target_diff_sha256": target_state.diff_sha256,
        "ground_truth": _display_path(ground_truth_path),
        "ground_truth_sha256": _sha256_file(ground_truth_path),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or None,
    }


def format_provenance_md(provenance: dict[str, str | bool | None]) -> str:
    def value(key: str) -> str:
        raw_value = provenance.get(key)
        if isinstance(raw_value, bool):
            return "yes" if raw_value else "no"
        return str(raw_value) if raw_value else "unavailable"

    return "\n".join(
        [
            "---",
            "",
            "## Reproducibility",
            "",
            f"- Clean release baseline: `{value('reproducible')}`",
            f"- Engine: `{value('engine')}`",
            f"- Scanner revision: `{value('scanner_revision')}`",
            f"- Scanner dirty: `{value('scanner_dirty')}`",
            f"- Scanner diff SHA-256: `{value('scanner_diff_sha256')}`",
            f"- Target revision: `{value('target_revision')}`",
            f"- Target subdirectory: `{value('target_subdir')}`",
            f"- Target dirty: `{value('target_dirty')}`",
            f"- Target diff SHA-256: `{value('target_diff_sha256')}`",
            f"- Ground truth: `{value('ground_truth')}`",
            f"- Ground truth SHA-256: `{value('ground_truth_sha256')}`",
            f"- Python: `{value('python_version')}`",
            f"- Platform: `{value('platform')}`",
            f"- Processor: `{value('processor')}`",
            "",
        ]
    )


def _process_memory_mb() -> tuple[float | None, float | None]:
    """Return current RSS and process-lifetime peak RSS when psutil exposes them."""
    try:
        import psutil
    except ImportError:
        return None, None

    try:
        info = psutil.Process(os.getpid()).memory_info()
    except (OSError, psutil.Error):
        return None, None
    rss_mb = info.rss / (1024 * 1024)
    peak_bytes = getattr(info, "peak_wset", None)
    peak_mb = peak_bytes / (1024 * 1024) if isinstance(peak_bytes, int) else None
    return rss_mb, peak_mb


def format_performance_md(performance: dict[str, float | None]) -> str:
    def metric(key: str) -> str:
        value = performance.get(key)
        return f"{value:.3f}" if value is not None else "unavailable"

    return "\n".join(
        [
            "---",
            "",
            "## Performance",
            "",
            f"- Scan duration: `{metric('scan_duration_seconds')} s`",
            f"- RSS before scan: `{metric('rss_before_mb')} MiB`",
            f"- RSS after scan: `{metric('rss_after_mb')} MiB`",
            f"- RSS delta: `{metric('rss_delta_mb')} MiB`",
            f"- Process peak RSS: `{metric('process_peak_rss_mb')} MiB`",
            "",
            "Peak RSS is the lifetime peak of this standalone evaluator process.",
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
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_REPORT_DIR, help="报告输出目录")
    parser.add_argument("--target-name", type=str, default=None, help="报告中的目标名称，默认用项目目录名")
    parser.add_argument(
        "--target-repository-root",
        type=Path,
        default=None,
        help="项目目录是 Git 仓库子目录时，显式指定用于 provenance 的仓库根目录",
    )
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
    parser.add_argument(
        "--require-clean",
        action="store_true",
        help="仅允许扫描器和目标项目均为可识别的干净 Git 工作区时产出报告",
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
    target_repository_root = Path(args.target_repository_root) if args.target_repository_root else None
    if target_repository_root is not None:
        if not target_repository_root.is_dir():
            print(f"错误: 目标仓库根目录不存在: {target_repository_root}")
            sys.exit(1)
        try:
            project_dir.resolve().relative_to(target_repository_root.resolve())
        except ValueError:
            print(f"错误: 项目目录不在目标仓库根目录内: {project_dir}")
            sys.exit(1)

    with open(gt_path, encoding="utf-8") as f:
        ground_truth = json.load(f)
    if not isinstance(ground_truth, list):
        ground_truth = ground_truth.get("expected", ground_truth) if isinstance(ground_truth, dict) else []
    target_name = args.target_name or project_dir.name
    provenance = build_provenance(
        project_dir,
        gt_path,
        args.engine,
        target_repository_root=target_repository_root,
    )
    if args.require_clean and provenance["reproducible"] is not True:
        print("错误: 正式基线要求扫描器和目标项目均为可识别的干净 Git 工作区。")
        print(format_provenance_md(provenance))
        sys.exit(2)
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
    rss_before_mb, _ = _process_memory_mb()
    scan_started = time.perf_counter()
    result = evaluate_project_against_ground_truth(project_dir, evaluated_ground_truth, engine=args.engine)
    scan_duration_seconds = time.perf_counter() - scan_started
    rss_after_mb, process_peak_rss_mb = _process_memory_mb()
    performance = {
        "scan_duration_seconds": round(scan_duration_seconds, 6),
        "rss_before_mb": round(rss_before_mb, 3) if rss_before_mb is not None else None,
        "rss_after_mb": round(rss_after_mb, 3) if rss_after_mb is not None else None,
        "rss_delta_mb": (
            round(rss_after_mb - rss_before_mb, 3) if rss_before_mb is not None and rss_after_mb is not None else None
        ),
        "process_peak_rss_mb": round(process_peak_rss_mb, 3) if process_peak_rss_mb is not None else None,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")
    md_path = args.output_dir / f"evaluate_{target_name}_{date_str}.md"
    json_path = args.output_dir / f"evaluate_{target_name}_{date_str}.json"

    md_path.write_text(
        "\n".join(
            [
                format_report_md(result, target_name=target_name, date_str=date_str),
                format_scope_md(len(ground_truth), len(evaluated_ground_truth), excluded_entries, invalid_entries),
                format_performance_md(performance),
                format_provenance_md(provenance),
            ]
        ),
        encoding="utf-8",
    )
    report_json = format_report_json(result, target_name=target_name, date_str=date_str)
    report_json["scope"] = scope
    report_json["performance"] = performance
    report_json["provenance"] = provenance
    json_path.write_text(
        json.dumps(report_json, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"报告: {md_path}")
    print(f"JSON: {json_path}")
    print(f"Recall: {result.recall:.1%}, Precision: {result.precision:.1%}, F1: {result.f1:.2f}")
    print(
        f"Scan: {performance['scan_duration_seconds']:.3f}s, "
        f"peak RSS: {performance['process_peak_rss_mb'] or 'unavailable'} MiB"
    )


if __name__ == "__main__":
    main()
