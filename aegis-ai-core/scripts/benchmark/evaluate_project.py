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
import hashlib
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.scanner.benchmark import (
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="阶段四：对真实项目扫描结果与 ground-truth 对比，输出评估报告",
    )
    parser.add_argument("--project-dir", type=Path, required=True, help="项目根目录")
    parser.add_argument("--ground-truth", type=Path, required=True, help="ground-truth JSON 文件路径")
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "reports", help="报告输出目录")
    parser.add_argument("--target-name", type=str, default=None, help="报告中的目标名称，默认用项目目录名")
    parser.add_argument("--engine", choices=["new"], default="new", help="兼容参数；当前仅支持 new")
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

    print(f"扫描项目: {project_dir}")
    print(f"Ground-truth: {gt_path} ({len(ground_truth)} 条预期)")
    result = evaluate_project_against_ground_truth(project_dir, ground_truth, engine=args.engine)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")
    md_path = args.output_dir / f"evaluate_{target_name}_{date_str}.md"
    json_path = args.output_dir / f"evaluate_{target_name}_{date_str}.json"

    md_path.write_text(
        f"{format_report_md(result, target_name=target_name, date_str=date_str)}\n{format_provenance_md(provenance)}",
        encoding="utf-8",
    )
    report_json = format_report_json(result, target_name=target_name, date_str=date_str)
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
