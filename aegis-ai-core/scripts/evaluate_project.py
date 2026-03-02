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
import json
import sys
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.scanner.benchmark import (
    evaluate_project_against_ground_truth,
    format_report_md,
    format_report_json,
    run_benchmark,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="阶段四：对真实项目扫描结果与 ground-truth 对比，输出评估报告",
    )
    parser.add_argument("--project-dir", type=Path, required=True, help="项目根目录")
    parser.add_argument("--ground-truth", type=Path, required=True, help="ground-truth JSON 文件路径")
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "reports", help="报告输出目录")
    parser.add_argument("--target-name", type=str, default=None, help="报告中的目标名称，默认用项目目录名")
    parser.add_argument("--engine", type=str, default="new", help="扫描引擎")
    args = parser.parse_args()

    project_dir = Path(args.project_dir)
    gt_path = Path(args.ground_truth)
    if not project_dir.is_dir():
        print(f"错误: 项目目录不存在: {project_dir}")
        sys.exit(1)
    if not gt_path.is_file():
        print(f"错误: ground-truth 文件不存在: {gt_path}")
        sys.exit(1)

    with open(gt_path, "r", encoding="utf-8") as f:
        ground_truth = json.load(f)
    if not isinstance(ground_truth, list):
        ground_truth = ground_truth.get("expected", ground_truth) if isinstance(ground_truth, dict) else []
    target_name = args.target_name or project_dir.name

    print(f"扫描项目: {project_dir}")
    print(f"Ground-truth: {gt_path} ({len(ground_truth)} 条预期)")
    result = evaluate_project_against_ground_truth(project_dir, ground_truth, engine=args.engine)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")
    md_path = args.output_dir / f"evaluate_{target_name}_{date_str}.md"
    json_path = args.output_dir / f"evaluate_{target_name}_{date_str}.json"

    md_path.write_text(
        format_report_md(result, target_name=target_name, date_str=date_str),
        encoding="utf-8",
    )
    json_path.write_text(
        json.dumps(format_report_json(result, target_name=target_name, date_str=date_str), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"报告: {md_path}")
    print(f"JSON: {json_path}")
    print(f"Recall: {result.recall:.1%}, Precision: {result.precision:.1%}, F1: {result.f1:.2f}")


if __name__ == "__main__":
    main()
