#!/usr/bin/env python3
"""
阶段四：运行标准基准测试并生成量化报告。

用法（在 aegis-ai-core 目录）:
  python scripts/run_benchmark_report.py
  python scripts/run_benchmark_report.py --project-dir C:\\NodeGoat

报告输出: reports/benchmark_report_YYYY-MM-DD.md 与 .json
"""

import argparse
import sys
from pathlib import Path

# 确保 aegis-ai-core 在 path 中（__file__ 在 scripts/benchmark/ 下，需上溯两级）
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.benchmark.phase_metrics import render_summary
from src.scanner.benchmark import run_and_save_report, run_rule_sample_benchmark


def main() -> None:
    parser = argparse.ArgumentParser(description="Aegis AI 标准基准测试与量化报告")
    parser.add_argument(
        "--target-name",
        default="自建基准",
        help="报告中的目标名称",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT_ROOT / "reports",
        help="报告输出目录",
    )
    parser.add_argument(
        "--project-dir",
        type=Path,
        default=None,
        help="可选：扫描指定项目目录，将按类型统计追加到报告",
    )
    parser.add_argument(
        "--language",
        type=str,
        default=None,
        help="可选：先输出 tests/rules 中指定语言的 TP/TN/FP/FN（javascript/python/php/java/go）",
    )
    args = parser.parse_args()

    sample_result = run_rule_sample_benchmark(
        PROJECT_ROOT / "tests" / "rules",
        language=args.language,
    )
    if sample_result.by_language:
        print("规则样本质量矩阵:")
        render_summary(sample_result.by_language)
        print("")
    else:
        print(f"未找到语言 `{args.language}` 的样本。")

    md_path, json_path, result = run_and_save_report(
        output_dir=args.output_dir,
        target_name=args.target_name,
    )
    print(f"报告已生成: {md_path}")
    print(f"JSON: {json_path}")
    print(f"Recall: {result.recall:.1%}, Precision: {result.precision:.1%}, F1: {result.f1:.2f}")

    matrix_suffix = f"_{args.language.lower()}" if args.language else ""
    matrix_md, matrix_json, _ = run_and_save_report(
        output_dir=args.output_dir,
        target_name="规则样本质量矩阵",
        result=sample_result,
        file_prefix=f"quality_matrix{matrix_suffix}",
    )
    print(f"质量矩阵: {matrix_md}")
    print(f"质量矩阵 JSON: {matrix_json}")

    if args.project_dir and args.project_dir.exists():
        try:
            from src.scanner.project_scanner import ProjectScanner

            scanner = ProjectScanner(str(args.project_dir), engine="new")
            results = scanner.scan_project(verbose=False)
            all_findings = []
            for file_findings in results.values():
                all_findings.extend(file_findings)
            by_type: dict = {}
            for f in all_findings:
                t = f.get("type", "UNKNOWN")
                by_type[t] = by_type.get(t, 0) + 1
            print(f"\n项目扫描 [{args.project_dir}]: 共 {len(all_findings)} 条发现")
            for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
                print(f"  {t}: {c}")
        except Exception as e:
            print(f"项目扫描失败: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
