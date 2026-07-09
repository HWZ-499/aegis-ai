#!/usr/bin/env python3
"""
降低误报改进方案 - 回归扫描脚本。

1. 跑自建基准，输出 Recall/Precision/F1。
2. 可选：对 NodeGoat、Juice Shop 全量扫一次，输出按类型统计并保存 HTML 报告，
   便于对比改进前后发现数与误报样本。

用法（在 aegis-ai-core 目录）:
  python scripts/run_regression_scan.py
  python scripts/run_regression_scan.py --nodegoat C:\\NodeGoat
  python scripts/run_regression_scan.py --nodegoat C:\\NodeGoat --juice-shop C:\\juice-shop
  set NODEGOAT_PATH=C:\\NodeGoat & python scripts/run_regression_scan.py

输出:
  - reports/benchmark_report_YYYY-MM-DD.md 与 .json
  - reports/regression_summary_YYYY-MM-DD.md（含基准指标 + 各项目按类型统计）
  - 若指定项目路径：reports/nodegoat-report_YYYY-MM-DD.html、juice-shop-report_YYYY-MM-DD.html
"""

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.scanner.benchmark import run_and_save_report
from src.scanner.report_generator import ReportGenerator


def _scan_project_and_stats(project_path: Path, use_cache: bool = True) -> tuple[dict, dict, dict]:
    """对项目全量扫描，返回 (按类型统计, results 字典, stats)。"""
    from src.scanner.project_scanner import ProjectScanner

    scanner = ProjectScanner(str(project_path), use_cache=use_cache)
    results = scanner.scan_project(verbose=False)
    stats = scanner.get_stats()
    all_findings = []
    for file_findings in results.values():
        all_findings.extend(file_findings)
    by_type: dict = {}
    for f in all_findings:
        t = f.get("type", "UNKNOWN")
        by_type[t] = by_type.get(t, 0) + 1
    return by_type, results, stats


def main() -> None:
    parser = argparse.ArgumentParser(
        description="降低误报改进方案 - 回归：基准 + 可选 NodeGoat/Juice Shop 全量扫描",
    )
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "reports", help="报告输出目录")
    parser.add_argument("--nodegoat", type=Path, default=None, help="NodeGoat 项目路径（可选）")
    parser.add_argument("--juice-shop", type=Path, default=None, help="Juice Shop 项目路径（可选）")
    parser.add_argument("--no-cache", action="store_true", help="扫描项目时禁用缓存")
    args = parser.parse_args()

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")

    # 1. 自建基准
    print("=" * 60)
    print("1. 自建基准")
    print("=" * 60)
    md_path, json_path, result = run_and_save_report(
        output_dir=output_dir,
        target_name="自建基准",
    )
    print(f"报告: {md_path}")
    print(f"Recall: {result.recall:.1%}, Precision: {result.precision:.1%}, F1: {result.f1:.2f}")

    # 2. 可选项目扫描（参数优先，其次环境变量）
    nodegoat_path = args.nodegoat or (os.environ.get("NODEGOAT_PATH") and Path(os.environ["NODEGOAT_PATH"]))
    juice_path = args.juice_shop or (os.environ.get("JUICESHOP_PATH") and Path(os.environ["JUICESHOP_PATH"]))

    lines = [
        f"# 回归扫描摘要 {date_str}",
        "",
        "## 自建基准",
        f"- Recall: {result.recall:.1%}",
        f"- Precision: {result.precision:.1%}",
        f"- F1: {result.f1:.2f}",
        "",
        "## 项目扫描",
    ]

    if nodegoat_path and nodegoat_path.exists():
        print("\n2. NodeGoat 全量扫描")
        try:
            by_type, results, stats = _scan_project_and_stats(nodegoat_path, use_cache=not args.no_cache)
            total = sum(by_type.values())
            print(f"   共 {total} 条发现")
            for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
                print(f"   {t}: {c}")
            lines.append(f"\n### NodeGoat ({nodegoat_path})")
            lines.append(f"- 总发现数: {total}")
            for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
                lines.append(f"- {t}: {c}")
            html_path = output_dir / f"nodegoat-report_{date_str}.html"
            gen = ReportGenerator("NodeGoat")
            html_content = gen.generate_html(results, stats)
            html_path.write_text(html_content, encoding="utf-8")
            print(f"   报告: {html_path}")
            lines.append(f"- 报告: {html_path.name}")
        except Exception as e:
            print(f"   NodeGoat 扫描失败: {e}", file=sys.stderr)
            lines.append(f"\n### NodeGoat: 扫描失败 - {e}")
    else:
        if nodegoat_path:
            print(f"\nNodeGoat 路径不存在: {nodegoat_path}")
        lines.append("\n### NodeGoat: 未指定或路径不存在（可设 --nodegoat 或 NODEGOAT_PATH）")

    if juice_path and juice_path.exists():
        print("\n3. Juice Shop 全量扫描")
        try:
            by_type, results, stats = _scan_project_and_stats(juice_path, use_cache=not args.no_cache)
            total = sum(by_type.values())
            print(f"   共 {total} 条发现")
            for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
                print(f"   {t}: {c}")
            lines.append(f"\n### Juice Shop ({juice_path})")
            lines.append(f"- 总发现数: {total}")
            for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
                lines.append(f"- {t}: {c}")
            html_path = output_dir / f"juice-shop-report_{date_str}.html"
            gen = ReportGenerator("Juice Shop")
            html_content = gen.generate_html(results, stats)
            html_path.write_text(html_content, encoding="utf-8")
            print(f"   报告: {html_path}")
            lines.append(f"- 报告: {html_path.name}")
        except Exception as e:
            print(f"   Juice Shop 扫描失败: {e}", file=sys.stderr)
            lines.append(f"\n### Juice Shop: 扫描失败 - {e}")
    else:
        if juice_path:
            print(f"\nJuice Shop 路径不存在: {juice_path}")
        lines.append("\n### Juice Shop: 未指定或路径不存在（可设 --juice-shop 或 JUICESHOP_PATH）")

    summary_path = output_dir / f"regression_summary_{date_str}.md"
    summary_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n回归摘要: {summary_path}")


if __name__ == "__main__":
    main()
