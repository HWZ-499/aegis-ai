#!/usr/bin/env python3
"""
Per-language rule-sample metrics for phased scanner optimization.

Usage (from aegis-ai-core):
  python scripts/benchmark/phase_metrics.py --language javascript
  python scripts/benchmark/phase_metrics.py --language python --output reports/phase2_python_metrics_2026-04-18.md
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

# script location: scripts/benchmark/phase_metrics.py
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.scanner.benchmark import run_rule_sample_benchmark


def collect_from_rule_samples(rules_dir: Path, language: str | None = None) -> dict[str, dict[str, int]]:
    """
    Collect TP/TN/FP/FN stats from tests/rules samples, optionally filtered by language.
    """
    return run_rule_sample_benchmark(rules_dir, language=language).by_language


def render_summary(stats: dict[str, dict[str, int]]) -> None:
    for language in sorted(stats):
        s = stats[language]
        tp = s["tp"]
        tn = s["tn"]
        fp = s["fp"]
        fn = s["fn"]
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        print(
            f"{language}: tp={tp} tn={tn} fp={fp} fn={fn} recall={recall:.1%} precision={precision:.1%} fpr={fpr:.1%}"
        )


def write_markdown_report(stats: dict[str, dict[str, int]], output_path: Path, title: str | None = None) -> Path:
    report_title = title or "Phase Language Metrics"
    lines = [
        f"# {report_title}",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "| Language | TP | TN | FP | FN | Recall | Precision | FPR |",
        "|----------|---:|---:|---:|---:|-------:|----------:|----:|",
    ]

    for language in sorted(stats):
        s = stats[language]
        tp = s["tp"]
        tn = s["tn"]
        fp = s["fp"]
        fn = s["fn"]
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        lines.append(f"| {language} | {tp} | {tn} | {fp} | {fn} | {recall:.1%} | {precision:.1%} | {fpr:.1%} |")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect per-language TP/TN/FP/FN from tests/rules samples")
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=PROJECT_ROOT / "tests" / "rules",
        help="Rule sample root directory (default: tests/rules)",
    )
    parser.add_argument(
        "--language",
        type=str,
        default=None,
        help="Optional language filter: javascript|python|php|java|go (aliases: js/ts/typescript)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional markdown output path",
    )
    parser.add_argument(
        "--title",
        type=str,
        default=None,
        help="Optional report title",
    )
    args = parser.parse_args()

    stats = collect_from_rule_samples(args.rules_dir, args.language)
    if not stats:
        print("No matching sample cases found.")
        return

    render_summary(stats)
    if args.output:
        report_path = write_markdown_report(stats, args.output, title=args.title)
        print(f"Markdown report: {report_path}")


if __name__ == "__main__":
    main()
