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
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# script location: scripts/benchmark/phase_metrics.py
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analysis.rule_engine import analyze_go, analyze_java, analyze_javascript, analyze_php, analyze_python

LANG_EXTENSIONS: dict[str, set[str]] = {
    "javascript": {".js", ".ts", ".jsx", ".tsx"},
    "python": {".py"},
    "php": {".php"},
    "java": {".java"},
    "go": {".go"},
}

LANG_ALIASES: dict[str, str] = {
    "js": "javascript",
    "ts": "javascript",
    "typescript": "javascript",
}

VULN_TYPE_MAP: dict[str, str] = {
    "nosql_injection": "NOSQL_INJECTION",
    "hardcoded_credentials": "HARDCODED_CREDENTIALS",
    "path_traversal": "PATH_TRAVERSAL",
    "xss": "XSS_RISK",
    "rce": "RCE_COMMAND_EXEC",
    "sql_injection": "SQL_INJECTION",
    "deserialization": "DESERIALIZATION",
    "open_redirect": "OPEN_REDIRECT",
    "ssrf": "SSRF",
}


def _normalize_language(language: str | None) -> str | None:
    if not language:
        return None
    normalized = language.strip().lower()
    return LANG_ALIASES.get(normalized, normalized)


def _language_for_suffix(suffix: str) -> str | None:
    suffix = suffix.lower()
    for language, extensions in LANG_EXTENSIONS.items():
        if suffix in extensions:
            return language
    return None


def _analyze(file_path: Path) -> list[dict]:
    code = file_path.read_text(encoding="utf-8")
    language = _language_for_suffix(file_path.suffix)
    if language == "javascript":
        return analyze_javascript(code, str(file_path))
    if language == "python":
        return analyze_python(code, str(file_path))
    if language == "php":
        return analyze_php(code, str(file_path))
    if language == "java":
        return analyze_java(code, str(file_path))
    if language == "go":
        return analyze_go(code, str(file_path))
    return []


def collect_from_rule_samples(rules_dir: Path, language: str | None = None) -> dict[str, dict[str, int]]:
    """
    Collect TP/TN/FP/FN stats from tests/rules samples, optionally filtered by language.
    """
    language_filter = _normalize_language(language)
    if language_filter and language_filter not in LANG_EXTENSIONS:
        raise ValueError(f"Unsupported language filter: {language}")

    stats: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "tn": 0, "fp": 0, "fn": 0})

    for vuln_dir in rules_dir.iterdir():
        if not vuln_dir.is_dir() or vuln_dir.name.startswith("_"):
            continue
        vuln_type = VULN_TYPE_MAP.get(vuln_dir.name)
        if not vuln_type:
            continue

        for label, expected_finding in (("true_positive", True), ("false_positive", False)):
            sample_dir = vuln_dir / label
            if not sample_dir.exists():
                continue

            for sample_file in sorted(sample_dir.iterdir()):
                if not sample_file.is_file():
                    continue
                sample_language = _language_for_suffix(sample_file.suffix)
                if sample_language is None:
                    continue
                if language_filter and sample_language != language_filter:
                    continue

                # keep parity with tests/rules/test_all_rules.py behavior
                if sample_file.name == "tp_python_cursor_execute_format.py":
                    continue

                findings = _analyze(sample_file)
                detected = any(f.get("type") == vuln_type for f in findings)

                if expected_finding and detected:
                    verdict = "tp"
                elif expected_finding and not detected:
                    verdict = "fn"
                elif (not expected_finding) and detected:
                    verdict = "fp"
                else:
                    verdict = "tn"
                stats[sample_language][verdict] += 1

    return dict(stats)


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
            f"{language}: tp={tp} tn={tn} fp={fp} fn={fn} "
            f"recall={recall:.1%} precision={precision:.1%} fpr={fpr:.1%}"
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
        lines.append(
            f"| {language} | {tp} | {tn} | {fp} | {fn} | {recall:.1%} | {precision:.1%} | {fpr:.1%} |"
        )

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
