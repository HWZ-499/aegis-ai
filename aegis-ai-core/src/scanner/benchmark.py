"""
benchmark.py - 阶段四：标准基准测试与量化报告

提供自建 Benchmark（TP/TN 用例）运行、按漏洞类型统计、
以及路线图格式的评估报告（Recall / Precision / FPR / F1）。

用法:
  python -m src.scanner.benchmark
  python scripts/run_benchmark_report.py
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from ..analysis.languages import AnalysisLanguage, normalize_analysis_language
from ..analysis.rule_engine import analyze_source

# 用例定义（与 test_acceptance_benchmark 对齐，便于统一维护）
from .benchmark_cases import BENCH_CASES_TN, BENCH_CASES_TP, BenchCase

logger = logging.getLogger(__name__)

LANGUAGE_EXTENSIONS: dict[str, set[str]] = {
    "javascript": {".js", ".jsx"},
    "typescript": {".ts", ".tsx"},
    "python": {".py"},
    "php": {".php"},
    "java": {".java"},
    "go": {".go"},
}

VULNERABILITY_DIRECTORY_TYPES: dict[str, str] = {
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


def _empty_counts() -> dict[str, int]:
    return {"tp": 0, "tn": 0, "fp": 0, "fn": 0}


def _metrics_for_counts(counts: dict[str, int]) -> dict[str, float]:
    tp = counts["tp"]
    tn = counts["tn"]
    fp = counts["fp"]
    fn = counts["fn"]
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    fpr = fp / (tn + fp) if (tn + fp) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        "recall": recall,
        "precision": precision,
        "fpr": fpr,
        "f1": f1,
    }


def _coerce_ground_truth_line(value: Any) -> int | None:
    """Return a positive integer line number from benchmark ground-truth data."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        line = int(value)
    except (TypeError, ValueError):
        return None
    return line if line > 0 else None


def _expected_ground_truth_lines(exp: dict) -> list[int]:
    """Return de-duplicated expected lines from ``line_candidates`` and ``line``."""
    candidates: list[int] = []
    line_candidates = exp.get("line_candidates")
    raw_candidates = line_candidates if isinstance(line_candidates, list) else [line_candidates]
    for item in raw_candidates:
        line = _coerce_ground_truth_line(item)
        if line is not None:
            candidates.append(line)

    line = _coerce_ground_truth_line(exp.get("line"))
    if line is not None:
        candidates.append(line)

    deduped: list[int] = []
    seen: set[int] = set()
    for value in candidates:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


@dataclass
class BenchmarkResult:
    """基准测试汇总结果。"""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    details: list[dict] = field(default_factory=list)
    by_category: dict[str, dict[str, int]] = field(default_factory=dict)
    by_language: dict[str, dict[str, int]] = field(default_factory=dict)
    by_language_category: dict[str, dict[str, dict[str, int]]] = field(default_factory=dict)

    @property
    def recall(self) -> float:
        """检测率 = TP / (TP + FN)。"""
        if (self.tp + self.fn) <= 0:
            return 0.0
        return self.tp / (self.tp + self.fn)

    @property
    def precision(self) -> float:
        """精确率 = TP / (TP + FP)。"""
        if (self.tp + self.fp) <= 0:
            return 0.0
        return self.tp / (self.tp + self.fp)

    @property
    def fpr(self) -> float:
        """误报率 = FP / (TN + FP)。"""
        total_neg = self.tn + self.fp
        if total_neg <= 0:
            return 0.0
        return self.fp / total_neg

    @property
    def f1(self) -> float:
        """F1 = 2 * P * R / (P + R)。"""
        p, r = self.precision, self.recall
        if (p + r) <= 0:
            return 0.0
        return 2 * p * r / (p + r)

    def record(self, language: str, category: str, verdict: str) -> None:
        """Record one TP/TN/FP/FN verdict across all quality dimensions."""
        verdict_key = verdict.lower()
        if verdict_key not in {"tp", "tn", "fp", "fn"}:
            raise ValueError(f"Unsupported benchmark verdict: {verdict}")

        setattr(self, verdict_key, getattr(self, verdict_key) + 1)
        self.by_category.setdefault(category, _empty_counts())[verdict_key] += 1
        self.by_language.setdefault(language, _empty_counts())[verdict_key] += 1
        language_categories = self.by_language_category.setdefault(language, {})
        language_categories.setdefault(category, _empty_counts())[verdict_key] += 1

    def to_dict(self) -> dict:
        """便于 JSON 序列化。"""
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "recall": round(self.recall, 4),
            "precision": round(self.precision, 4),
            "fpr": round(self.fpr, 4),
            "f1": round(self.f1, 4),
            "details": self.details,
            "by_category": self.by_category,
            "by_language": self.by_language,
            "by_language_category": self.by_language_category,
        }


@dataclass(frozen=True)
class QualityThresholds:
    """Minimum quality thresholds for a benchmark regression gate."""

    min_recall: float = 0.0
    min_precision: float = 0.0
    min_f1: float = 0.0
    max_fpr: float = 1.0


def quality_gate_violations(
    result: BenchmarkResult,
    thresholds: QualityThresholds,
    *,
    per_language: bool = False,
    per_category: bool = False,
    per_language_category: bool = False,
) -> list[str]:
    """Return human-readable quality regressions without raising in library code."""

    def check(scope: str, counts: dict[str, int]) -> list[str]:
        metrics = _metrics_for_counts(counts)
        violations: list[str] = []
        checks = (
            ("recall", metrics["recall"], thresholds.min_recall, ">=", counts["tp"] + counts["fn"] > 0),
            ("precision", metrics["precision"], thresholds.min_precision, ">=", counts["tp"] + counts["fp"] > 0),
            (
                "f1",
                metrics["f1"],
                thresholds.min_f1,
                ">=",
                counts["tp"] + counts["fn"] + counts["fp"] > 0,
            ),
            ("fpr", metrics["fpr"], thresholds.max_fpr, "<=", counts["tn"] + counts["fp"] > 0),
        )
        for metric, actual, expected, operator, applicable in checks:
            if not applicable:
                continue
            failed = actual < expected if operator == ">=" else actual > expected
            if failed:
                violations.append(f"{scope} {metric}={actual:.4f} must be {operator} {expected:.4f}")
        return violations

    overall_counts = {"tp": result.tp, "tn": result.tn, "fp": result.fp, "fn": result.fn}
    violations = check("overall", overall_counts)
    if per_language:
        for language, counts in sorted(result.by_language.items()):
            violations.extend(check(f"language:{language}", counts))
    if per_category:
        for category, counts in sorted(result.by_category.items()):
            violations.extend(check(f"category:{category}", counts))
    if per_language_category:
        for language, categories in sorted(result.by_language_category.items()):
            for category, counts in sorted(categories.items()):
                violations.extend(check(f"language-category:{language}:{category}", counts))
    return violations


def run_benchmark(cases: list[BenchCase] | None = None) -> BenchmarkResult:
    """
    运行基准用例，按用例语言分发到对应 rule_engine 分析器。

    Args:
        cases: 用例列表；为 None 时使用默认 TP + TN 全集。

    Returns:
        BenchmarkResult 汇总结果。
    """
    if cases is None:
        cases = BENCH_CASES_TP + BENCH_CASES_TN

    result = BenchmarkResult()
    for case in cases:
        findings = _analyze_case(case)
        relevant = [f for f in findings if f.get("type", "") == case.category]
        detected = len(relevant) > 0

        if case.expect_finding:
            if detected:
                verdict = "TP"
            else:
                verdict = "FN"
        else:
            if detected:
                verdict = "FP"
            else:
                verdict = "TN"

        language = _normalize_language(case.language) or "javascript"
        result.record(language, case.category, verdict)
        result.details.append(
            {
                "id": case.id,
                "category": case.category,
                "language": language,
                "pattern": case.pattern,
                "description": case.description,
                "expect": "VULN" if case.expect_finding else "SAFE",
                "detected": detected,
                "verdict": verdict,
                "finding_count": len(relevant),
            }
        )

    return result


def _normalize_language(language: str | None) -> AnalysisLanguage | None:
    return cast(AnalysisLanguage | None, normalize_analysis_language(language))


def _language_for_path(file_path: Path) -> str | None:
    suffix = file_path.suffix.lower()
    for language, extensions in LANGUAGE_EXTENSIONS.items():
        if suffix in extensions:
            return language
    return None


def _analyze_source(code: str, file_path: str, language: str) -> list[dict]:
    """Route source through the same production analyzers used by CLI and LSP."""
    normalized = _normalize_language(language) or "javascript"
    return cast(list[dict], analyze_source(code, file_path, language=normalized))


def _analyze_case(case: BenchCase) -> list[dict]:
    """按语言路由到对应分析器，避免跨语言用例被误记为 FN。"""
    language = _normalize_language(case.language) or "javascript"
    suffixes = {
        "javascript": ".js",
        "typescript": ".ts",
        "python": ".py",
        "php": ".php",
        "java": ".java",
        "go": ".go",
    }
    suffix = suffixes.get(language, ".js")
    filename = f"Benchmark{suffix}" if language == "java" else f"benchmark{suffix}"
    return _analyze_source(case.code, filename, language)


def run_rule_sample_benchmark(
    rules_dir: Path,
    language: str | None = None,
) -> BenchmarkResult:
    """Evaluate the curated ``tests/rules`` corpus with one shared metric model."""
    language_filter = _normalize_language(language)
    if language_filter and language_filter not in LANGUAGE_EXTENSIONS:
        raise ValueError(f"Unsupported language filter: {language}")

    result = BenchmarkResult()
    for vulnerability_dir in sorted(rules_dir.iterdir()):
        if not vulnerability_dir.is_dir() or vulnerability_dir.name.startswith("_"):
            continue
        category = VULNERABILITY_DIRECTORY_TYPES.get(vulnerability_dir.name)
        if category is None:
            continue

        for label, expect_finding in (("true_positive", True), ("false_positive", False)):
            sample_dir = vulnerability_dir / label
            if not sample_dir.is_dir():
                continue

            for sample_file in sorted(sample_dir.iterdir()):
                if not sample_file.is_file():
                    continue
                sample_language = _language_for_path(sample_file)
                if sample_language is None:
                    continue
                if language_filter and sample_language != language_filter:
                    continue

                code = sample_file.read_text(encoding="utf-8")
                findings = _analyze_source(code, str(sample_file), sample_language)
                relevant = [finding for finding in findings if finding.get("type") == category]
                detected = bool(relevant)
                if expect_finding:
                    verdict = "TP" if detected else "FN"
                else:
                    verdict = "FP" if detected else "TN"

                result.record(sample_language, category, verdict)
                result.details.append(
                    {
                        "id": str(sample_file.relative_to(rules_dir)).replace("\\", "/"),
                        "category": category,
                        "language": sample_language,
                        "pattern": sample_file.stem,
                        "description": sample_file.name,
                        "expect": "VULN" if expect_finding else "SAFE",
                        "detected": detected,
                        "verdict": verdict,
                        "finding_count": len(relevant),
                    }
                )

    return result


def format_report_md(
    result: BenchmarkResult,
    target_name: str = "自建基准",
    date_str: str | None = None,
) -> str:
    """
    生成路线图格式的 Markdown 评估报告。

    Args:
        result: run_benchmark() 的返回值
        target_name: 报告标题中的目标名称
        date_str: 日期字符串，默认当前日期

    Returns:
        Markdown 字符串
    """
    if date_str is None:
        date_str = datetime.now().strftime("%Y-%m-%d")

    total_expected_pos = result.tp + result.fn
    total_expected_neg = result.tn + result.fp
    total_found = result.tp + result.fp

    lines = [
        "# Aegis AI SAST 评估报告",
        "",
        f"**目标**: {target_name}  ",
        f"**日期**: {date_str}  ",
        "",
        "---",
        "",
        "## 检测率 (Recall)",
        "",
        "| 漏洞类型 | 应检出 | 已检出 | Recall |",
        "|----------|--------|--------|--------|",
    ]

    for cat in sorted(result.by_category.keys()):
        st = result.by_category[cat]
        tp_c, fn_c = st["tp"], st["fn"]
        expected = tp_c + fn_c
        if expected > 0:
            rec = tp_c / expected
            lines.append(f"| {cat} | {expected} | {tp_c} | {rec:.0%} |")
        else:
            lines.append(f"| {cat} | 0 | 0 | N/A |")

    lines.extend(
        [
            f"| **总计** | **{total_expected_pos}** | **{result.tp}** | **{result.recall:.1%}** |",
            "",
            "---",
            "",
            "## 按语言质量矩阵",
            "",
            "| 语言 | TP | TN | FP | FN | Recall | Precision | FPR | F1 |",
            "|------|---:|---:|---:|---:|-------:|----------:|----:|---:|",
        ]
    )

    for language, counts in sorted(result.by_language.items()):
        metrics = _metrics_for_counts(counts)
        lines.append(
            f"| {language} | {counts['tp']} | {counts['tn']} | {counts['fp']} | {counts['fn']} | "
            f"{metrics['recall']:.1%} | {metrics['precision']:.1%} | {metrics['fpr']:.1%} | {metrics['f1']:.2f} |"
        )

    lines.extend(
        [
            "",
            "### 语言 × 漏洞类型",
            "",
            "| 语言 | 漏洞类型 | TP | TN | FP | FN | Recall | Precision |",
            "|------|----------|---:|---:|---:|---:|-------:|----------:|",
        ]
    )
    for language, categories in sorted(result.by_language_category.items()):
        for category, counts in sorted(categories.items()):
            metrics = _metrics_for_counts(counts)
            lines.append(
                f"| {language} | {category} | {counts['tp']} | {counts['tn']} | "
                f"{counts['fp']} | {counts['fn']} | {metrics['recall']:.1%} | {metrics['precision']:.1%} |"
            )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 误报率 (FPR)",
            "",
            f"- 总发现数: {total_found}",
            f"- 真阳性 (TP): {result.tp}",
            f"- 误报 (FP): {result.fp}",
            f"- 应阴性总数 (TN+FP): {total_expected_neg}",
            f"- **误报率 (FPR)**: {result.fpr:.1%}",
            "",
            "---",
            "",
            "## 综合指标",
            "",
            f"- **Recall (检测率)**: {result.recall:.1%}",
            f"- **Precision (精确率)**: {result.precision:.1%}",
            f"- **F1 Score**: {result.f1:.2f}",
            "",
            "---",
            "",
            "## 明细 (TP/TN/FP/FN)",
            "",
            "| ID | 类型 | 模式 | 预期 | 结果 | 判定 |",
            "|----|------|------|------|------|------|",
        ]
    )

    project_details = bool(result.details and "ground_truth_index" in result.details[0])
    if project_details:
        lines[-2:] = [
            "| # | 判定 | 漏洞类型 | 位置 | 规则 | 说明 |",
            "|---:|------|----------|------|------|------|",
        ]

        def markdown_cell(value: Any) -> str:
            return str(value or "").replace("|", "\\|").replace("\r", " ").replace("\n", " ")

        for index, detail in enumerate(result.details, start=1):
            expected_entry = cast(dict[str, Any], detail.get("expected") or {})
            finding_entry = cast(dict[str, Any], detail.get("finding") or {})
            finding_type = finding_entry.get("type") or expected_entry.get("type") or "UNKNOWN"
            file_name = finding_entry.get("file") or expected_entry.get("file") or "unknown"
            line = finding_entry.get("line") or expected_entry.get("line")
            location = f"{file_name}:{line}" if line else file_name
            note = finding_entry.get("details") or finding_entry.get("content") or expected_entry.get("comment") or ""
            lines.append(
                f"| {index} | {markdown_cell(detail.get('verdict'))} | {markdown_cell(finding_type)} | "
                f"{markdown_cell(location)} | "
                f"{markdown_cell(finding_entry.get('rule_id') or finding_entry.get('source'))} | "
                f"{markdown_cell(note)} |"
            )
    else:
        for d in result.details:
            res_str = "FOUND" if d["detected"] else "CLEAN"
            lines.append(
                f"| {d['id']} | {d['category']} | {d['pattern']} | {d['expect']} | {res_str} | {d['verdict']} |"
            )

    lines.append("")
    return "\n".join(lines)


def format_report_json(
    result: BenchmarkResult,
    target_name: str = "自建基准",
    date_str: str | None = None,
) -> dict:
    """生成可序列化的 JSON 报告结构。"""
    if date_str is None:
        date_str = datetime.now().strftime("%Y-%m-%d")
    return {
        "target": target_name,
        "date": date_str,
        "metrics": {
            "tp": result.tp,
            "fp": result.fp,
            "fn": result.fn,
            "tn": result.tn,
            "recall": round(result.recall, 4),
            "precision": round(result.precision, 4),
            "fpr": round(result.fpr, 4),
            "f1": round(result.f1, 4),
        },
        "by_category": result.by_category,
        "by_language": result.by_language,
        "by_language_category": result.by_language_category,
        "details": result.details,
    }


def run_and_save_report(
    output_dir: Path | None = None,
    target_name: str = "自建基准",
    result: BenchmarkResult | None = None,
    file_prefix: str = "benchmark_report",
) -> tuple[Path, Path, BenchmarkResult]:
    """
    运行基准、生成 Markdown 与 JSON 报告并写入目录。

    Args:
        output_dir: 报告输出目录，默认 aegis-ai-core/reports
        target_name: 报告中的目标名称
        result: 若已运行过可传入，避免重复运行
        file_prefix: 输出文件名前缀。

    Returns:
        (md_path, json_path, result)
    """
    if output_dir is None:
        # aegis-ai-core/reports（scanner -> src -> aegis-ai-core）
        output_dir = Path(__file__).resolve().parent.parent.parent / "reports"
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    date_str = datetime.now().strftime("%Y-%m-%d")
    if result is None:
        result = run_benchmark()

    md_path = output_dir / f"{file_prefix}_{date_str}.md"
    md_path.write_text(
        format_report_md(result, target_name=target_name, date_str=date_str),
        encoding="utf-8",
    )

    json_path = output_dir / f"{file_prefix}_{date_str}.json"
    json_path.write_text(
        json.dumps(
            format_report_json(result, target_name=target_name, date_str=date_str), ensure_ascii=False, indent=2
        ),
        encoding="utf-8",
    )

    return md_path, json_path, result


def _file_matches(finding_file: str, expected_file: str) -> bool:
    """预期 file 可为路径后缀或包含关系，如 'login.js' 或 '*login*'。"""
    import fnmatch

    f = finding_file.replace("\\", "/")
    e = expected_file.replace("\\", "/")
    if "*" in e:
        return fnmatch.fnmatch(f, e) or e in f
    return f.endswith(e) or e in f


def evaluate_project_against_ground_truth(
    project_dir: Path,
    ground_truth: list[dict],
    engine: str = "new",
) -> BenchmarkResult:
    """
    阶段四：对真实项目扫描结果与 ground-truth 对比，得到 Recall/Precision/F1。

    Ground-truth 格式：列表，每项 {"file": str, "line": int, "type": str}。
    可选字段 ``line_candidates`` 支持多候选行号（分支差异时可用）。
    file 可为路径后缀或 glob（如 "login.js"、"*route*"）。

    Args:
        project_dir: 项目根目录
        ground_truth: 预期漏洞列表
        engine: 扫描引擎，默认 "new"

    Returns:
        BenchmarkResult（TP/FP/FN 由匹配结果统计）
    """
    from .project_scanner import ProjectScanner

    # 评估阶段需要反映当前规则代码，禁用缓存避免复用过期扫描结果。
    scanner = ProjectScanner(str(project_dir), engine=engine, use_cache=False)
    results = scanner.scan_project(verbose=False)
    all_findings: list[dict] = []
    for file_path, findings in results.items():
        for f in findings:
            f = dict(f)
            f["_file"] = file_path
            all_findings.append(f)

    # 将 ground_truth 分为两组：
    # - is_true_positive=True（或缺省） -> 真实漏洞，检出则 TP，漏报则 FN
    # - is_true_positive=False          -> 误报基准，检出则 FP，未检出则 TN
    positives = [(i, e) for i, e in enumerate(ground_truth) if e.get("is_true_positive", True)]
    negatives = [(i, e) for i, e in enumerate(ground_truth) if not e.get("is_true_positive", True)]

    positive_matches: list[int | None] = [None] * len(positives)
    negative_matches: list[int | None] = [None] * len(negatives)
    matched_finding_idx: set = set()

    # 行号容差：±LINE_TOLERANCE 内视为匹配
    LINE_TOLERANCE = 3

    def _match(exp: dict, finding: dict) -> bool:
        if finding.get("type", "") != exp.get("type", ""):
            return False
        if not _file_matches(finding.get("_file", ""), exp.get("file", "")):
            return False
        f_line = finding.get("line")
        exp_lines = _expected_ground_truth_lines(exp)
        if exp_lines:
            if f_line is None:
                return False
            try:
                f_line_num = int(f_line)
            except (TypeError, ValueError):
                return False
            return any(abs(f_line_num - exp_line) <= LINE_TOLERANCE for exp_line in exp_lines)
        return True

    for k, (_, exp) in enumerate(positives):
        for j, finding in enumerate(all_findings):
            if j in matched_finding_idx:
                continue
            if _match(exp, finding):
                positive_matches[k] = j
                matched_finding_idx.add(j)
                break

    for k, (_, exp) in enumerate(negatives):
        for j, finding in enumerate(all_findings):
            if j in matched_finding_idx:
                continue
            if _match(exp, finding):
                negative_matches[k] = j
                matched_finding_idx.add(j)
                break

    tp = sum(1 for match in positive_matches if match is not None)
    fn = len(positives) - tp
    fp_neg = sum(1 for match in negative_matches if match is not None)
    fp_extra = sum(1 for j in range(len(all_findings)) if j not in matched_finding_idx)
    fp = fp_neg + fp_extra
    tn = sum(1 for match in negative_matches if match is None)

    result = BenchmarkResult(tp=tp, fp=fp, fn=fn, tn=tn)
    result.by_category = {}

    for k, (_, exp) in enumerate(positives):
        cat = exp.get("type", "UNKNOWN")
        if cat not in result.by_category:
            result.by_category[cat] = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
        result.by_category[cat]["tp" if positive_matches[k] is not None else "fn"] += 1

    for k, (_, exp) in enumerate(negatives):
        cat = exp.get("type", "UNKNOWN")
        if cat not in result.by_category:
            result.by_category[cat] = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
        result.by_category[cat]["fp" if negative_matches[k] is not None else "tn"] += 1

    for j in range(len(all_findings)):
        if j in matched_finding_idx:
            continue
        cat = all_findings[j].get("type", "UNKNOWN")
        if cat not in result.by_category:
            result.by_category[cat] = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
        result.by_category[cat]["fp"] += 1

    def report_finding(finding_index: int) -> dict[str, Any]:
        finding = all_findings[finding_index]
        keys = (
            "type",
            "rule_id",
            "severity",
            "confidence",
            "line",
            "column",
            "end_line",
            "language",
            "details",
            "content",
            "source",
        )
        report = {key: finding[key] for key in keys if key in finding}
        report["file"] = finding.get("_file") or finding.get("file")
        return report

    for k, (ground_truth_index, expected) in enumerate(positives):
        finding_index = positive_matches[k]
        result.details.append(
            {
                "verdict": "TP" if finding_index is not None else "FN",
                "ground_truth_index": ground_truth_index,
                "expected": expected,
                "finding": report_finding(finding_index) if finding_index is not None else None,
            }
        )

    for k, (ground_truth_index, expected) in enumerate(negatives):
        finding_index = negative_matches[k]
        result.details.append(
            {
                "verdict": "FP" if finding_index is not None else "TN",
                "ground_truth_index": ground_truth_index,
                "expected": expected,
                "finding": report_finding(finding_index) if finding_index is not None else None,
            }
        )

    for finding_index in range(len(all_findings)):
        if finding_index not in matched_finding_idx:
            result.details.append(
                {
                    "verdict": "FP",
                    "ground_truth_index": None,
                    "expected": None,
                    "finding": report_finding(finding_index),
                }
            )

    return result


def main() -> None:
    """CLI 入口：运行基准并写入 reports/。"""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    md_path, json_path, result = run_and_save_report()
    logger.info("报告已生成: %s", md_path)
    logger.info("JSON: %s", json_path)
    logger.info(
        "Recall: %s, Precision: %s, F1: %s",
        f"{result.recall:.1%}",
        f"{result.precision:.1%}",
        f"{result.f1:.2f}",
    )


if __name__ == "__main__":
    main()
