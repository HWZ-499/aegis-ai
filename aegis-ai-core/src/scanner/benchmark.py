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

# 用例定义（与 test_acceptance_benchmark 对齐，便于统一维护）
from .benchmark_cases import BENCH_CASES_TN, BENCH_CASES_TP, BenchCase

logger = logging.getLogger(__name__)


@dataclass
class BenchmarkResult:
    """基准测试汇总结果。"""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    details: list[dict] = field(default_factory=list)
    by_category: dict[str, dict[str, int]] = field(default_factory=dict)

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
        }


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
                result.tp += 1
                verdict = "TP"
            else:
                result.fn += 1
                verdict = "FN"
        else:
            if detected:
                result.fp += 1
                verdict = "FP"
            else:
                result.tn += 1
                verdict = "TN"

        result.details.append(
            {
                "id": case.id,
                "category": case.category,
                "language": case.language,
                "pattern": case.pattern,
                "description": case.description,
                "expect": "VULN" if case.expect_finding else "SAFE",
                "detected": detected,
                "verdict": verdict,
                "finding_count": len(relevant),
            }
        )

        # 按类型聚合
        cat = case.category
        if cat not in result.by_category:
            result.by_category[cat] = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
        result.by_category[cat][verdict.lower()] += 1

    return result


def _analyze_case(case: BenchCase) -> list[dict]:
    """按语言路由到对应分析器，避免跨语言用例被误记为 FN。"""
    from ..analysis.rule_engine import (
        analyze_go,
        analyze_java,
        analyze_javascript,
        analyze_php,
        analyze_python,
    )

    language = (case.language or "javascript").lower()
    if language in {"javascript", "js", "jsx"}:
        suffix = "jsx" if language == "jsx" else "js"
        return analyze_javascript(case.code, f"benchmark.{suffix}", language="javascript")
    if language in {"typescript", "ts", "tsx"}:
        suffix = "tsx" if language == "tsx" else "ts"
        return analyze_javascript(case.code, f"benchmark.{suffix}", language="typescript")
    if language == "python":
        return analyze_python(case.code, "benchmark.py")
    if language == "php":
        return analyze_php(case.code, "benchmark.php")
    if language == "java":
        return analyze_java(case.code, "Benchmark.java")
    if language == "go":
        return analyze_go(case.code, "benchmark.go")

    logger.warning(
        "Unknown benchmark case language '%s' in case %s, fallback to JavaScript analyzer", language, case.id
    )
    return analyze_javascript(case.code, "benchmark.js")


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

    for d in result.details:
        res_str = "FOUND" if d["detected"] else "CLEAN"
        lines.append(f"| {d['id']} | {d['category']} | {d['pattern']} | {d['expect']} | {res_str} | {d['verdict']} |")

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
        "details": result.details,
    }


def run_and_save_report(
    output_dir: Path | None = None,
    target_name: str = "自建基准",
    result: BenchmarkResult | None = None,
) -> tuple[Path, Path, BenchmarkResult]:
    """
    运行基准、生成 Markdown 与 JSON 报告并写入目录。

    Args:
        output_dir: 报告输出目录，默认 aegis-ai-core/reports
        target_name: 报告中的目标名称
        result: 若已运行过可传入，避免重复运行

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

    md_path = output_dir / f"benchmark_report_{date_str}.md"
    md_path.write_text(
        format_report_md(result, target_name=target_name, date_str=date_str),
        encoding="utf-8",
    )

    json_path = output_dir / f"benchmark_report_{date_str}.json"
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

    used_positive: list[bool] = [False] * len(positives)
    used_negative: list[bool] = [False] * len(negatives)
    matched_finding_idx: set = set()

    # 行号容差：±LINE_TOLERANCE 内视为匹配
    LINE_TOLERANCE = 3

    def _expected_lines(exp: dict) -> list[int]:
        candidates: list[int] = []
        line_candidates = exp.get("line_candidates")
        if isinstance(line_candidates, list):
            for item in line_candidates:
                try:
                    candidates.append(int(item))
                except (TypeError, ValueError):
                    continue
        elif line_candidates is not None:
            try:
                candidates.append(int(line_candidates))
            except (TypeError, ValueError):
                pass

        line = exp.get("line")
        if line is not None:
            try:
                candidates.append(int(line))
            except (TypeError, ValueError):
                pass

        deduped: list[int] = []
        seen: set[int] = set()
        for value in candidates:
            if value in seen:
                continue
            seen.add(value)
            deduped.append(value)
        return deduped

    def _match(exp: dict, finding: dict) -> bool:
        if finding.get("type", "") != exp.get("type", ""):
            return False
        if not _file_matches(finding.get("_file", ""), exp.get("file", "")):
            return False
        f_line = finding.get("line")
        exp_lines = _expected_lines(exp)
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
                used_positive[k] = True
                matched_finding_idx.add(j)
                break

    for k, (_, exp) in enumerate(negatives):
        for j, finding in enumerate(all_findings):
            if j in matched_finding_idx:
                continue
            if _match(exp, finding):
                used_negative[k] = True
                matched_finding_idx.add(j)
                break

    tp = sum(1 for u in used_positive if u)
    fn = len(positives) - tp
    fp_neg = sum(1 for u in used_negative if u)
    fp_extra = sum(1 for j in range(len(all_findings)) if j not in matched_finding_idx)
    fp = fp_neg + fp_extra
    tn = sum(1 for u in used_negative if not u)

    result = BenchmarkResult(tp=tp, fp=fp, fn=fn, tn=tn)
    result.by_category = {}

    for k, (_, exp) in enumerate(positives):
        cat = exp.get("type", "UNKNOWN")
        if cat not in result.by_category:
            result.by_category[cat] = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
        result.by_category[cat]["tp" if used_positive[k] else "fn"] += 1

    for k, (_, exp) in enumerate(negatives):
        cat = exp.get("type", "UNKNOWN")
        if cat not in result.by_category:
            result.by_category[cat] = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
        result.by_category[cat]["fp" if used_negative[k] else "tn"] += 1

    for j in range(len(all_findings)):
        if j in matched_finding_idx:
            continue
        cat = all_findings[j].get("type", "UNKNOWN")
        if cat not in result.by_category:
            result.by_category[cat] = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
        result.by_category[cat]["fp"] += 1

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
