"""
test_acceptance_benchmark.py - 阶段一 + 阶段二 综合验收基准测试

模拟真实世界的 Express.js 代码，量化评估 Aegis SAST 的检测能力。

测试维度：
1. True Positive  (TP)  — 应该报，报了                → 检测率 Recall
2. False Positive (FP)  — 不该报，报了                → 误报率 FPR
3. False Negative (FN)  — 应该报，没报                → 漏报
4. True Negative  (TN)  — 不该报，没报                → 正确放行

最终输出：
- 按漏洞类型的 TP / FP / FN / TN
- 按传播模式覆盖情况
- 综合 Recall / Precision / F1
"""

import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

# 确保项目根目录在 sys.path 中
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# 阶段四：用例与 benchmark 模块共用，单一数据源
from src.analysis.base.analysis_context import AnalysisContext
from src.analysis.base.js_dataflow_collector import JavaScriptDataFlowCollector
from src.analysis.rule_engine import analyze_python
from src.scanner.benchmark import (
    QualityThresholds,
    quality_gate_violations,
    run_rule_sample_benchmark,
)
from src.scanner.benchmark_cases import BENCH_CASES_TN as TN_CASES
from src.scanner.benchmark_cases import BENCH_CASES_TP as TP_CASES
from src.scanner.benchmark_cases import BenchCase

# ── Tree-sitter ──
try:
    from tree_sitter import Parser
    from tree_sitter_languages import get_language

    JS_LANGUAGE = get_language("javascript")
    _parser = Parser()
    _parser.set_language(JS_LANGUAGE)
    TREE_SITTER_AVAILABLE = True
except Exception:
    TREE_SITTER_AVAILABLE = False
    _parser = None

# ── 所有规则 ──
try:
    from src.analysis.rules.deserialization.javascript_ast_rule import JavaScriptDeserializationAstRule
    from src.analysis.rules.hardcoded_credentials.javascript_ast_rule import JavaScriptHardcodedCredentialsAstRule
    from src.analysis.rules.nosql_injection.javascript_ast_rule import JavaScriptNoSQLInjectionAstRule
    from src.analysis.rules.path_traversal.javascript_ast_rule import JavaScriptPathTraversalAstRule
    from src.analysis.rules.rce.javascript_ast_rule import JavaScriptRCEAstRule
    from src.analysis.rules.sql_injection.javascript_ast_rule import JavaScriptSQLInjectionAstRule
    from src.analysis.rules.xss.javascript_ast_rule import JavaScriptXSSAstRule

    ALL_RULES_AVAILABLE = True
except ImportError:
    ALL_RULES_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not TREE_SITTER_AVAILABLE or not ALL_RULES_AVAILABLE,
    reason="tree-sitter 或规则模块不可用",
)
pytestmark = [
    pytest.mark.acceptance,
    pytest.mark.skipif(
        not TREE_SITTER_AVAILABLE or not ALL_RULES_AVAILABLE,
        reason="tree-sitter 或规则模块不可用",
    ),
]


# =====================================================================
# 扫描引擎
# =====================================================================


def _full_scan(code: str) -> list[dict]:
    """
    用所有规则扫描一段 JS 代码。

    返回 findings 列表。
    """
    root = _parser.parse(bytes(code, "utf-8")).root_node
    ctx = AnalysisContext(file_path=Path("benchmark.js"), language="javascript")

    collector = JavaScriptDataFlowCollector()
    rules = [
        JavaScriptNoSQLInjectionAstRule(),
        JavaScriptSQLInjectionAstRule(),
        JavaScriptXSSAstRule(),
        JavaScriptRCEAstRule(),
        JavaScriptHardcodedCredentialsAstRule(),
        JavaScriptPathTraversalAstRule(),
        JavaScriptDeserializationAstRule(),
    ]

    def walk(node):
        collector.visit(node, ctx)
        for rule in rules:
            rule.visit(node, ctx)
        for child in node.children:
            walk(child)

    walk(root)
    return ctx.findings


def _scan_case(case: BenchCase) -> list[dict]:
    """按用例语言选择分析器。"""
    language = (case.language or "javascript").lower()
    if language in {"javascript", "js", "typescript", "ts"}:
        return _full_scan(case.code)
    if language == "python":
        return analyze_python(case.code, "benchmark_case.py")
    return []


# =====================================================================
# 量化统计（用例见 src.scanner.benchmark_cases）
# =====================================================================


@dataclass
class BenchmarkResult:
    """基准测试结果。"""

    tp: int = 0  # True Positive
    fp: int = 0  # False Positive
    fn: int = 0  # False Negative
    tn: int = 0  # True Negative
    details: list[dict] = field(default_factory=list)

    @property
    def recall(self) -> float:
        """检测率 = TP / (TP + FN)"""
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def precision(self) -> float:
        """精确率 = TP / (TP + FP)"""
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def f1(self) -> float:
        """F1 = 2 * P * R / (P + R)"""
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


def _run_benchmark(cases: list[BenchCase]) -> BenchmarkResult:
    """运行所有用例，统计结果。"""
    result = BenchmarkResult()

    for case in cases:
        findings = _scan_case(case)
        # 只看对应类型的 findings
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
                "pattern": case.pattern,
                "description": case.description,
                "expect": "VULN" if case.expect_finding else "SAFE",
                "detected": detected,
                "verdict": verdict,
                "finding_count": len(relevant),
            }
        )

    return result


# =====================================================================
# Pytest 入口
# =====================================================================


class TestAcceptanceBenchmark:
    """综合验收基准测试。"""

    def test_rule_sample_quality_matrix_has_no_regressions(self):
        """Curated samples must remain clean overall and for every supported language."""
        result = run_rule_sample_benchmark(PROJECT_ROOT / "tests" / "rules")
        thresholds = QualityThresholds(
            min_recall=1.0,
            min_precision=1.0,
            min_f1=1.0,
            max_fpr=0.0,
        )

        violations = quality_gate_violations(
            result,
            thresholds,
            per_language=True,
            per_category=True,
            per_language_category=True,
        )

        assert violations == []
        assert set(result.by_language) == {"go", "java", "javascript", "php", "python"}
        assert result.tp + result.tn + result.fp + result.fn >= 180
        assert any(detail["id"].endswith("tp_python_cursor_execute_format.py") for detail in result.details)

    def test_full_benchmark(self, capsys):
        """运行完整基准测试并输出报告。"""
        all_cases = TP_CASES + TN_CASES
        result = _run_benchmark(all_cases)

        # ── 输出报告 ──
        report_lines = []
        report_lines.append("")
        report_lines.append("=" * 72)
        report_lines.append("  Aegis AI SAST 综合验收基准测试报告")
        report_lines.append("=" * 72)
        report_lines.append("")

        # 逐条输出
        report_lines.append(f"{'ID':<16} {'类型':<24} {'模式':<24} {'预期':>6} {'结果':>6} {'判定':>6}")
        report_lines.append("-" * 86)

        for d in result.details:
            marker = {
                "TP": "[OK]",
                "TN": "[OK]",
                "FP": "[!!]",
                "FN": "[!!]",
            }[d["verdict"]]
            report_lines.append(
                f"{d['id']:<16} {d['category']:<24} {d['pattern']:<24} "
                f"{d['expect']:>6} {'FOUND' if d['detected'] else 'CLEAN':>6} "
                f"{marker + ' ' + d['verdict']:>8}"
            )

        report_lines.append("")
        report_lines.append("-" * 72)
        report_lines.append("  汇总统计")
        report_lines.append("-" * 72)
        report_lines.append(f"  True Positive  (TP) : {result.tp:>3}  （应该报，报了）")
        report_lines.append(f"  True Negative  (TN) : {result.tn:>3}  （不该报，没报）")
        report_lines.append(f"  False Positive (FP) : {result.fp:>3}  （不该报，报了 — 误报）")
        report_lines.append(f"  False Negative (FN) : {result.fn:>3}  （应该报，没报 — 漏报）")
        report_lines.append("")
        report_lines.append(f"  Recall    (检测率) : {result.recall:.1%}")
        report_lines.append(f"  Precision (精确率) : {result.precision:.1%}")
        report_lines.append(f"  F1 Score          : {result.f1:.1%}")
        report_lines.append("")

        # 按漏洞类型分组统计
        cats: dict[str, dict[str, int]] = {}
        for d in result.details:
            cat = d["category"]
            if cat not in cats:
                cats[cat] = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
            cats[cat][d["verdict"].lower()] += 1

        report_lines.append("-" * 72)
        report_lines.append("  按漏洞类型")
        report_lines.append("-" * 72)
        report_lines.append(f"  {'漏洞类型':<28} {'TP':>4} {'TN':>4} {'FP':>4} {'FN':>4}  {'Recall':>8}")
        for cat, stats in sorted(cats.items()):
            tp_c, fn_c = stats["tp"], stats["fn"]
            recall_c = tp_c / (tp_c + fn_c) if (tp_c + fn_c) > 0 else float("nan")
            recall_str = f"{recall_c:.0%}" if (tp_c + fn_c) > 0 else "N/A"
            report_lines.append(
                f"  {cat:<28} {stats['tp']:>4} {stats['tn']:>4} {stats['fp']:>4} {stats['fn']:>4}  {recall_str:>8}"
            )

        # 传播模式覆盖
        patterns_tested = set()
        for d in result.details:
            patterns_tested.add(d["pattern"])
        report_lines.append("")
        report_lines.append("-" * 72)
        report_lines.append("  传播模式覆盖")
        report_lines.append("-" * 72)
        for p in sorted(patterns_tested):
            report_lines.append(f"    [x] {p}")

        report_lines.append("")
        report_lines.append("=" * 72)

        report_text = "\n".join(report_lines)

        # 打印到控制台（pytest -s 可见）
        print(report_text)

        # ── 断言 ──
        # 检测率不低于 70%
        assert result.recall >= 0.70, f"Recall {result.recall:.1%} < 70%"
        # 误报率不超过 20%
        total_neg = result.tn + result.fp
        fpr = result.fp / total_neg if total_neg > 0 else 0
        assert fpr <= 0.20, f"FPR {fpr:.1%} > 20%"
        # F1 不低于 0.75
        assert result.f1 >= 0.75, f"F1 {result.f1:.1%} < 75%"

    # ── 单独的 TP 断言，方便看哪条失败 ──

    @pytest.mark.parametrize(
        "case",
        TP_CASES,
        ids=[c.id for c in TP_CASES],
    )
    def test_true_positive(self, case: BenchCase):
        """验证每个 TP 用例都能被检测到。"""
        findings = _scan_case(case)
        relevant = [f for f in findings if f.get("type", "") == case.category]
        assert len(relevant) >= 1, (
            f"[{case.id}] 应该检测到 {case.category}，但没有。"
            f"\n代码: {case.code[:80]}..."
            f"\n所有 findings: {[f.get('type') for f in findings]}"
        )

    @pytest.mark.parametrize(
        "case",
        TN_CASES,
        ids=[c.id for c in TN_CASES],
    )
    def test_true_negative(self, case: BenchCase):
        """验证每个 TN 用例都不会被误报。"""
        findings = _scan_case(case)
        relevant = [f for f in findings if f.get("type", "") == case.category]
        assert len(relevant) == 0, (
            f"[{case.id}] 不应该检测到 {case.category}，但误报了 {len(relevant)} 个。"
            f"\n代码: {case.code[:80]}..."
            f"\n误报内容: {[f.get('details', '')[:60] for f in relevant]}"
        )
