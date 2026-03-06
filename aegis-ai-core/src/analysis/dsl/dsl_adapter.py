"""
dsl_adapter.py

将 YAML DSL 规则适配为现有 SecurityRule 接口，便于与 AST 规则并存。
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from ..base import AnalysisContext, SecurityRule
from .dsl_engine import load_rules_from_directory, match_source
from .rule_schema import DslRule


_SEVERITY_MAP: Dict[str, str] = {
    "INFO": "Info",
    "LOW": "Low",
    "MEDIUM": "Medium",
    "HIGH": "High",
    "CRITICAL": "Critical",
}


class DslRuleAdapter(SecurityRule):
    """将 DslRule 包装为 SecurityRule 的适配器。

    适配策略：
    - 不在 visit() 中做任何处理，仅在 after_file() 中对整文件源码执行匹配；
    - 使用 match_source() 返回的行级 Finding 结果；
    - 为避免与 AST 规则重复报警，在追加前会检查同一 (line, type) 是否已存在。
    """

    def __init__(self, dsl_rule: DslRule) -> None:
        """初始化适配器。

        Args:
            dsl_rule: DslRule 实例。
        """
        severity = _SEVERITY_MAP.get(dsl_rule.severity, "Medium")
        super().__init__(
            rule_id=dsl_rule.id,
            severity=severity,
            languages=[dsl_rule.language],
        )
        self._dsl_rule = dsl_rule

    def visit(self, node, context: AnalysisContext) -> None:  # type: ignore[override]
        """DSL 规则不依赖逐节点访问。

        Args:
            node: AST 节点（未使用）。
            context: 分析上下文（未使用）。
        """
        return

    def after_file(self, context: AnalysisContext) -> None:  # type: ignore[override]
        """在整文件分析结束后执行 DSL 匹配。

        Args:
            context: 分析上下文。
        """
        source = context.extras.get("source", "")
        if not source:
            return

        file_path = Path(context.file_path)
        existing_pairs = {
            (f.get("line"), f.get("type")) for f in context.findings
        }

        findings = match_source(self._dsl_rule, source, file_path)
        for finding in findings:
            key = (finding.get("line"), finding.get("type"))
            if key in existing_pairs:
                continue
            existing_pairs.add(key)
            finding.setdefault("rule_id", self.rule_id)
            finding.setdefault("severity", self.severity)
            context.add_finding(finding)


def load_dsl_rules_for_language(language: str) -> List[SecurityRule]:
    """加载指定语言的 DSL 规则并包装为 SecurityRule 适配器。

    Args:
        language: 语言标识，例如 \"python\"、\"javascript\"、\"go\"。

    Returns:
        对应语言的 DslRuleAdapter 列表。
    """
    root = (
        Path(__file__)
        .resolve()
        .parent.parent
        / "rules"
        / "dsl"
    )
    all_rules = load_rules_from_directory(root)
    adapters: List[SecurityRule] = []
    lang = language.lower()
    for rule in all_rules:
        if rule.language != lang:
            continue
        adapters.append(DslRuleAdapter(rule))
    return adapters


__all__ = ["DslRuleAdapter", "load_dsl_rules_for_language"]

