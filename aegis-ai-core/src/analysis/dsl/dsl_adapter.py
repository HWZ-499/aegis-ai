"""
dsl_adapter.py

将 YAML DSL 规则适配为现有 SecurityRule 接口，便于与 AST 规则并存。
支持从 .aegis/rules/ 或 --rules-dir 加载额外 DSL 规则。
"""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path

from ..base import AnalysisContext, SecurityRule
from .dsl_engine import _load_rules_from_versions, _rule_file_versions, match_source
from .rule_schema import DslRule

logger = logging.getLogger(__name__)


def _safe_extra_dirs(extra_dirs: list[Path] | None, allowed_root: Path | None) -> list[Path]:
    """过滤并解析 extra_dirs，拒绝路径穿越与 allowed_root 外路径。"""
    if not extra_dirs:
        return []
    out: list[Path] = []
    for p in extra_dirs:
        try:
            resolved = p.resolve()
            if not resolved.exists() or not resolved.is_dir():
                continue
            if ".." in p.parts:
                logger.warning("跳过规则目录（含 ..）: %s", p)
                continue
            if allowed_root is not None:
                try:
                    resolved.relative_to(allowed_root)
                except ValueError:
                    logger.warning("跳过规则目录（超出允许根）: %s", p)
                    continue
            out.append(resolved)
        except (OSError, RuntimeError) as e:
            logger.debug("跳过规则目录 %s: %s", p, e)
    return out


_SEVERITY_MAP: dict[str, str] = {
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
        existing_pairs = {(f.get("line"), f.get("type")) for f in context.findings}

        findings = match_source(self._dsl_rule, source, file_path)
        for finding in findings:
            key = (finding.get("line"), finding.get("type"))
            if key in existing_pairs:
                continue
            existing_pairs.add(key)
            finding.setdefault("rule_id", self.rule_id)
            finding.setdefault("severity", self.severity)
            context.add_finding(finding)


def load_dsl_rules_for_language(
    language: str,
    extra_dirs: list[Path] | None = None,
    allowed_root: Path | None = None,
    preloaded_rules: tuple[DslRule, ...] | None = None,
) -> list[SecurityRule]:
    """加载指定语言的 DSL 规则并包装为 SecurityRule 适配器。

    Args:
        language: 语言标识，例如 \"python\"、\"javascript\"、\"go\"。
        extra_dirs: 额外规则目录（如 .aegis/rules），会与内置规则合并。
        allowed_root: 若提供，则 extra_dirs 中的路径必须在此根下。
        preloaded_rules: 已加载的目标语言规则快照，用于项目批量扫描复用。

    Returns:
        对应语言的 DslRuleAdapter 列表。
    """
    if preloaded_rules is None:
        definitions = load_dsl_rule_definitions(extra_dirs=extra_dirs, allowed_root=allowed_root)
        all_rules = definitions.get(language.lower(), ())
    else:
        all_rules = preloaded_rules
    adapters: list[SecurityRule] = []
    lang = language.lower()
    for rule in all_rules:
        if rule.language != lang:
            continue
        adapters.append(DslRuleAdapter(rule))
    return adapters


def load_dsl_rule_definitions(
    extra_dirs: list[Path] | None = None,
    allowed_root: Path | None = None,
) -> dict[str, tuple[DslRule, ...]]:
    """Load all built-in and project DSL definitions in one filesystem pass."""
    root = Path(__file__).resolve().parent.parent / "rules" / "dsl"
    rule_dirs = [root, *_safe_extra_dirs(extra_dirs or [], allowed_root)]
    file_versions = tuple(version for rule_dir in rule_dirs for version in _rule_file_versions(rule_dir))
    grouped: defaultdict[str, list[DslRule]] = defaultdict(list)
    for rule in _load_rules_from_versions(file_versions):
        grouped[rule.language].append(rule)
    return {language: tuple(rules) for language, rules in grouped.items()}


__all__ = ["DslRuleAdapter", "load_dsl_rule_definitions", "load_dsl_rules_for_language"]
