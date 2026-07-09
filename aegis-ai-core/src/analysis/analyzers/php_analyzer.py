"""
php_analyzer.py - PHP 专用分析器（主引擎对齐版）

说明：
- 架构对齐 JavaScriptAnalyzer：
  - 构建 AnalysisContext；
  - 通过 TaintAnalyzer（Tree-sitter PHP）构建统一污点图（taint_graph）；
  - 运行统一 SecurityRule 生命周期；
  - 污点图失败时仍遍历 AST，保留直接 Source→Sink 检测。
- 取代了原来 rule_engine.analyze_php 中的分散调用逻辑。
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path
from typing import cast

from ..base import AnalysisContext, SecurityRule
from ..tree_sitter_runtime import get_thread_parser
from .runtime import log_analysis_degradation

logger = logging.getLogger(__name__)

# Tree-sitter 导入
try:
    from tree_sitter import Parser

    _TREE_SITTER_AVAILABLE = True
except ImportError:
    _TREE_SITTER_AVAILABLE = False


class PhpAnalyzer:
    """
    PHP 代码分析入口。

    统一 AST 主引擎策略：
    1. TaintAnalyzer（Tree-sitter PHP AST）→ context.taint_graph，供规则层精确查询
    2. SecurityRule 生命周期 → 高置信度 AST findings
    3. 污点图失败时继续遍历 AST，处理直接 Source→Sink 场景
    """

    def __init__(self, rules: Iterable[SecurityRule]) -> None:
        """
        Args:
            rules: SecurityRule 规则集合（目前传入空列表，行级规则内部处理）
        """
        self.rules: list[SecurityRule] = [r for r in rules if r.supports("php") or not r.languages]

        # 初始化 Tree-sitter parser（PHP 语言）
        self._parser: Parser | None = None
        if _TREE_SITTER_AVAILABLE:
            self._parser = get_thread_parser("php")

    def analyze(self, code: str, file_path: Path) -> list[dict]:
        """
        对单个 PHP 文件执行分析。

        Args:
            code: PHP 源码字符串
            file_path: 文件路径

        Returns:
            findings 列表
        """
        # 1. 构建上下文
        context = AnalysisContext(
            file_path=file_path,
            language="php",
        )
        context.extras["source"] = code

        # 2. 解析一次 Tree-sitter AST，供污点分析和规则遍历复用
        ts_tree = None
        if self._parser:
            try:
                ts_tree = self._parser.parse(bytes(code, "utf8"))
            except (RuntimeError, ValueError) as e:
                log_analysis_degradation(
                    logger,
                    language="php",
                    stage="parse",
                    file_path=file_path,
                    error=e,
                )

        # 3. 构建统一污点图（Tree-sitter PHP AST）
        #    PHP Tree-sitter 支持 PHP 5/7/8 语法
        if ts_tree is not None:
            try:
                from ..taint import TaintAnalyzer

                taint_analyzer = TaintAnalyzer(language="php", initialize_parser=False)
                taint_analyzer.analyze_tree(ts_tree.root_node, str(file_path), code)
                context.taint_graph = taint_analyzer.get_graph()
            except (ImportError, RuntimeError, ValueError) as e:
                log_analysis_degradation(
                    logger,
                    language="php",
                    stage="taint",
                    file_path=file_path,
                    error=e,
                )
                context.taint_graph = None

        # 4. before_file 钩子
        for rule in self.rules:
            rule.before_file(context)

        # 5. 遍历已解析的 AST（若可用）。
        # AST 规则必须能在污点图构建失败时继续处理直接 Source→Sink 场景。
        if ts_tree is not None:
            try:
                self._traverse_tree(ts_tree.root_node, context)
            except (RuntimeError, ValueError) as e:
                log_analysis_degradation(
                    logger,
                    language="php",
                    stage="traverse",
                    file_path=file_path,
                    error=e,
                )

        # 6. after_file 钩子
        for rule in self.rules:
            rule.after_file(context)

        return cast(list[dict], context.findings)

    def _traverse_tree(self, node: object, context: AnalysisContext) -> None:
        """递归遍历 Tree-sitter AST 节点，调用各规则的 visit。"""
        for rule in self.rules:
            rule.visit(node, context)
        for child in getattr(node, "children", []):
            self._traverse_tree(child, context)


__all__ = ["PhpAnalyzer"]
