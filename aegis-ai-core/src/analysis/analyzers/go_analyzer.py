"""
go_analyzer.py - Go 专用分析器（统一污点系统版）

说明：
- 架构与 JavaAnalyzer/JavaScriptAnalyzer 对齐：
  - 构建 AnalysisContext；
  - 通过 TaintAnalyzer（Tree-sitter Go）构建统一污点图（taint_graph）；
  - 统一遍历 Tree-sitter AST 节点并把节点交给各个 SecurityRule；
  - 在遍历前后调用规则的 before_file/after_file。
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path

from ..base import AnalysisContext, SecurityRule
from ..tree_sitter_runtime import get_thread_parser
from .runtime import log_analysis_degradation

logger = logging.getLogger(__name__)

# Tree-sitter 导入
try:
    from tree_sitter import Node, Parser

    _TREE_SITTER_AVAILABLE = True
except ImportError:
    Parser = None  # type: ignore[misc,assignment]
    Node = None  # type: ignore[misc,assignment]
    _TREE_SITTER_AVAILABLE = False


class GoAnalyzer:
    """
    Go 代码分析入口。
    """

    def __init__(self, rules: Iterable[SecurityRule]) -> None:
        """
        Args:
            rules: SecurityRule 规则集合
        """
        # 只保留支持 go 的规则
        self.rules: list[SecurityRule] = [r for r in rules if r.supports("go") or not r.languages]

        # 初始化 Tree-sitter parser（Go 语言）
        self._parser: Parser | None = None
        if _TREE_SITTER_AVAILABLE:
            self._parser = get_thread_parser("go")

    def analyze(self, code: str, file_path: Path) -> list[dict]:
        """
        对单个 Go 文件执行分析。

        Args:
            code: Go 源码字符串
            file_path: 文件路径

        Returns:
            findings 列表
        """
        # 1. 构建上下文
        context = AnalysisContext(
            file_path=file_path,
            language="go",
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
                    language="go",
                    stage="parse",
                    file_path=file_path,
                    error=e,
                )
                ts_tree = None

        # 3. 构建统一污点图（Tree-sitter Go AST）
        if ts_tree is not None:
            try:
                from ..taint import TaintAnalyzer

                taint_analyzer = TaintAnalyzer(language="go", initialize_parser=False)
                taint_analyzer.analyze_tree(ts_tree.root_node, str(file_path), code)
                context.taint_graph = taint_analyzer.get_graph()
                context.dataflow_tracker = None
            except (ImportError, RuntimeError, ValueError) as e:
                log_analysis_degradation(
                    logger,
                    language="go",
                    stage="taint",
                    file_path=file_path,
                    error=e,
                )
                context.taint_graph = None

        # 4. before_file 钩子
        for rule in self.rules:
            rule.before_file(context)

        # 5. 遍历已解析的 Tree-sitter AST（若可用）
        if ts_tree is not None:
            try:
                self._traverse_tree(ts_tree.root_node, context)
            except (RuntimeError, ValueError) as e:
                log_analysis_degradation(
                    logger,
                    language="go",
                    stage="traverse",
                    file_path=file_path,
                    error=e,
                )
                # AST 失败不应影响行级/模式规则

        # 6. after_file 钩子
        for rule in self.rules:
            rule.after_file(context)

        return context.findings

    def _traverse_tree(self, node: Node, context: AnalysisContext) -> None:  # type: ignore[name-defined]
        """
        递归遍历 Tree-sitter AST 节点，调用各个规则的 visit。

        Args:
            node: Tree-sitter Node
            context: AnalysisContext
        """
        for rule in self.rules:
            rule.visit(node, context)

        for child in node.children:
            self._traverse_tree(child, context)


__all__ = ["GoAnalyzer"]
