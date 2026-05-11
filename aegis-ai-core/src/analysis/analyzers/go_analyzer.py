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

from collections.abc import Iterable
from pathlib import Path

from ..base import AnalysisContext, SecurityRule

# Tree-sitter 导入
try:
    from tree_sitter import Node, Parser
    from tree_sitter_languages import get_language

    _TREE_SITTER_AVAILABLE = True
except ImportError:
    Parser = None  # type: ignore[misc,assignment]
    Node = None  # type: ignore[misc,assignment]
    get_language = None  # type: ignore[misc,assignment]
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
            try:
                go_lang = get_language("go")
                self._parser = Parser()
                self._parser.set_language(go_lang)
            except (ImportError, RuntimeError, OSError):
                self._parser = None

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

        # 2. 构建统一污点图（Tree-sitter Go AST）
        if self._parser:
            try:
                from ..taint import TaintAnalyzer

                taint_analyzer = TaintAnalyzer(language="go")
                ts_tree = self._parser.parse(bytes(code, "utf8"))
                taint_analyzer.analyze_tree(ts_tree.root_node, str(file_path), code)
                context.taint_graph = taint_analyzer.get_graph()
                context.dataflow_tracker = None
            except (ImportError, RuntimeError, ValueError):
                context.taint_graph = None

        # 3. before_file 钩子
        for rule in self.rules:
            rule.before_file(context)

        # 4. 遍历 Tree-sitter AST（若可用）
        if self._parser:
            try:
                ts_tree = self._parser.parse(bytes(code, "utf8"))
                self._traverse_tree(ts_tree.root_node, context)
            except (RuntimeError, ValueError):
                # AST 失败不应影响行级/模式规则
                pass

        # 5. after_file 钩子
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
