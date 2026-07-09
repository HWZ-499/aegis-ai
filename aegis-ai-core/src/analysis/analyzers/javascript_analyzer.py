"""
javascript_analyzer.py - JavaScript/TypeScript 分析器（新规则架构）

说明：
- 与 PythonAnalyzer 风格一致：
  - 构建 AnalysisContext；
  - 解析 Tree-sitter AST；
  - 统一遍历 AST 节点并把节点交给各个 SecurityRule；
  - 在遍历前后调用规则的 before_file/after_file。
- 具体规则（如 RCE / SQLi / XSS 等）逐步从旧实现迁移到 `analysis.rules.*` 子包中。
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

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Parser = None  # type: ignore[misc,assignment]
    Node = None  # type: ignore[misc,assignment]


class JavaScriptAnalyzer:
    """
    JavaScript / TypeScript 代码分析入口。
    """

    def __init__(self, rules: Iterable[SecurityRule]) -> None:
        """
        Args:
            rules: SecurityRule 规则集合
        """
        # 只保留支持 javascript/typescript 的规则
        self.rules: list[SecurityRule] = [
            r for r in rules if r.supports("javascript") or r.supports("typescript") or not r.languages
        ]

        # 初始化 Tree-sitter parsers（如果可用）
        self._js_parser: Parser | None = None
        self._ts_parser: Parser | None = None
        if TREE_SITTER_AVAILABLE:
            self._js_parser = get_thread_parser("javascript")
            self._ts_parser = get_thread_parser("typescript")

    def analyze(self, code: str, file_path: Path, language: str = "javascript") -> list[dict]:
        """
        对单个 JS/TS 文件执行分析。

        Args:
            code: 源代码字符串
            file_path: 文件路径
            language: 'javascript' 或 'typescript'
        """
        lang = language.lower()
        if lang not in ("javascript", "typescript"):
            raise ValueError(f"JavaScriptAnalyzer 只支持 javascript/typescript，收到: {language}")

        # 1. 构建上下文
        context = AnalysisContext(
            file_path=file_path,
            language=lang,
        )
        # 将源码放入 extras，方便行级/混合规则使用
        context.extras["source"] = code

        # 2. before_file 钩子
        for rule in self.rules:
            rule.before_file(context)

        # 3. 解析 Tree-sitter AST（如果可用）
        parser = self._parser_for_language(lang)
        if parser:
            try:
                tree = parser.parse(bytes(code, "utf8"))
            except (RuntimeError, ValueError) as e:
                log_analysis_degradation(
                    logger,
                    language=lang,
                    stage="parse",
                    file_path=file_path,
                    error=e,
                )
            else:
                root = tree.root_node

                # 3.1 先运行 TaintAnalyzer 构建污点图，规则层通过 context.taint_graph 查询
                try:
                    from ..taint import TaintAnalyzer

                    taint_analyzer = TaintAnalyzer(language=lang, initialize_parser=False)
                    taint_analyzer.analyze_tree(root, str(file_path), code)
                    context.taint_graph = taint_analyzer.get_graph()
                    # 阶段二污点统一：JS/TS 仅用 taint_graph，不回退到 DataFlowTracker
                    context.dataflow_tracker = None
                except (ImportError, RuntimeError, ValueError) as e:
                    log_analysis_degradation(
                        logger,
                        language=lang,
                        stage="taint",
                        file_path=file_path,
                        error=e,
                    )
                    context.taint_graph = None

                # 4. 统一遍历 AST 节点
                try:
                    self._traverse_tree(root, context)
                except (RuntimeError, ValueError) as e:
                    log_analysis_degradation(
                        logger,
                        language=lang,
                        stage="traverse",
                        file_path=file_path,
                        error=e,
                    )

        # 5. after_file 钩子（适合行级规则或需要全局视角的规则）
        for rule in self.rules:
            rule.after_file(context)

        return context.findings

    def _parser_for_language(self, language: str) -> Parser | None:
        """Return the parser that matches the requested JavaScript-family language."""
        if language == "typescript":
            return self._ts_parser or self._js_parser
        return self._js_parser

    def _traverse_tree(self, node: Node, context: AnalysisContext) -> None:
        """
        递归遍历 Tree-sitter AST 节点，调用各个规则的 visit。

        Args:
            node: Tree-sitter Node
            context: AnalysisContext
        """
        # 跳过函数定义（规则内部会处理函数调用）
        if node.type == "function_declaration":
            # 只递归遍历子节点
            for child in node.children:
                self._traverse_tree(child, context)
            return

        # 对当前节点调用所有规则的 visit
        for rule in self.rules:
            rule.visit(node, context)

        # 递归遍历子节点
        for child in node.children:
            self._traverse_tree(child, context)


__all__ = ["JavaScriptAnalyzer"]
