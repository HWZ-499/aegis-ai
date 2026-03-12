"""
python_analyzer.py - Python 专用分析器（统一污点系统版）

说明：
- 负责：
  - 构建 AnalysisContext；
  - 通过 TaintAnalyzer 构建统一污点图（taint_graph）；
  - 解析 Python stdlib AST；
  - 统一遍历 AST 节点并把节点交给各个 SecurityRule；
  - 在遍历前后调用规则的 before_file/after_file。
- 与 JavaScriptAnalyzer 对齐：先运行 TaintAnalyzer 填充 taint_graph，
  规则层统一通过 context.taint_graph 查询污点状态，不再依赖 DataFlowTracker。
"""

from __future__ import annotations

import ast
import logging
from collections.abc import Iterable
from pathlib import Path

from ..base import AnalysisContext, SecurityRule

logger = logging.getLogger(__name__)

# Tree-sitter 导入（Python 分析器也需要它来运行 TaintAnalyzer）
try:
    from tree_sitter import Parser
    from tree_sitter_languages import get_language

    _TREE_SITTER_AVAILABLE = True
except ImportError:
    _TREE_SITTER_AVAILABLE = False


class PythonAnalyzer:
    """
    Python 代码分析入口。
    """

    def __init__(self, rules: Iterable[SecurityRule]) -> None:
        # 只保留支持 python 的规则
        self.rules: list[SecurityRule] = [r for r in rules if r.supports("python") or not r.languages]

        # 初始化 Tree-sitter parser（用于 TaintAnalyzer）
        self._ts_parser: Parser | None = None
        if _TREE_SITTER_AVAILABLE:
            try:
                py_lang = get_language("python")
                self._ts_parser = Parser()
                self._ts_parser.set_language(py_lang)
            except (ImportError, RuntimeError, OSError):
                self._ts_parser = None

    def analyze(self, code: str, file_path: Path) -> list[dict]:
        """
        对单个 Python 文件执行分析。

        Args:
            code: Python 源代码字符串
            file_path: 文件路径

        Returns:
            findings 列表
        """
        # 1. 构建上下文
        context = AnalysisContext(
            file_path=file_path,
            language="python",
        )
        # 将源码放入 extras，方便行级/混合规则使用
        context.extras["source"] = code

        # 2. 构建统一污点图（与 JavaScriptAnalyzer 对齐）
        #    TaintAnalyzer 基于 Tree-sitter AST，同时支持 Python
        #    填充后规则层通过 context.taint_graph 查询，不再依赖 DataFlowTracker
        if self._ts_parser:
            try:
                from ..taint import TaintAnalyzer

                taint_analyzer = TaintAnalyzer(language="python")
                ts_tree = self._ts_parser.parse(bytes(code, "utf8"))
                taint_analyzer.analyze_tree(ts_tree.root_node, str(file_path), code)
                context.taint_graph = taint_analyzer.get_graph()
                # 统一污点系统：Python 也只使用 taint_graph，废弃 DataFlowTracker
                context.dataflow_tracker = None
            except (ImportError, RuntimeError, ValueError) as e:
                logger.debug("Python TaintAnalyzer 构建失败 [%s]: %s", file_path, e)
                context.taint_graph = None

        # 3. 解析 Python stdlib AST（规则层使用）
        try:
            stdlib_tree = ast.parse(code)
        except SyntaxError:
            # 代码语法错误时直接返回空结果，宽容处理
            return []

        # 4. before_file 钩子
        for rule in self.rules:
            rule.before_file(context)

        # 5. 统一遍历 AST 节点
        for node in ast.walk(stdlib_tree):
            for rule in self.rules:
                # 规则内部自行判断关心哪些节点
                rule.visit(node, context)

        # 6. after_file 钩子（适合行级规则或需要全局视角的规则）
        for rule in self.rules:
            rule.after_file(context)

        return context.findings


__all__ = ["PythonAnalyzer"]
