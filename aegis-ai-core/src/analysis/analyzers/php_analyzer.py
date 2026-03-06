"""
php_analyzer.py - PHP 专用分析器（主引擎对齐版）

说明：
- 架构对齐 JavaScriptAnalyzer：
  - 构建 AnalysisContext；
  - 通过 TaintAnalyzer（Tree-sitter PHP）构建统一污点图（taint_graph）；
  - 并行运行 PhpTaintGraph 行级规则（精确层）；
  - 按 (line, type) 去重后合并返回。
- 取代了原来 rule_engine.analyze_php 中的分散调用逻辑。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Iterable, List

from ..base import AnalysisContext, SecurityRule

logger = logging.getLogger(__name__)

# Tree-sitter 导入
try:
    from tree_sitter import Parser
    from tree_sitter_languages import get_language
    _TREE_SITTER_AVAILABLE = True
except ImportError:
    _TREE_SITTER_AVAILABLE = False


class PhpAnalyzer:
    """
    PHP 代码分析入口。

    双引擎策略：
    1. TaintAnalyzer（Tree-sitter PHP AST）→ context.taint_graph，供规则层精确查询
    2. PhpTaintGraph 行级精确规则（`_PhpTaintBaseRule` 子类）→ 高置信度 findings
    3. 正则补充层（兜底）→ 通过 rule_engine.scan_code_locally 提供
    """

    def __init__(self, rules: Iterable[SecurityRule]) -> None:
        """
        Args:
            rules: SecurityRule 规则集合（目前传入空列表，行级规则内部处理）
        """
        self.rules: List[SecurityRule] = [
            r for r in rules if r.supports("php") or not r.languages
        ]

        # 初始化 Tree-sitter parser（PHP 语言）
        self._parser: Parser | None = None
        if _TREE_SITTER_AVAILABLE:
            try:
                php_lang = get_language("php")
                self._parser = Parser()
                self._parser.set_language(php_lang)
            except Exception as e:
                logger.debug("PHP Tree-sitter 初始化失败: %s", e)
                self._parser = None

    def analyze(self, code: str, file_path: Path) -> List[Dict]:
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

        # 2. 构建统一污点图（Tree-sitter PHP AST）
        #    PHP Tree-sitter 支持 PHP 5/7/8 语法
        if self._parser:
            try:
                from ..taint import TaintAnalyzer
                taint_analyzer = TaintAnalyzer(language="php")
                ts_tree = self._parser.parse(bytes(code, "utf8"))
                taint_analyzer.analyze_tree(ts_tree.root_node, str(file_path), code)
                context.taint_graph = taint_analyzer.get_graph()
            except Exception as e:
                logger.debug("PHP TaintAnalyzer 构建失败 [%s]: %s", file_path, e)
                context.taint_graph = None

        # 3. before_file 钩子
        for rule in self.rules:
            rule.before_file(context)

        # 4. 遍历 AST（若可用）
        if self._parser and context.taint_graph is not None:
            try:
                ts_tree = self._parser.parse(bytes(code, "utf8"))
                self._traverse_tree(ts_tree.root_node, context)
            except Exception as e:
                logger.debug("PHP AST 遍历失败 [%s]: %s", file_path, e)

        # 5. after_file 钩子
        for rule in self.rules:
            rule.after_file(context)

        return context.findings

    def _traverse_tree(self, node: object, context: AnalysisContext) -> None:
        """递归遍历 Tree-sitter AST 节点，调用各规则的 visit。"""
        for rule in self.rules:
            rule.visit(node, context)
        for child in getattr(node, "children", []):
            self._traverse_tree(child, context)


__all__ = ["PhpAnalyzer"]
