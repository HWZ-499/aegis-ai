"""
security_rule.py - 规则基类（面向 AST 节点）

注意：
- 这里不再提供基于“代码行”的 match(line) 接口。
- 所有具体规则都应实现 visit(node, context)：
  - node: 语言对应的 AST 节点（Python ast.AST 或 Tree-sitter 节点）
  - context: AnalysisContext，包含文件信息、符号表、数据流图等。
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any

_rule_logger = logging.getLogger(__name__)

from .analysis_context import AnalysisContext


class SecurityRule(ABC):
    """
    安全规则基类（AST 访问模型）。

    设计要点：
    - 面向“节点 (node)”而不是“代码行 (line)”；
    - 不直接返回 bool，而是通过 context.add_finding() 记录结果；
    - 通过 supports(language) 控制规则适用的语言集合。
    """

    def __init__(self, rule_id: str, severity: str, languages: Iterable[str] | None = None) -> None:
        """
        Args:
            rule_id: 规则唯一标识（如 "SQL_INJECTION"）
            severity: 严重程度（Critical/High/Medium/Low）
            languages: 适用语言列表（如 ["python", "javascript"]），为空则表示所有语言。
        """
        self.rule_id = rule_id
        self.severity = severity
        self._languages: set[str] = set(languages or [])

    # ------------------------------------------------------------------
    # 元信息
    # ------------------------------------------------------------------
    @property
    def languages(self) -> set[str]:
        """返回规则适用的语言集合。"""
        return self._languages

    def supports(self, language: str) -> bool:
        """
        判断规则是否适用于给定语言。

        如果未显式指定 languages，则视为支持所有语言。
        """
        return not self._languages or language in self._languages

    # ------------------------------------------------------------------
    # 核心接口：访问 AST 节点
    # ------------------------------------------------------------------
    @abstractmethod
    def visit(self, node: Any, context: AnalysisContext) -> None:
        """
        访问一个 AST 节点。

        规则实现者可以在这里：
        - 检查当前节点是否命中危险模式；
        - 必要时访问子节点（如果不依赖统一的遍历器）；
        - 通过 context.add_finding() 追加扫描结果。
        """

    # ------------------------------------------------------------------
    # 可选：在整文件分析前后做准备/收尾
    # ------------------------------------------------------------------
    def before_file(self, context: AnalysisContext) -> None:
        """
        在遍历文件 AST 之前调用。

        可以在这里初始化规则内部状态，例如清空缓存、准备符号表等。
        默认实现为空，实现类可按需重写。
        """

    def after_file(self, context: AnalysisContext) -> None:
        """
        在遍历完整个文件 AST 之后调用。

        适用于需要“全局视角”的规则（例如先收集信息，再统一下结论）。
        默认实现为空，实现类可按需重写。
        """


def safe_find_paths(graph: Any, rule_id: str) -> list:
    """
    安全执行 graph.find_paths_to_sinks()，异常时记录日志并返回空列表。
    供各 ast_rule 的 after_file 统一使用，避免散布的 try/except。
    """
    try:
        return graph.find_paths_to_sinks()
    except Exception as e:
        _rule_logger.debug(
            "find_paths_to_sinks failed in rule %s: %s", rule_id, e
        )
        return []
