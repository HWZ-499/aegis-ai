"""
nosql_injection.go_ast_rule

Go NoSQL 注入规则（行级模式匹配版）。

当前 PoC 目标：
- 覆盖典型模式：MongoDB/ODM 查询方法的参数直接包含 `r.FormValue(...)`
  或 `r.URL.Query().Get(...)` 等用户输入。
"""

from __future__ import annotations

import re
from typing import Any

from ...base import AnalysisContext, SecurityRule

try:
    from tree_sitter import Node

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any  # type: ignore[misc,assignment]


class GoNoSQLInjectionAstRule(SecurityRule):
    """基于源码行级模式的 Go NoSQL 注入检测规则。

    该规则不依赖 TaintGraph，仅在 `after_file` 钩子中扫描源码，
    用于补齐 Go 语言的 NoSQL 注入检测能力。
    """

    _NOSQL_METHODS = frozenset(
        ["Find", "FindOne", "Update", "UpdateOne", "UpdateMany", "DeleteOne", "DeleteMany", "Aggregate"]
    )
    _GO_USER_INPUT_CALL_RE = re.compile(
        r"\b(?:c|ctx|r|req|request)\.(?:Query|FormValue|PostForm|PostFormValue|Param|DefaultQuery)\s*\("
        r"|\b(?:r|req|request)\.URL\.Query\(\)\.Get\s*\(",
        re.IGNORECASE,
    )
    _GO_NOSQL_CALL_START_RE = re.compile(
        r"\.\s*(?:Find|FindOne|Update|UpdateOne|UpdateMany|DeleteOne|DeleteMany|Aggregate)\s*\(",
        re.IGNORECASE | re.VERBOSE,
    )

    def __init__(self) -> None:
        """初始化 Go NoSQL 注入规则。"""
        super().__init__(
            rule_id="NOSQL_INJECTION_GO_AST",
            severity="High",
            languages=["go"],
        )
        self._reported_lines: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:  # type: ignore[override]
        self._reported_lines = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:  # type: ignore[override]
        """检测单个 Mongo/ODM call expression 内的用户输入。"""
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        if node.type != "call_expression":
            return

        method_name = self._get_method_name(node)
        if method_name not in self._NOSQL_METHODS:
            return

        call_text = self._get_node_text(node) or ""
        if not self._GO_USER_INPUT_CALL_RE.search(call_text):
            return

        self._report(node.start_point[0] + 1 if hasattr(node, "start_point") else 0, context)

    def after_file(self, context: AnalysisContext) -> None:  # type: ignore[override]
        """在文件分析结束后执行 bounded fallback NoSQL 注入模式匹配。

        Args:
            context: 分析上下文。
        """
        source = context.extras.get("source", "")
        if not source:
            return

        for match in self._iter_nosql_call_matches(source):
            line_no = source[: match.start()].count("\n") + 1
            self._report(line_no, context)

    @staticmethod
    def _get_node_text(node: Any) -> str | None:
        if hasattr(node, "text"):
            raw = node.text
            return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        return None

    def _get_method_name(self, node: Any) -> str | None:
        for child in getattr(node, "children", []) or []:
            if getattr(child, "type", "") != "selector_expression":
                continue
            for sub in getattr(child, "children", []) or []:
                if getattr(sub, "type", "") == "field_identifier":
                    return self._get_node_text(sub)
        return None

    def _iter_nosql_call_matches(self, source: str) -> list[re.Match[str]]:
        matches: list[re.Match[str]] = []
        for match in self._GO_NOSQL_CALL_START_RE.finditer(source):
            open_paren = source.find("(", match.start(), match.end())
            if open_paren < 0:
                continue
            close_paren = self._find_matching_paren(source, open_paren)
            if close_paren is None:
                continue
            call_text = source[match.start() : close_paren + 1]
            if self._GO_USER_INPUT_CALL_RE.search(call_text):
                matches.append(match)
        return matches

    @staticmethod
    def _find_matching_paren(source: str, open_paren: int) -> int | None:
        depth = 0
        quote: str | None = None
        escaped = False

        for index in range(open_paren, len(source)):
            ch = source[index]
            if quote is not None:
                if escaped:
                    escaped = False
                    continue
                if ch == "\\" and quote != "`":
                    escaped = True
                    continue
                if ch == quote:
                    quote = None
                continue

            if ch in ('"', "'", "`"):
                quote = ch
                continue
            if ch == "(":
                depth += 1
                continue
            if ch == ")":
                depth -= 1
                if depth == 0:
                    return index
        return None

    def _report(self, line_no: int, context: AnalysisContext) -> None:
        if line_no in self._reported_lines:
            return
        self._reported_lines.add(line_no)
        finding: dict[str, Any] = {
            "type": "NOSQL_INJECTION",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line_no,
            "details": (
                "检测到 Go 代码中使用 HTTP 请求参数直接构造 NoSQL 查询条件，"
                "存在 NoSQL 注入风险，建议进行白名单过滤或参数绑定。"
            ),
        }
        context.add_finding(finding)


__all__ = ["GoNoSQLInjectionAstRule"]
