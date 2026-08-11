"""
nosql_injection.java_ast_rule

Java NoSQL 注入规则（AST + bounded fallback）。

当前 PoC 目标：
- 覆盖典型模式：MongoDB/ODM 查询方法的参数直接包含 Servlet request input。
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


_REQUEST_VAR_DEFAULTS = frozenset({"request", "req"})
_REQUEST_TYPES = frozenset({"HttpServletRequest", "ServletRequest"})
_JAVA_USER_INPUT_METHODS = frozenset(
    {
        "getParameter",
        "getParameterValues",
        "getHeader",
        "getCookies",
        "getInputStream",
        "getReader",
        "getQueryString",
        "getRequestURI",
        "getPathInfo",
        "getBody",
    }
)


class JavaNoSQLInjectionAstRule(SecurityRule):
    """基于 AST 与 bounded fallback 的 Java NoSQL 注入检测规则。

    该规则不依赖 TaintGraph，优先在 method_invocation 内做 AST 检查，
    并在 `after_file` 中保留单个调用边界内的文本 fallback，
    用于补齐 Java 语言的 NoSQL 注入检测能力。
    """

    _NOSQL_METHODS = frozenset(
        ["find", "findOne", "update", "updateOne", "updateMany", "deleteOne", "deleteMany", "aggregate"]
    )
    _JAVA_NOSQL_CALL_START_RE = re.compile(
        r"\.\s*(?:find|findOne|update|updateOne|updateMany|deleteOne|deleteMany|aggregate)\s*\("
    )
    _JAVA_REQUEST_VAR_DECL_RE = re.compile(
        r"\b(?:final\s+)?(?:[\w.]+\.)?(?:HttpServletRequest|ServletRequest)\s+([A-Za-z_]\w*)"
    )

    def __init__(self) -> None:
        """初始化 Java NoSQL 注入规则。"""
        super().__init__(
            rule_id="NOSQL_INJECTION_JAVA_AST",
            severity="High",
            languages=["java"],
        )
        self._reported_lines: set[int] = set()
        self._request_vars: set[str] = set()

    def before_file(self, context: AnalysisContext) -> None:  # type: ignore[override]
        self._reported_lines = set()
        self._request_vars = set(_REQUEST_VAR_DEFAULTS)

    def visit(self, node: Any, context: AnalysisContext) -> None:  # type: ignore[override]
        """检测单个 Java Mongo/ODM method invocation 内的请求输入。"""
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        if node.type in ("formal_parameter", "local_variable_declaration", "field_declaration"):
            self._track_request_variable(node)
            return

        if node.type != "method_invocation":
            return

        method_name = self._get_method_name(node)
        if method_name not in self._NOSQL_METHODS:
            return

        if not any(self._subtree_has_request_input(arg) for arg in self._get_arguments(node)):
            return

        line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
        self._report(line_no, context)

    def after_file(self, context: AnalysisContext) -> None:  # type: ignore[override]
        """在文件分析结束后执行 bounded NoSQL 注入模式匹配。

        Args:
            context: 分析上下文。
        """
        source = context.extras.get("source", "")
        if not source:
            return

        request_vars = self._request_vars | self._collect_request_var_names_from_source(source)
        for match in self._iter_nosql_call_matches(source, request_vars):
            line_no = source[: match.start()].count("\n") + 1
            self._report(line_no, context)

    @staticmethod
    def _get_node_text(node: Any) -> str | None:
        if hasattr(node, "text"):
            raw = node.text
            return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        return None

    @staticmethod
    def _get_method_name(node: Any) -> str | None:
        method_index = JavaNoSQLInjectionAstRule._get_method_identifier_index(node)
        if method_index is None:
            return None
        return JavaNoSQLInjectionAstRule._get_node_text(node.children[method_index])

    @staticmethod
    def _get_method_identifier_index(node: Any) -> int | None:
        children = list(getattr(node, "children", []) or [])
        argument_index = next(
            (index for index, child in enumerate(children) if child.type == "argument_list"),
            len(children),
        )
        for index in range(argument_index - 1, -1, -1):
            if children[index].type == "identifier":
                return index
        return None

    @staticmethod
    def _get_receiver_node(node: Any) -> Any | None:
        children = list(getattr(node, "children", []) or [])
        method_index = JavaNoSQLInjectionAstRule._get_method_identifier_index(node)
        if method_index is None:
            return None

        index = method_index - 1
        while index >= 0 and children[index].type in (".", "::"):
            index -= 1
        if index < 0:
            return None
        return children[index]

    @staticmethod
    def _get_arguments(node: Any) -> list[Any]:
        for child in getattr(node, "children", []) or []:
            if child.type == "argument_list":
                return [c for c in child.children if c.type not in ("(", ")", ",")]
        return []

    def _track_request_variable(self, node: Any) -> None:
        type_name = self._extract_declared_type(node)
        if type_name not in _REQUEST_TYPES:
            return

        for child in getattr(node, "children", []) or []:
            if child.type == "identifier":
                name = self._get_node_text(child)
                if name:
                    self._request_vars.add(name)
            elif child.type == "variable_declarator":
                var_name = self._extract_variable_declarator_name(child)
                if var_name:
                    self._request_vars.add(var_name)

    def _subtree_has_request_input(self, node: Any) -> bool:
        if self._is_request_input_call(node):
            return True
        return any(self._subtree_has_request_input(child) for child in getattr(node, "children", []) or [])

    def _is_request_input_call(self, node: Any) -> bool:
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return False
        if node.type != "method_invocation":
            return False

        method_name = self._get_method_name(node)
        if method_name not in _JAVA_USER_INPUT_METHODS:
            return False

        receiver = self._get_receiver_node(node)
        receiver_text = self._get_node_text(receiver) if receiver is not None else None
        return bool(receiver_text and receiver_text in self._request_vars)

    def _extract_declared_type(self, node: Any) -> str | None:
        for child in getattr(node, "children", []) or []:
            if child.type in ("type_identifier", "scoped_type_identifier", "generic_type"):
                return self._simple_type_name(self._get_node_text(child) or "")
        return None

    def _extract_variable_declarator_name(self, node: Any) -> str | None:
        for child in getattr(node, "children", []) or []:
            if child.type == "identifier":
                return self._get_node_text(child)
        return None

    @staticmethod
    def _simple_type_name(type_text: str) -> str:
        clean = type_text.strip()
        if "<" in clean:
            clean = clean.split("<", 1)[0]
        clean = clean.replace("[]", "").strip()
        return clean.rsplit(".", 1)[-1]

    def _iter_nosql_call_matches(self, source: str, request_vars: set[str]) -> list[re.Match[str]]:
        matches: list[re.Match[str]] = []
        sanitized_source = self._mask_comments_and_strings(source)
        for match in self._JAVA_NOSQL_CALL_START_RE.finditer(sanitized_source):
            open_paren = sanitized_source.find("(", match.start(), match.end())
            if open_paren < 0:
                continue
            close_paren = self._find_matching_paren(sanitized_source, open_paren)
            if close_paren is None:
                continue
            call_text = sanitized_source[match.start() : close_paren + 1]
            if self._call_text_has_request_input(call_text, request_vars):
                matches.append(match)
        return matches

    def _call_text_has_request_input(self, call_text: str, request_vars: set[str]) -> bool:
        if not request_vars:
            return False
        receivers = "|".join(re.escape(var_name) for var_name in sorted(request_vars))
        methods = "|".join(re.escape(method_name) for method_name in sorted(_JAVA_USER_INPUT_METHODS))
        return bool(re.search(rf"\b(?:{receivers})\s*\.\s*(?:{methods})\s*\(", call_text))

    @staticmethod
    def _collect_request_var_names_from_source(source: str) -> set[str]:
        return set(_REQUEST_VAR_DEFAULTS) | {
            match.group(1) for match in JavaNoSQLInjectionAstRule._JAVA_REQUEST_VAR_DECL_RE.finditer(source)
        }

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
                if ch == "\\":
                    escaped = True
                    continue
                if ch == quote:
                    quote = None
                continue

            if ch in ('"', "'"):
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

    @staticmethod
    def _mask_comments_and_strings(source: str) -> str:
        """Blank comments and literals while preserving offsets and newlines."""
        chars = list(source)
        index = 0
        in_line_comment = False
        in_block_comment = False
        quote: str | None = None
        escaped = False

        while index < len(chars):
            char = chars[index]
            next_char = chars[index + 1] if index + 1 < len(chars) else ""

            if in_line_comment:
                if char != "\n":
                    chars[index] = " "
                else:
                    in_line_comment = False
                index += 1
                continue

            if in_block_comment:
                if char == "*" and next_char == "/":
                    chars[index] = " "
                    chars[index + 1] = " "
                    in_block_comment = False
                    index += 2
                else:
                    if char != "\n":
                        chars[index] = " "
                    index += 1
                continue

            if quote is not None:
                if char != "\n":
                    chars[index] = " "
                if escaped:
                    escaped = False
                    index += 1
                    continue
                if char == "\\":
                    escaped = True
                    index += 1
                    continue
                if char == quote:
                    quote = None
                index += 1
                continue

            if char == "/" and next_char == "/":
                chars[index] = " "
                chars[index + 1] = " "
                in_line_comment = True
                index += 2
                continue

            if char == "/" and next_char == "*":
                chars[index] = " "
                chars[index + 1] = " "
                in_block_comment = True
                index += 2
                continue

            if char in ('"', "'"):
                chars[index] = " "
                quote = char
                index += 1
                continue

            index += 1

        return "".join(chars)

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
                "检测到 Java 代码中使用 Servlet 请求输入直接构造 NoSQL 查询条件，"
                "存在 NoSQL 注入风险，建议进行白名单过滤或参数绑定。"
            ),
        }
        context.add_finding(finding)


__all__ = ["JavaNoSQLInjectionAstRule"]
