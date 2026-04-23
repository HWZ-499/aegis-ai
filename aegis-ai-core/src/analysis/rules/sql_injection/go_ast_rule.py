"""
sql_injection.go_ast_rule

Go SQL 注入 AST/污点规则。

检测目标：
1. Tree-sitter AST 节点级分析（visit）：
   - 字符串拼接构造 SQL（"SELECT..." + var / fmt.Sprintf）
   - db.Query/db.Exec 参数中包含拼接
   - 参数化查询识别（占位符 $1 / ?）→ 安全
2. TaintGraph 路径分析（after_file，兜底）：
   - 通过 SourceSinkRegistry 的 Go Sources/Sinks 追踪用户输入到 SQL sink。
"""

from __future__ import annotations

import re
from typing import Any

from ...base import (
    AnalysisContext,
    SecurityRule,
    safe_find_paths,
    tree_sitter_node_to_range,
)
from ...base.user_input_detector import is_user_input_node

try:
    from tree_sitter import Node

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any  # type: ignore[misc,assignment]

# SQL 关键词
_SQL_KEYWORDS = frozenset(["select", "insert", "update", "delete", "drop", "create", "alter", "where"])

# Go database/sql 执行方法（sink）
_SQL_EXEC_METHODS = frozenset(
    [
        "Query",
        "QueryRow",
        "QueryContext",
        "QueryRowContext",
        "Exec",
        "ExecContext",
        "Prepare",
        "PrepareContext",
        # GORM
        "Raw",
        "Where",
        "Exec",
    ]
)

# Go 常见用户输入调用（用于 AST 本地传播）
_GO_USER_INPUT_CALL_RE = re.compile(
    r"\b(?:r|req|request)\.(?:FormValue|PostFormValue)\s*\("
    r"|\b(?:r|req|request)\.URL\.Query\s*\("
)


class GoSQLInjectionAstRule(SecurityRule):
    """
    基于 Tree-sitter AST + TaintGraph 的 Go SQL 注入检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="SQL_INJECTION_GO_TAINT",
            severity="High",
            languages=["go"],
        )
        self._reported_lines: set[int] = set()
        self._var_assignments: dict[str, Any] = {}

    def before_file(self, context: AnalysisContext) -> None:
        self._reported_lines = set()
        self._var_assignments = {}

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """
        逐节点 AST 分析：检测字符串拼接、fmt.Sprintf 构造 SQL 等模式。
        """
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        # 0. 跟踪局部变量赋值（用于 identifier 参数回溯）
        if node.type in ("short_var_declaration", "assignment_statement"):
            self._track_expr_list_assignment(node)
        elif node.type == "var_spec":
            self._track_var_spec_assignment(node)

        # 1. 检测函数/方法调用
        if node.type == "call_expression":
            self._check_call_expression(node, context)

        # 2. 检测字符串拼接（binary_expression with +）
        elif node.type == "binary_expression":
            self._check_string_concatenation(node, context)

    def _check_call_expression(self, node: Any, context: AnalysisContext) -> None:
        """检测 db.Query("..." + var) 和 fmt.Sprintf("SELECT...%s", var) 等模式。"""
        func_name = self._get_func_name(node)
        if func_name is None:
            return

        # fmt.Sprintf 检测
        if func_name == "Sprintf":
            self._check_sprintf_sql(node, context)
            return

        # db.Query / db.Exec 等
        if func_name not in _SQL_EXEC_METHODS:
            return

        args = self._get_arguments(node)
        if not args:
            return

        first_arg = args[0]

        # 参数化查询检测：纯字符串字面量含 $1 / ? → 安全
        if self._is_parameterized_query(first_arg):
            return

        # 字符串拼接
        if first_arg.type == "binary_expression":
            if self._has_sql_concat_with_input(first_arg, context):
                self._report(node, context, func_name)
        # fmt.Sprintf 结果传入
        elif first_arg.type == "call_expression":
            inner_func = self._get_func_name(first_arg)
            if inner_func == "Sprintf":
                self._check_sprintf_sql(first_arg, context)
        # 变量传入
        elif first_arg.type == "identifier":
            if is_user_input_node(first_arg, context, language="go"):
                self._report(node, context, func_name)
                return

            assigned_expr = self._resolve_identifier_expr(first_arg)
            if assigned_expr is None:
                return

            if self._is_parameterized_query(assigned_expr):
                return

            if assigned_expr.type == "binary_expression":
                if self._has_sql_concat_with_input(assigned_expr, context):
                    self._report(node, context, func_name)
                return

            if assigned_expr.type == "call_expression":
                inner_func = self._get_func_name(assigned_expr)
                if inner_func == "Sprintf" and self._is_sprintf_sql_with_input(assigned_expr, context):
                    self._report(node, context, func_name)
                return

            text = (self._get_node_text(assigned_expr) or "").lower()
            if any(kw in text for kw in _SQL_KEYWORDS) and self._subtree_has_user_input(assigned_expr, context):
                self._report(node, context, func_name)

    def _check_sprintf_sql(self, node: Any, context: AnalysisContext) -> None:
        """检测 fmt.Sprintf("SELECT...%s", userInput) 模式。"""
        if self._is_sprintf_sql_with_input(node, context):
            self._report(node, context, "fmt.Sprintf → SQL")

    def _is_sprintf_sql_with_input(self, node: Any, context: AnalysisContext) -> bool:
        """判断 fmt.Sprintf 是否在构造包含用户输入的 SQL。"""
        args = self._get_arguments(node)
        if len(args) < 2:
            return False

        # 第一个参数必须是含 SQL 关键词的格式字符串
        format_str = self._get_node_text(args[0]) or ""
        format_lower = format_str.lower()
        if not any(kw in format_lower for kw in _SQL_KEYWORDS):
            return False

        # 含 %s / %v 等格式化占位符
        if "%s" not in format_str and "%v" not in format_str and "%d" not in format_str:
            return False

        # 后续参数中是否有用户输入
        for arg in args[1:]:
            if self._subtree_has_user_input(arg, context):
                return True
        return False

    def _check_string_concatenation(self, node: Any, context: AnalysisContext) -> None:
        """检测独立的 SQL 字符串拼接。"""
        op = self._get_operator(node)
        if op != "+":
            return

        text = self._get_node_text(node) or ""
        text_lower = text.lower()
        if not any(kw in text_lower for kw in _SQL_KEYWORDS):
            return

        if not self._subtree_has_user_input(node, context):
            return

        line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
        if line in self._reported_lines:
            return

        identifiers = self._collect_identifiers(node)
        if identifiers and (context.taint_graph or context.dataflow_tracker):
            if all(context.is_var_sanitized(v) for v in identifiers):
                return

        self._reported_lines.add(line)
        finding: dict[str, Any] = {
            "type": "SQL_INJECTION",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line,
            "details": (
                "检测到 Go 代码中 SQL 字符串拼接且含用户可控输入，"
                "存在 SQL 注入风险，建议使用参数化查询（$1, $2 占位符）。"
            ),
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)

    def after_file(self, context: AnalysisContext) -> None:
        """TaintGraph 兜底：读取 TaintGraph 中 Source→Sink 路径。"""
        graph = getattr(context, "taint_graph", None)
        if graph is None:
            return

        reported_sinks: set[str] = set()
        paths = safe_find_paths(graph, self.rule_id)

        for path in paths:
            if getattr(path, "is_sanitized", False):
                continue
            sink = getattr(path, "sink_node", None)
            source = getattr(path, "source_node", None)
            if sink is None or source is None:
                continue
            sink_id = getattr(sink, "id", "")
            if not sink_id or sink_id in reported_sinks:
                continue
            category = (sink.extras or {}).get("category") if hasattr(sink, "extras") else None
            if category != "sql_injection":
                continue
            line_no = getattr(sink, "line", 0) or 0
            if line_no in self._reported_lines:
                continue
            reported_sinks.add(sink_id)
            src_expr = getattr(source, "name", "") or getattr(source, "code_snippet", "")
            sink_expr = getattr(sink, "name", "") or getattr(sink, "code_snippet", "")
            finding: dict[str, Any] = {
                "type": "SQL_INJECTION",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": (
                    "检测到 Go 代码中用户可控输入流入 database/sql Query/Exec，"
                    "且未检测到占位符参数绑定，建议使用 $1/$2 参数化查询。"
                ),
                "source_expr": src_expr,
                "sink_expr": sink_expr,
            }
            context.add_finding(finding)

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------
    @staticmethod
    def _get_node_text(node: Any) -> str | None:
        if hasattr(node, "text"):
            raw = node.text
            return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        return None

    @staticmethod
    def _get_func_name(node: Any) -> str | None:
        """从 call_expression 提取函数/方法名。"""
        for child in node.children:
            # db.Query → selector_expression → field_identifier
            if child.type == "selector_expression":
                for sub in child.children:
                    if sub.type == "field_identifier":
                        text = sub.text
                        return text.decode("utf-8") if isinstance(text, bytes) else str(text)
            # 直接函数调用 Query(...)
            if child.type == "identifier":
                text = child.text
                return text.decode("utf-8") if isinstance(text, bytes) else str(text)
        return None

    @staticmethod
    def _get_operator(node: Any) -> str | None:
        for child in node.children:
            text = child.type if hasattr(child, "type") else ""
            if text in ("+", "-", "*", "/"):
                return text
        return None

    @staticmethod
    def _get_arguments(node: Any) -> list[Any]:
        """提取函数调用的参数节点列表。"""
        for child in node.children:
            if child.type == "argument_list":
                return [c for c in child.children if c.type not in ("(", ")", ",")]
        return []

    def _is_parameterized_query(self, arg_node: Any) -> bool:
        """判断是否是含占位符的字符串字面量。"""
        text = self._get_node_text(arg_node) or ""
        # Go 的参数化占位符: $1, $2 (PostgreSQL) 或 ? (MySQL)
        if "$1" in text or "?" in text:
            return True
        return False

    def _has_sql_concat_with_input(self, node: Any, context: AnalysisContext) -> bool:
        text = self._get_node_text(node) or ""
        text_lower = text.lower()
        has_sql = any(kw in text_lower for kw in _SQL_KEYWORDS)
        if not has_sql:
            return False
        return self._subtree_has_user_input(node, context)

    def _subtree_has_user_input(
        self,
        node: Any,
        context: AnalysisContext,
        seen_vars: set[str] | None = None,
    ) -> bool:
        seen_vars = seen_vars or set()

        if is_user_input_node(node, context, language="go"):
            return True

        if self._looks_like_go_user_input_expr(node):
            return True

        if getattr(node, "type", "") == "identifier":
            var_name = self._get_node_text(node) or ""
            if var_name and var_name not in seen_vars:
                seen_vars.add(var_name)
                assigned_expr = self._var_assignments.get(var_name)
                if assigned_expr is not None and self._subtree_has_user_input(assigned_expr, context, seen_vars):
                    return True

        for child in getattr(node, "children", []) or []:
            if self._subtree_has_user_input(child, context, seen_vars):
                return True
        return False

    def _resolve_identifier_expr(self, node: Any) -> Any | None:
        if getattr(node, "type", "") != "identifier":
            return None
        var_name = self._get_node_text(node) or ""
        if not var_name:
            return None
        return self._resolve_var_expr(var_name, set())

    def _resolve_var_expr(self, var_name: str, seen_vars: set[str]) -> Any | None:
        if var_name in seen_vars:
            return None
        seen_vars.add(var_name)

        expr = self._var_assignments.get(var_name)
        if expr is None:
            return None

        if getattr(expr, "type", "") == "identifier":
            nested_name = self._get_node_text(expr) or ""
            if nested_name:
                nested = self._resolve_var_expr(nested_name, seen_vars)
                if nested is not None:
                    return nested

        return expr

    def _track_expr_list_assignment(self, node: Any) -> None:
        expr_lists = [c for c in node.children if getattr(c, "type", "") == "expression_list"]
        if len(expr_lists) < 2:
            return

        left_nodes = [c for c in expr_lists[0].children if getattr(c, "type", "") == "identifier"]
        right_nodes = [c for c in expr_lists[1].children if getattr(c, "type", "") != ","]
        if not left_nodes or not right_nodes:
            return

        for idx, left in enumerate(left_nodes):
            if idx >= len(right_nodes):
                break
            name = self._get_node_text(left) or ""
            if not name:
                continue
            self._var_assignments[name] = right_nodes[idx]

    def _track_var_spec_assignment(self, node: Any) -> None:
        left_names: list[str] = []
        right_nodes: list[Any] = []
        seen_values = False

        for child in node.children:
            ctype = getattr(child, "type", "")
            if ctype == "expression_list" and not seen_values:
                right_nodes = [c for c in child.children if getattr(c, "type", "") != ","]
                seen_values = True
                continue

            if not seen_values and ctype == "identifier":
                name = self._get_node_text(child) or ""
                if name:
                    left_names.append(name)

        if not left_names or not right_nodes:
            return

        for idx, name in enumerate(left_names):
            if idx >= len(right_nodes):
                break
            self._var_assignments[name] = right_nodes[idx]

    def _looks_like_go_user_input_expr(self, node: Any) -> bool:
        text = self._get_node_text(node) or ""
        if not text:
            return False
        return bool(_GO_USER_INPUT_CALL_RE.search(text))

    def _collect_identifiers(self, node: Any) -> list[str]:
        result: list[str] = []
        if node.type == "identifier" or node.type == "field_identifier":
            text = self._get_node_text(node)
            if text:
                result.append(text)
        for child in getattr(node, "children", []) or []:
            result.extend(self._collect_identifiers(child))
        return result

    def _report(self, node: Any, context: AnalysisContext, method_name: str) -> None:
        line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
        if line in self._reported_lines:
            return
        self._reported_lines.add(line)

        identifiers = self._collect_identifiers(node)
        if identifiers and (context.taint_graph or context.dataflow_tracker):
            if all(context.is_var_sanitized(v) for v in identifiers):
                return

        finding: dict[str, Any] = {
            "type": "SQL_INJECTION",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line,
            "details": (
                f"检测到 {method_name}() 调用中包含拼接的 SQL 字符串且含用户可控输入，"
                "存在 SQL 注入风险，建议使用参数化查询。"
            ),
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)


__all__ = ["GoSQLInjectionAstRule"]
