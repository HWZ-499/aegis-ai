"""
sql_injection.java_ast_rule

Java SQL 注入 AST/污点规则。

检测目标：
1. Tree-sitter AST 节点级分析（visit）：
   - 字符串拼接构造 SQL（"SELECT..." + var）
   - Statement.executeQuery/executeUpdate 参数中包含拼接
   - 参数化查询识别（PreparedStatement）→ 安全
2. TaintGraph 路径分析（after_file，兜底）：
   - 通过 SourceSinkRegistry 的 Java Sources/Sinks 追踪用户输入到 SQL sink。
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

# Java SQL 执行方法（sink）
_SQL_EXEC_METHODS = frozenset(
    [
        "executeQuery",
        "executeUpdate",
        "execute",
        "addBatch",
        "prepareStatement",
    ]
)

# 安全方法 — 使用 PreparedStatement 的调用不应报告
_SAFE_PREPARED_METHODS = frozenset(["prepareStatement", "prepareCall"])

# 非 DB receiver（排除误报，如 task.execute()）
_NON_DB_RECEIVERS = frozenset(
    [
        "task",
        "workflow",
        "executor",
        "runner",
        "thread",
        "process",
        "command",
        "action",
        "job",
        "handler",
        "Runtime",
    ]
)


class JavaSQLInjectionAstRule(SecurityRule):
    """
    基于 Tree-sitter AST + TaintGraph 的 Java SQL 注入检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="SQL_INJECTION_JAVA_TAINT",
            severity="High",
            languages=["java"],
        )
        self._reported_lines: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported_lines = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """
        逐节点 AST 分析：检测字符串拼接、模板构造 SQL 等模式。
        """
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        # 1. 检测方法调用中的 SQL 拼接
        if node.type == "method_invocation":
            self._check_method_invocation(node, context)

        # 2. 检测字符串拼接（binary_expression with +）
        elif node.type == "binary_expression":
            self._check_string_concatenation(node, context)

    def _check_method_invocation(self, node: Any, context: AnalysisContext) -> None:
        """检测 stmt.executeQuery("..." + var) 等模式。"""
        method_name = self._get_method_name(node)
        if method_name is None:
            return

        # 排除非 DB receiver
        receiver = self._get_receiver_name(node)
        if receiver and receiver in _NON_DB_RECEIVERS:
            return

        # prepareStatement("..." + var) — 虽然用了 PreparedStatement，但 SQL 本身拼接了
        # executeQuery("..." + var) — 直接拼接
        if method_name not in _SQL_EXEC_METHODS:
            return

        # 获取参数列表
        args = self._get_arguments(node)
        if not args:
            return

        first_arg = args[0]

        # 参数化查询检测：纯字符串字面量（含占位符 ?）→ 安全
        if self._is_parameterized_query(first_arg):
            return

        # 检测参数是否包含字符串拼接
        if first_arg.type == "binary_expression":
            if self._has_sql_concat_with_input(first_arg, context):
                self._report(node, context, method_name)
        elif first_arg.type == "identifier":
            # 变量传入 — 检查是否被污点标记
            if is_user_input_node(first_arg, context, language="java"):
                self._report(node, context, method_name)

    def _check_string_concatenation(self, node: Any, context: AnalysisContext) -> None:
        """检测独立的 SQL 字符串拼接（不在方法调用内时作为补充检测）。"""
        # 只处理 + 运算符
        op = self._get_operator(node)
        if op != "+":
            return

        text = self._get_node_text(node) or ""
        text_lower = text.lower()

        # 必须包含 SQL 关键词
        if not any(kw in text_lower for kw in _SQL_KEYWORDS):
            return

        # 检查是否包含用户输入
        if not self._subtree_has_user_input(node, context):
            return

        # 如果已经被 method_invocation 检测报过，跳过
        line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
        if line in self._reported_lines:
            return

        # Sanitizer 感知
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
                "检测到 Java 代码中 SQL 字符串拼接且含用户可控输入，"
                "存在 SQL 注入风险，建议使用 PreparedStatement 参数绑定。"
            ),
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)

    def after_file(self, context: AnalysisContext) -> None:
        """
        TaintGraph 兜底：在 AST visit 未覆盖的情况下，读取 TaintGraph 路径。
        """
        graph = getattr(context, "taint_graph", None)
        any_reported = False
        if graph is not None:
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
                # 跳过 visit 阶段已报告的行
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
                        "检测到 Java 代码中用户可控输入流入 SQL 执行点，"
                        "且未检测到参数化查询或有效净化，建议使用 PreparedStatement。"
                    ),
                    "source_expr": src_expr,
                    "sink_expr": sink_expr,
                }
                context.add_finding(finding)
                any_reported = True

        if any_reported or self._reported_lines:
            return

        # 最终兜底：正则模式匹配
        source_code = context.extras.get("source") or ""
        if not source_code:
            return
        pattern = re.compile(
            r"""(?im)\bexecute(?:Query|Update)?\s*\([^;]*request\.getParameter\s*\(""",
        )
        for m in pattern.finditer(source_code):
            line_no = source_code[: m.start()].count("\n") + 1
            sink_expr = m.group(0).strip()
            finding: dict[str, Any] = {
                "type": "SQL_INJECTION",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": ("检测到 Java 代码中使用 request.getParameter 拼接 SQL，建议改用 PreparedStatement。"),
                "source_expr": "request.getParameter(...)",
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
    def _get_operator(node: Any) -> str | None:
        """从 binary_expression 提取运算符。"""
        for child in node.children:
            text = child.type if hasattr(child, "type") else ""
            if text in ("+", "-", "*", "/"):
                return text
        return None

    @staticmethod
    def _get_method_name(node: Any) -> str | None:
        """从 method_invocation 节点提取方法名。"""
        for child in node.children:
            if child.type == "identifier":
                text = child.text
                return text.decode("utf-8") if isinstance(text, bytes) else str(text)
        # 可能是 obj.method 形式
        for child in node.children:
            if child.type == "member_expression" or child.type == ".":
                continue
            if child.type == "identifier":
                text = child.text
                return text.decode("utf-8") if isinstance(text, bytes) else str(text)
        return None

    @staticmethod
    def _get_receiver_name(node: Any) -> str | None:
        """提取方法调用的 receiver 名称。"""
        children = list(node.children)
        if len(children) >= 3 and children[1].type == ".":
            first = children[0]
            if first.type == "identifier":
                text = first.text
                return text.decode("utf-8") if isinstance(text, bytes) else str(text)
        return None

    @staticmethod
    def _get_arguments(node: Any) -> list[Any]:
        """提取方法调用的参数节点列表。"""
        for child in node.children:
            if child.type == "argument_list":
                return [c for c in child.children if c.type not in ("(", ")", ",")]
        return []

    def _is_parameterized_query(self, arg_node: Any) -> bool:
        """判断参数是否是包含 ? 占位符的纯字符串字面量。"""
        if arg_node.type == "string_literal":
            text = self._get_node_text(arg_node) or ""
            return "?" in text
        return False

    def _has_sql_concat_with_input(self, node: Any, context: AnalysisContext) -> bool:
        """检测 binary_expression 是否包含 SQL 关键词 + 用户输入。"""
        text = self._get_node_text(node) or ""
        text_lower = text.lower()
        has_sql = any(kw in text_lower for kw in _SQL_KEYWORDS)
        if not has_sql:
            return False
        return self._subtree_has_user_input(node, context)

    def _subtree_has_user_input(self, node: Any, context: AnalysisContext) -> bool:
        """递归检查子树中是否包含用户输入节点。"""
        if is_user_input_node(node, context, language="java"):
            return True
        for child in getattr(node, "children", []) or []:
            if self._subtree_has_user_input(child, context):
                return True
        return False

    def _collect_identifiers(self, node: Any) -> list[str]:
        """收集子树中所有 identifier 文本。"""
        result: list[str] = []
        if node.type == "identifier":
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

        # Sanitizer 感知
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
                "存在 SQL 注入风险，建议使用 PreparedStatement 参数绑定。"
            ),
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)


__all__ = ["JavaSQLInjectionAstRule"]
