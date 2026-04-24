"""
xss.go_ast_rule

Go XSS 风险 AST/污点规则。

检测目标：
1. Tree-sitter AST 节点级分析（visit）：
   - fmt.Fprintf(w, userInput) — 直接写入 ResponseWriter
   - w.Write([]byte(userInput))
   - template.HTML(userInput) — 不安全的模板标记
2. TaintGraph 路径分析（after_file，兜底）。
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

# 可能输出到 HTTP 响应的函数
_XSS_SINK_FUNCS = frozenset(["Fprintf", "Fprintln", "Fprint", "Write", "WriteString", "SendString"])

# HTML 转义函数（sanitizer）
_SANITIZERS = frozenset(["HTMLEscapeString", "EscapeString", "html.EscapeString", "template.HTMLEscapeString"])

_GO_USER_INPUT_CALL_RE = re.compile(
    r"\b(?:c|ctx|r|req|request)\.(?:Query|FormValue|PostForm|PostFormValue|Param|DefaultQuery)\s*\(",
    re.IGNORECASE,
)


class GoXSSAstRule(SecurityRule):
    """
    基于 Tree-sitter AST + TaintGraph 的 Go XSS 风险检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="XSS_RISK_GO_TAINT",
            severity="High",
            languages=["go"],
        )
        self._reported_lines: set[int] = set()
        self._var_assignments: dict[str, Any] = {}
        self._var_assignment_history: dict[str, list[tuple[int, Any]]] = {}

    def before_file(self, context: AnalysisContext) -> None:
        self._reported_lines = set()
        self._var_assignments = {}
        self._var_assignment_history = {}

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        if node.type in ("short_var_declaration", "assignment_statement"):
            self._track_expr_list_assignment(node)
        elif node.type == "var_spec":
            self._track_var_spec_assignment(node)

        if node.type == "call_expression":
            self._check_call_expression(node, context)

    def _check_call_expression(self, node: Any, context: AnalysisContext) -> None:
        """检测 fmt.Fprintf(w, userInput) 等。"""
        func_name, pkg_name = self._get_qualified_name(node)
        if func_name is None:
            return

        # fmt.Sprintf("<html...%s...", userInput) — 在构造 HTML 阶段即已形成 XSS 风险
        if func_name == "Sprintf" and self._is_html_sprintf_with_user_input(node, context):
            self._report(node, context, "fmt.Sprintf")
            return

        # template.HTML(userInput) — 绕过模板自动转义
        if func_name == "HTML" and pkg_name == "template":
            args = self._get_arguments(node)
            for arg in args:
                if self._subtree_has_user_input(arg, context):
                    self._report(node, context, "template.HTML")
                    return
            return

        if func_name not in _XSS_SINK_FUNCS:
            return

        args = self._get_arguments(node)
        if not args:
            return

        # 若 SendString 直接输出由 fmt.Sprintf(HTML, userInput) 构造的变量，
        # 优先在 Sprintf 位置报警，避免同一问题重复在输出行再次告警。
        if func_name == "SendString":
            first_arg = args[0]
            if getattr(first_arg, "type", "") == "identifier":
                assigned_expr = self._resolve_identifier_expr(first_arg)
                if assigned_expr is not None and getattr(assigned_expr, "type", "") == "call_expression":
                    inner_func, _ = self._get_qualified_name(assigned_expr)
                    if inner_func == "Sprintf" and self._is_html_sprintf_with_user_input(assigned_expr, context):
                        return

        # fmt.Fprintf(w, format, args...) — 第一个参数是 writer，第二个及之后是数据
        # w.Write(data) — 第一个参数是数据
        start_idx = 0
        if func_name in ("Fprintf", "Fprintln", "Fprint") and len(args) > 1:
            start_idx = 1  # 跳过 writer 参数

        for arg in args[start_idx:]:
            # 检查是否经过 HTML 转义
            arg_text = self._get_node_text(arg) or ""
            if any(s in arg_text for s in _SANITIZERS):
                return

            if self._subtree_has_user_input(arg, context):
                identifiers = self._collect_identifiers(arg)
                if identifiers and (context.taint_graph or context.dataflow_tracker):
                    if all(context.is_var_sanitized(v) for v in identifiers):
                        return

                display = f"{pkg_name}.{func_name}" if pkg_name else func_name
                self._report(node, context, display)
                return

    def after_file(self, context: AnalysisContext) -> None:
        """TaintGraph 兜底。"""
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
            if category != "xss":
                continue
            line_no = getattr(sink, "line", 0) or 0
            if line_no in self._reported_lines:
                continue
            reported_sinks.add(sink_id)
            src_expr = getattr(source, "name", "") or getattr(source, "code_snippet", "")
            sink_expr = getattr(sink, "name", "") or getattr(sink, "code_snippet", "")

            if not self._fallback_sink_has_real_user_input(line_no, sink_expr, context):
                continue

            finding: dict[str, Any] = {
                "type": "XSS_RISK",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": (
                    "检测到 Go 代码中用户可控输入通过 fmt.Fprintf 输出到响应，且未检测到 HTML 转义，存在 XSS 风险。"
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
    def _get_qualified_name(node: Any) -> tuple[str | None, str | None]:
        for child in node.children:
            if child.type == "selector_expression":
                parts = []
                for sub in child.children:
                    if sub.type in ("identifier", "field_identifier"):
                        text = sub.text
                        parts.append(text.decode("utf-8") if isinstance(text, bytes) else str(text))
                if len(parts) >= 2:
                    return parts[-1], parts[0]
                if len(parts) == 1:
                    return parts[0], None
            if child.type == "identifier":
                text = child.text
                name = text.decode("utf-8") if isinstance(text, bytes) else str(text)
                return name, None
        return None, None

    @staticmethod
    def _get_arguments(node: Any) -> list[Any]:
        for child in node.children:
            if child.type == "argument_list":
                return [c for c in child.children if c.type not in ("(", ")", ",")]
        return []

    def _subtree_has_user_input(self, node: Any, context: AnalysisContext) -> bool:
        text = self._get_node_text(node) or ""
        if text and _GO_USER_INPUT_CALL_RE.search(text):
            return True

        if getattr(node, "type", "") == "identifier":
            assigned_expr = self._resolve_identifier_expr(node)
            if assigned_expr is not None:
                return self._expr_derives_from_user_input(assigned_expr, context, set())
            # 回退：仅当存在明确 taint 信息时使用 context
            return is_user_input_node(node, context, language="go")

        for child in getattr(node, "children", []) or []:
            if self._subtree_has_user_input(child, context):
                return True
        return False

    def _expr_derives_from_user_input(self, node: Any, context: AnalysisContext, seen_vars: set[str]) -> bool:
        text = self._get_node_text(node) or ""
        if text and _GO_USER_INPUT_CALL_RE.search(text):
            return True

        ntype = getattr(node, "type", "")
        if ntype == "identifier":
            name = self._get_node_text(node) or ""
            if not name or name in seen_vars:
                return False
            seen_vars.add(name)
            assigned = self._var_assignments.get(name)
            if assigned is None:
                return is_user_input_node(node, context, language="go")
            return self._expr_derives_from_user_input(assigned, context, seen_vars)

        if ntype == "binary_expression":
            for child in getattr(node, "children", []) or []:
                if self._expr_derives_from_user_input(child, context, seen_vars):
                    return True
            return False

        if ntype == "call_expression":
            func_name, _ = self._get_qualified_name(node)
            if func_name == "Sprintf":
                args = self._get_arguments(node)
                for arg in args[1:]:
                    if self._expr_derives_from_user_input(arg, context, seen_vars):
                        return True
                return False
            # 对于其他函数调用，保守处理，避免把常量/模板字符串误判为用户输入
            return False

        for child in getattr(node, "children", []) or []:
            if self._expr_derives_from_user_input(child, context, seen_vars):
                return True
        return False

    def _is_html_sprintf_with_user_input(self, node: Any, context: AnalysisContext) -> bool:
        args = self._get_arguments(node)
        if len(args) < 2:
            return False

        fmt_text = self._get_node_text(args[0]) or ""
        fmt_lower = fmt_text.lower()
        if "<" not in fmt_text or ">" not in fmt_text:
            return False
        if "%s" not in fmt_text and "%v" not in fmt_text:
            return False
        if "<script" in fmt_lower:
            # 出现显式 script 标签时直接视为高风险输出构造
            return True

        for arg in args[1:]:
            if self._subtree_has_user_input(arg, context):
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

    def _resolve_var_expr_at_line(self, var_name: str, line_no: int, seen_vars: set[str]) -> Any | None:
        if var_name in seen_vars:
            return None
        seen_vars.add(var_name)

        history = self._var_assignment_history.get(var_name) or []
        chosen_expr: Any | None = None
        best_line = -1
        for assign_line, expr in history:
            if assign_line <= line_no and assign_line >= best_line:
                best_line = assign_line
                chosen_expr = expr

        if chosen_expr is None:
            return None

        if getattr(chosen_expr, "type", "") == "identifier":
            nested_name = self._get_node_text(chosen_expr) or ""
            if nested_name:
                nested = self._resolve_var_expr_at_line(nested_name, line_no, seen_vars)
                if nested is not None:
                    return nested
        return chosen_expr

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
            line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
            self._record_var_assignment(name, line, right_nodes[idx])

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
            line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
            self._record_var_assignment(name, line, right_nodes[idx])

    def _record_var_assignment(self, name: str, line: int, expr_node: Any) -> None:
        self._var_assignments[name] = expr_node
        if name not in self._var_assignment_history:
            self._var_assignment_history[name] = []
        self._var_assignment_history[name].append((line, expr_node))

    def _fallback_sink_has_real_user_input(self, line_no: int, sink_expr: str, context: AnalysisContext) -> bool:
        source_code = context.extras.get("source") or ""
        line_text = ""
        if source_code:
            lines = source_code.splitlines()
            if 1 <= line_no <= len(lines):
                line_text = lines[line_no - 1].strip()

        candidate = line_text or sink_expr
        if "SendString(" not in candidate:
            return True

        arg_text = self._extract_sendstring_arg(candidate)
        if not arg_text:
            return True
        arg = arg_text.strip()
        if not arg:
            return False
        if arg.startswith('"') or arg.startswith("`"):
            return False
        if _GO_USER_INPUT_CALL_RE.search(arg):
            return True
        if re.fullmatch(r"[A-Za-z_]\w*", arg):
            assigned = self._resolve_var_expr_at_line(arg, line_no, set())
            if assigned is None:
                return False
            if getattr(assigned, "type", "") == "call_expression":
                inner_func, _ = self._get_qualified_name(assigned)
                if inner_func == "Sprintf" and self._is_html_sprintf_with_user_input(assigned, context):
                    # 在 Sprintf 位置报警即可，避免同一流在 SendString 行重复告警
                    return False
            return self._expr_derives_from_user_input(assigned, context, set())
        return False

    @staticmethod
    def _extract_sendstring_arg(text: str) -> str | None:
        m = re.search(r"SendString\s*\((.*)\)\s*$", text)
        if not m:
            return None
        return m.group(1)

    def _collect_identifiers(self, node: Any) -> list[str]:
        result: list[str] = []
        if node.type in ("identifier", "field_identifier"):
            text = self._get_node_text(node)
            if text:
                result.append(text)
        for child in getattr(node, "children", []) or []:
            result.extend(self._collect_identifiers(child))
        return result

    def _report(self, node: Any, context: AnalysisContext, func_desc: str) -> None:
        line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
        if line in self._reported_lines:
            return
        self._reported_lines.add(line)
        finding: dict[str, Any] = {
            "type": "XSS_RISK",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line,
            "details": (
                f"检测到 {func_desc}() 调用中包含用户可控输入直接写入响应，"
                "且未检测到 HTML 转义，存在 XSS 风险，建议使用 template.HTMLEscapeString 转义。"
            ),
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)


__all__ = ["GoXSSAstRule"]
