"""
rce.go_ast_rule

Go RCE / 命令执行 AST/污点规则。

检测目标：
1. Tree-sitter AST 节点级分析（visit）：
   - exec.Command(userInput)
   - exec.CommandContext(ctx, userInput)
   - syscall.Exec(userInput, ...)
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

# 危险的命令执行函数
_RCE_FUNCS = frozenset(["Command", "CommandContext", "Exec", "StartProcess"])

# 危险的包名
_RCE_PACKAGES = frozenset(["exec", "os", "syscall"])

_GO_SHELL_NAMES = frozenset(["sh", "/bin/sh", "bash", "/bin/bash"])
_GO_USER_INPUT_CALL_RE = re.compile(
    r"\b(?:c|ctx|r|req|request)\.(?:Query|FormValue|PostForm|PostFormValue|Param|DefaultQuery)\s*\(",
    re.IGNORECASE,
)


class GoRCEAstRule(SecurityRule):
    """
    基于 Tree-sitter AST + TaintGraph 的 Go RCE 检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="RCE_COMMAND_EXEC_GO_TAINT",
            severity="Critical",
            languages=["go"],
        )
        self._reported_lines: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported_lines = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        if node.type == "call_expression":
            self._check_call_expression(node, context)

    def _check_call_expression(self, node: Any, context: AnalysisContext) -> None:
        """检测 exec.Command(var), os.StartProcess(var, ...) 等。"""
        func_name, pkg_name = self._get_qualified_name(node)
        if func_name is None:
            return

        if func_name not in _RCE_FUNCS:
            return

        # 如果能识别包名，检查是否是危险包
        if pkg_name and pkg_name not in _RCE_PACKAGES:
            return

        args = self._get_arguments(node)
        if not args:
            return

        if self._is_shell_dynamic_exec(args, context):
            self._report(node, context, f"{pkg_name or ''}.{func_name}")
            return

        # exec.CommandContext 第一个参数是 ctx，跳过
        start_idx = 1 if func_name == "CommandContext" and len(args) > 1 else 0

        for arg in args[start_idx:]:
            if self._subtree_has_user_input(arg, context):
                self._report(node, context, f"{pkg_name or ''}.{func_name}")
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
            if category != "rce":
                continue
            line_no = getattr(sink, "line", 0) or 0
            if line_no in self._reported_lines:
                continue
            reported_sinks.add(sink_id)
            src_expr = getattr(source, "name", "") or getattr(source, "code_snippet", "")
            sink_expr = getattr(sink, "name", "") or getattr(sink, "code_snippet", "")
            finding: dict[str, Any] = {
                "type": "RCE_COMMAND_EXEC",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": (
                    "检测到 Go 代码中用户可控输入流入 exec.Command，"
                    "存在命令注入风险，建议使用固定命令白名单或严格校验参数。"
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
        """从 call_expression 提取 (函数名, 包名)。"""
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
        if is_user_input_node(node, context, language="go"):
            return True
        text = self._get_node_text(node) or ""
        if text and _GO_USER_INPUT_CALL_RE.search(text):
            return True
        for child in getattr(node, "children", []) or []:
            if self._subtree_has_user_input(child, context):
                return True
        return False

    def _is_shell_dynamic_exec(self, args: list[Any], context: AnalysisContext) -> bool:
        """
        识别 `exec.Command("sh","-c", dynamic)` 风险模式。

        该模式在真实项目中常见于先构造命令字符串再交给 shell 执行。
        """
        if len(args) < 3:
            return False

        shell_idx = 0
        if not self._is_shell_name(args[shell_idx]):
            if len(args) < 4:
                return False
            shell_idx = 1
            if not self._is_shell_name(args[shell_idx]):
                return False

        dash_c_idx = shell_idx + 1
        cmd_idx = shell_idx + 2
        if cmd_idx >= len(args):
            return False

        if not self._is_dash_c(args[dash_c_idx]):
            return False

        cmd_arg = args[cmd_idx]
        if self._is_string_literal(cmd_arg):
            return False

        if self._subtree_has_user_input(cmd_arg, context):
            return True

        if self._looks_like_dynamic_command_expr(cmd_arg) and self._file_has_go_user_input(context):
            return True

        return False

    def _file_has_go_user_input(self, context: AnalysisContext) -> bool:
        source_code = context.extras.get("source") or ""
        if not source_code:
            return False
        return bool(_GO_USER_INPUT_CALL_RE.search(source_code))

    def _looks_like_dynamic_command_expr(self, node: Any) -> bool:
        text = self._get_node_text(node) or ""
        if not text:
            return False
        lowered = text.lower()
        return (
            ".string(" in lowered
            or "sprintf(" in lowered
            or "+" in lowered
        )

    def _is_shell_name(self, node: Any) -> bool:
        text = (self._get_node_text(node) or "").strip()
        unquoted = text.strip("`\"")
        return unquoted in _GO_SHELL_NAMES

    @staticmethod
    def _is_dash_c(node: Any) -> bool:
        text = (GoRCEAstRule._get_node_text(node) or "").strip()
        return text in ('"-c"', "`-c`")

    @staticmethod
    def _is_string_literal(node: Any) -> bool:
        return getattr(node, "type", "") in ("interpreted_string_literal", "raw_string_literal")

    def _report(self, node: Any, context: AnalysisContext, func_desc: str) -> None:
        line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
        if line in self._reported_lines:
            return
        self._reported_lines.add(line)
        finding: dict[str, Any] = {
            "type": "RCE_COMMAND_EXEC",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line,
            "details": (
                f"检测到 {func_desc}() 调用中包含用户可控输入，存在命令注入风险，建议使用固定命令白名单或严格校验参数。"
            ),
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)


__all__ = ["GoRCEAstRule"]
