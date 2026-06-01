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
_GO_INTERPRETER_EVAL_FLAGS = {
    "node": frozenset(["-e", "--eval"]),
    "python": frozenset(["-c"]),
    "perl": frozenset(["-e"]),
    "ruby": frozenset(["-e"]),
    "php": frozenset(["-r"]),
}
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
        if start_idx >= len(args):
            return

        if self._is_interpreter_dynamic_exec(args, start_idx, context):
            self._report(node, context, f"{pkg_name or ''}.{func_name}")
            return

        command_arg = args[start_idx]
        if self._subtree_has_user_input(command_arg, context):
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
            src_expr = getattr(source, "name", "") or getattr(source, "code_snippet", "")
            sink_expr = getattr(sink, "name", "") or getattr(sink, "code_snippet", "")
            if self._is_safe_fixed_command_argv_sink(line_no, sink_expr, context):
                continue
            reported_sinks.add(sink_id)
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
        return ".string(" in lowered or "sprintf(" in lowered or "+" in lowered

    def _is_shell_name(self, node: Any) -> bool:
        text = (self._get_node_text(node) or "").strip()
        unquoted = text.strip('`"')
        return unquoted in _GO_SHELL_NAMES

    def _is_safe_fixed_command_argv_sink(self, line_no: int, sink_expr: str, context: AnalysisContext) -> bool:
        call_text = self._line_text_for_sink(line_no, context) or sink_expr
        args = self._extract_text_call_args(call_text, "exec.Command")
        if not args:
            return False

        command_arg = args[0].strip()
        if not self._is_string_literal_text(command_arg):
            return False
        if self._text_args_include_interpreter_eval(args):
            return False
        if self._is_shell_literal_text(command_arg) and len(args) >= 3 and self._is_dash_c_text(args[1].strip()):
            return False
        return True

    def _is_interpreter_dynamic_exec(self, args: list[Any], command_idx: int, context: AnalysisContext) -> bool:
        command_name = self._canonical_command_name(self._literal_value(args[command_idx]) or "")
        flags = _GO_INTERPRETER_EVAL_FLAGS.get(command_name)
        if not flags:
            return False

        for idx in range(command_idx + 1, len(args) - 1):
            flag = self._literal_value(args[idx])
            if flag not in flags:
                continue
            code_arg = args[idx + 1]
            if not self._is_string_literal(code_arg) and self._subtree_has_user_input(code_arg, context):
                return True
        return False

    @staticmethod
    def _line_text_for_sink(line_no: int, context: AnalysisContext) -> str:
        source_code = context.extras.get("source") or ""
        if not source_code:
            return ""
        lines = source_code.splitlines()
        if 1 <= line_no <= len(lines):
            return lines[line_no - 1]
        return ""

    def _extract_text_call_args(self, text: str, call_name: str) -> list[str]:
        call_index = text.find(call_name)
        if call_index < 0:
            return []
        open_paren = text.find("(", call_index + len(call_name))
        if open_paren < 0:
            return []
        close_paren = self._find_matching_paren_in_text(text, open_paren)
        if close_paren is None:
            return []
        return self._split_top_level_args(text[open_paren + 1 : close_paren])

    @staticmethod
    def _find_matching_paren_in_text(text: str, open_paren: int) -> int | None:
        depth = 0
        quote: str | None = None
        escaped = False
        for index in range(open_paren, len(text)):
            ch = text[index]
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

    @staticmethod
    def _split_top_level_args(text: str) -> list[str]:
        args: list[str] = []
        start = 0
        paren_depth = 0
        brace_depth = 0
        bracket_depth = 0
        quote: str | None = None
        escaped = False

        for index, ch in enumerate(text):
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
                paren_depth += 1
                continue
            if ch == ")":
                paren_depth -= 1
                continue
            if ch == "{":
                brace_depth += 1
                continue
            if ch == "}":
                brace_depth -= 1
                continue
            if ch == "[":
                bracket_depth += 1
                continue
            if ch == "]":
                bracket_depth -= 1
                continue
            if ch == "," and paren_depth == 0 and brace_depth == 0 and bracket_depth == 0:
                args.append(text[start:index].strip())
                start = index + 1

        tail = text[start:].strip()
        if tail:
            args.append(tail)
        return args

    @staticmethod
    def _is_string_literal_text(text: str) -> bool:
        return (text.startswith('"') and text.endswith('"')) or (text.startswith("`") and text.endswith("`"))

    def _text_args_include_interpreter_eval(self, args: list[str]) -> bool:
        if not args:
            return False
        command_name = self._canonical_command_name(self._literal_value_text(args[0]) or "")
        flags = _GO_INTERPRETER_EVAL_FLAGS.get(command_name)
        if not flags:
            return False

        for idx in range(1, len(args) - 1):
            flag = self._literal_value_text(args[idx])
            if flag in flags and not self._is_string_literal_text(args[idx + 1].strip()):
                return True
        return False

    @staticmethod
    def _is_shell_literal_text(text: str) -> bool:
        return text.strip().strip('`"') in _GO_SHELL_NAMES

    @staticmethod
    def _is_dash_c_text(text: str) -> bool:
        return text.strip() in ('"-c"', "`-c`")

    @staticmethod
    def _is_dash_c(node: Any) -> bool:
        text = (GoRCEAstRule._get_node_text(node) or "").strip()
        return text in ('"-c"', "`-c`")

    @staticmethod
    def _is_string_literal(node: Any) -> bool:
        return getattr(node, "type", "") in ("interpreted_string_literal", "raw_string_literal")

    def _literal_value(self, node: Any) -> str | None:
        text = (self._get_node_text(node) or "").strip()
        return self._literal_value_text(text)

    @staticmethod
    def _literal_value_text(text: str) -> str | None:
        text = text.strip()
        if (text.startswith('"') and text.endswith('"')) or (text.startswith("`") and text.endswith("`")):
            return text[1:-1]
        return None

    @staticmethod
    def _canonical_command_name(value: str) -> str:
        command = value.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if command.endswith(".exe"):
            command = command[:-4]
        if command.startswith("python"):
            return "python"
        return command

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
