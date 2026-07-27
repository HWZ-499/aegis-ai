"""PHP RCE (Remote Code Execution) AST rule — Tree-sitter based."""

from __future__ import annotations

import re
from typing import Any

from ...base import AnalysisContext, SecurityRule, tree_sitter_node_to_range
from ...base.user_input_detector import _subtree_contains_unsafe_php_user_input

try:
    from tree_sitter import Node

    _TS = True
except ImportError:
    _TS = False
    Node = Any  # type: ignore[misc,assignment]


class PhpRCEAstRule(SecurityRule):
    """Detect command execution with user input in PHP."""

    DANGEROUS_FUNCS = frozenset(
        {
            "system",
            "exec",
            "passthru",
            "shell_exec",
            "popen",
            "proc_open",
            "pcntl_exec",
            "eval",
            "assert",
            "preg_replace",
        }
    )
    COMMAND_EXEC_FUNCS = DANGEROUS_FUNCS - {"eval", "assert", "preg_replace"}
    COMMAND_SANITIZERS = frozenset(
        {
            "escapeshellarg",
            "escapeshellcmd",
            "intval",
            "floatval",
            "abs",
            "ctype_digit",
            "ctype_alpha",
            "ctype_alnum",
        }
    )
    DYNAMIC_DISPATCH_FUNCS = frozenset({"call_user_func", "call_user_func_array"})

    def __init__(self) -> None:
        super().__init__(rule_id="RCE_PHP_AST", severity="Critical", languages=["php"])
        self._reported: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not _TS or not isinstance(node, Node):
            return

        if node.type == "shell_command_expression":
            self._check_shell_command(node, context)
            return
        if node.type != "function_call_expression":
            return

        func_name = self._get_func_name(node)
        if not func_name:
            return
        if func_name in self.DYNAMIC_DISPATCH_FUNCS:
            self._check_dynamic_dispatch(node, context, func_name)
            return
        if func_name not in self.DANGEROUS_FUNCS:
            return
        if func_name == "preg_replace" and not self._preg_replace_uses_eval_modifier(node):
            return

        line = node.start_point[0] + 1
        if line in self._reported:
            return

        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    if arg.type == "argument":
                        inner = self._unwrap(arg)
                        # Skip string literals (no user input)
                        if inner.type in ("string", "encapsed_string"):
                            if not self._has_variable(inner):
                                continue
                        if self._contains_unsafe_user_input(arg, context):
                            if func_name in self.COMMAND_EXEC_FUNCS and self._is_numeric_ip_rebuild_guarded_arg(
                                arg,
                                context,
                                line,
                            ):
                                continue
                            self._report(node, context, line, func_name)
                            return
                        # Check tainted variable
                        if inner.type == "variable_name":
                            var = self._text(inner).lstrip("$")
                            if context.is_var_tainted(var) or context.is_var_tainted("$" + var):
                                if func_name in self.COMMAND_EXEC_FUNCS and self._is_numeric_ip_rebuild_guarded_arg(
                                    inner,
                                    context,
                                    line,
                                ):
                                    continue
                                self._report(node, context, line, func_name)
                                return

    def _check_shell_command(self, node: Any, context: AnalysisContext) -> None:
        line = node.start_point[0] + 1
        if line in self._reported or not self._contains_unsafe_user_input(node, context):
            return
        if self._is_numeric_ip_rebuild_guarded_arg(node, context, line):
            return
        self._report(node, context, line, "backtick shell command")

    def _check_dynamic_dispatch(self, node: Any, context: AnalysisContext, dispatcher: str) -> None:
        arguments = self._argument_nodes(node)
        if len(arguments) < 2:
            return

        target = self._static_string_value(self._unwrap(arguments[0]))
        if target is None or target.lower().lstrip("\\") not in self.DANGEROUS_FUNCS:
            return

        line = node.start_point[0] + 1
        for argument in arguments[1:]:
            if not self._contains_unsafe_user_input(argument, context):
                continue
            if target in self.COMMAND_EXEC_FUNCS and self._is_numeric_ip_rebuild_guarded_arg(
                argument,
                context,
                line,
            ):
                continue
            self._report(node, context, line, f"{dispatcher}({target})")
            return

    def _contains_unsafe_user_input(self, node: Any, context: AnalysisContext) -> bool:
        return _subtree_contains_unsafe_php_user_input(
            node,
            context,
            sanitizers=self.COMMAND_SANITIZERS,
        )

    @staticmethod
    def _argument_nodes(node: Any) -> list[Any]:
        for child in getattr(node, "children", []):
            if getattr(child, "type", "") == "arguments":
                return [arg for arg in getattr(child, "children", []) if getattr(arg, "type", "") == "argument"]
        return []

    def _static_string_value(self, node: Any) -> str | None:
        if getattr(node, "type", "") not in {"string", "encapsed_string"}:
            return None
        value = self._text(node).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            return value[1:-1]
        return None

    def _report(self, node: Any, context: AnalysisContext, line: int, func: str) -> None:
        self._reported.add(line)
        finding = {
            "type": "RCE_COMMAND_EXEC",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line,
            "details": f"PHP: {func}() 参数来自用户输入，存在远程代码/命令执行风险。",
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)

    @staticmethod
    def _unwrap(arg: Any) -> Any:
        if arg.type == "argument":
            for c in arg.children:
                if c.type not in (",", "(", ")"):
                    return c
        return arg

    @staticmethod
    def _has_variable(node: Any) -> bool:
        if hasattr(node, "children"):
            for c in node.children:
                if c.type == "variable_name":
                    return True
        return False

    def _preg_replace_uses_eval_modifier(self, node: Any) -> bool:
        """Return True when preg_replace() has a static regex /e modifier."""
        for child in node.children:
            if child.type != "arguments":
                continue
            for arg in child.children:
                if arg.type == "argument":
                    return self._node_contains_eval_regex_modifier(self._unwrap(arg))
        return False

    def _node_contains_eval_regex_modifier(self, node: Any) -> bool:
        if node.type in {"string", "encapsed_string"}:
            if self._regex_literal_has_eval_modifier(self._text(node)):
                return True

        if hasattr(node, "children"):
            return any(self._node_contains_eval_regex_modifier(child) for child in node.children)
        return False

    @staticmethod
    def _regex_literal_has_eval_modifier(raw_text: str) -> bool:
        value = raw_text.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if not value:
            return False

        delimiter = value[0]
        if delimiter.isalnum() or delimiter == "\\" or delimiter.isspace():
            return False

        closing_delimiter = {"(": ")", "[": "]", "{": "}", "<": ">"}.get(delimiter, delimiter)
        closing_index = PhpRCEAstRule._find_last_unescaped_delimiter(value, closing_delimiter)
        if closing_index <= 0:
            return False

        modifiers = value[closing_index + 1 :]
        return "e" in modifiers

    @staticmethod
    def _find_last_unescaped_delimiter(value: str, delimiter: str) -> int:
        for index in range(len(value) - 1, 0, -1):
            if value[index] == delimiter and not PhpRCEAstRule._is_escaped(value, index):
                return index
        return -1

    def _is_numeric_ip_rebuild_guarded_arg(self, node: Any, context: AnalysisContext, sink_line: int) -> bool:
        """
        Detect the common safe command pattern:
        user input -> explode('.') -> four is_numeric octet checks -> IP string rebuild -> shell command.

        This is intentionally narrow. A partial numeric check or a direct use of the original input still reports RCE.
        """
        source = context.extras.get("source")
        if not isinstance(source, str) or not source:
            return False

        lines = source.splitlines()
        for var_name in self._collect_variable_names(node):
            assignment = self._find_latest_assignment_expr(var_name, sink_line, lines)
            if assignment is None:
                continue
            assignment_line, assignment_expr = assignment
            array_var = self._extract_ip_rebuild_array_var(assignment_expr)
            if array_var is None:
                continue
            if not self._has_explode_assignment(lines, array_var, var_name, assignment_line):
                continue
            if self._has_complete_numeric_ip_guard(lines, array_var, assignment_line, sink_line):
                return True
        return False

    @staticmethod
    def _collect_variable_names(node: Any) -> set[str]:
        return {name.lstrip("$") for name in re.findall(r"\$[A-Za-z_]\w*", PhpRCEAstRule._text(node))}

    @staticmethod
    def _find_latest_assignment_expr(var_name: str, sink_line: int, lines: list[str]) -> tuple[int, str] | None:
        upper_bound = min(max(sink_line - 1, 0), len(lines))
        assign_re = re.compile(rf"\${re.escape(var_name)}\s*=\s*(.+?)\s*;?\s*$")
        for index in range(upper_bound - 1, -1, -1):
            matched = assign_re.search(lines[index])
            if matched is not None:
                return index + 1, matched.group(1).strip()
        return None

    @staticmethod
    def _extract_ip_rebuild_array_var(expr: str) -> str | None:
        matches: list[tuple[str, str]] = re.findall(r"\$([A-Za-z_]\w*)\s*\[\s*([0-3])\s*\]", expr)
        if not matches:
            return None
        array_names = {name for name, _ in matches}
        indexes = {index for _, index in matches}
        if len(array_names) != 1 or indexes != {"0", "1", "2", "3"}:
            return None
        if len(re.findall(r"['\"]\.['\"]", expr)) < 3:
            return None
        return next(iter(array_names))

    @staticmethod
    def _has_explode_assignment(lines: list[str], array_var: str, source_var: str, before_line: int) -> bool:
        explode_re = re.compile(
            rf"\${re.escape(array_var)}\s*=\s*explode\s*\(\s*['\"]\.['\"]\s*,\s*\${re.escape(source_var)}\s*\)",
            re.IGNORECASE,
        )
        upper_bound = min(max(before_line - 1, 0), len(lines))
        return any(explode_re.search(lines[index]) for index in range(upper_bound - 1, -1, -1))

    def _has_complete_numeric_ip_guard(
        self,
        lines: list[str],
        array_var: str,
        assignment_line: int,
        sink_line: int,
    ) -> bool:
        start = max(0, assignment_line - 25)
        end = max(0, assignment_line - 1)
        for guard_index in range(end - 1, start - 1, -1):
            if "if" not in lines[guard_index]:
                continue
            condition_text = "\n".join(lines[guard_index:end])
            if not self._condition_checks_four_numeric_octets(condition_text, array_var):
                continue
            if self._guard_block_contains_line(lines, guard_index, sink_line):
                return True
        return False

    @staticmethod
    def _condition_checks_four_numeric_octets(condition_text: str, array_var: str) -> bool:
        if re.search(r"!\s*is_numeric", condition_text, re.IGNORECASE):
            return False
        for index in range(4):
            if not re.search(
                rf"\bis_numeric\s*\(\s*\${re.escape(array_var)}\s*\[\s*{index}\s*\]\s*\)",
                condition_text,
                re.IGNORECASE,
            ):
                return False
        size_expr = rf"(?:sizeof|count)\s*\(\s*\${re.escape(array_var)}\s*\)"
        return bool(
            re.search(rf"{size_expr}\s*={{2,3}}\s*4", condition_text, re.IGNORECASE)
            or re.search(rf"4\s*={{2,3}}\s*{size_expr}", condition_text, re.IGNORECASE)
        )

    @staticmethod
    def _guard_block_contains_line(lines: list[str], guard_index: int, sink_line: int) -> bool:
        sink_index = sink_line - 1
        depth = 0
        seen_open = False
        for index in range(guard_index, min(len(lines), sink_index + 1)):
            if index == sink_index:
                return seen_open and depth > 0
            current = lines[index]
            if "{" in current:
                seen_open = True
            depth += current.count("{") - current.count("}")
            if seen_open and depth <= 0:
                return False
        return False

    @staticmethod
    def _is_escaped(value: str, index: int) -> bool:
        slash_count = 0
        pos = index - 1
        while pos >= 0 and value[pos] == "\\":
            slash_count += 1
            pos -= 1
        return slash_count % 2 == 1

    @staticmethod
    def _get_func_name(node: Any) -> str | None:
        for c in node.children:
            if c.type == "name":
                raw = getattr(c, "text", None)
                if isinstance(raw, bytes):
                    return raw.decode("utf-8")
                if isinstance(raw, str):
                    return raw
        return None

    @staticmethod
    def _text(node: Any) -> str:
        if hasattr(node, "text"):
            raw = node.text
            return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        return ""


__all__ = ["PhpRCEAstRule"]
