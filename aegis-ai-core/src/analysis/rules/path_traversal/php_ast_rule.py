"""PHP Path Traversal AST rule — Tree-sitter based."""

from __future__ import annotations

import re
from typing import Any

from ...base import AnalysisContext, SecurityRule, tree_sitter_node_to_range
from ...base.user_input_detector import _subtree_contains_php_user_input

try:
    from tree_sitter import Node

    _TS = True
except ImportError:
    _TS = False
    Node = Any  # type: ignore[misc,assignment]


class PhpPathTraversalAstRule(SecurityRule):
    """Detect path traversal via file operations with user input."""

    FILE_FUNCS = frozenset(
        {
            "file_get_contents",
            "file_put_contents",
            "readfile",
            "fopen",
            "file",
            "unlink",
            "copy",
            "rename",
            "mkdir",
            "rmdir",
        }
    )

    def __init__(self) -> None:
        super().__init__(rule_id="PATH_TRAVERSAL_PHP_AST", severity="High", languages=["php"])
        self._reported: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not _TS or not isinstance(node, Node):
            return

        # include/require expressions
        if node.type == "include_expression":
            self._check_include(node, context)
        # function_call_expression: file_get_contents(), fopen(), readfile()
        elif node.type == "function_call_expression":
            func_name = self._get_func_name(node)
            if func_name and func_name in self.FILE_FUNCS:
                self._check_file_func(node, context, func_name)

    def _check_include(self, node: Any, context: AnalysisContext) -> None:
        line = node.start_point[0] + 1
        if line in self._reported:
            return
        # include expression children: "include" keyword + the path expression
        for child in node.children:
            if child.type in ("include", "include_once", "require", "require_once", ";"):
                continue
            if _subtree_contains_php_user_input(child, context):
                self._reported.add(line)
                finding = {
                    "type": "PATH_TRAVERSAL",
                    "rule_id": self.rule_id,
                    "severity": self.severity,
                    "line": line,
                    "details": "PHP: include/require 的路径包含用户输入，存在路径遍历/文件包含风险。",
                }
                finding.update(tree_sitter_node_to_range(node))
                context.add_finding(finding)
                return
            if child.type == "variable_name":
                var = self._text(child).lstrip("$")
                if context.is_var_tainted(var) or context.is_var_tainted("$" + var):
                    self._reported.add(line)
                    finding = {
                        "type": "PATH_TRAVERSAL",
                        "rule_id": self.rule_id,
                        "severity": self.severity,
                        "line": line,
                        "details": f"PHP: include/require 的路径变量 ${var} 被污染，存在路径遍历风险。",
                    }
                    finding.update(tree_sitter_node_to_range(node))
                    context.add_finding(finding)
                    return

    def _check_file_func(self, node: Any, context: AnalysisContext, func: str) -> None:
        line = node.start_point[0] + 1
        if line in self._reported:
            return
        for child in node.children:
            if child.type == "arguments":
                path_arg_indexes = self._path_arg_indexes(func)
                arg_index = 0
                for arg in child.children:
                    if arg.type == "argument":
                        if arg_index not in path_arg_indexes:
                            arg_index += 1
                            continue
                        if self._path_arg_uses_only_safe_randomized_upload_vars(arg, context, line):
                            arg_index += 1
                            continue
                        if _subtree_contains_php_user_input(arg, context):
                            self._reported.add(line)
                            finding = {
                                "type": "PATH_TRAVERSAL",
                                "rule_id": self.rule_id,
                                "severity": self.severity,
                                "line": line,
                                "details": f"PHP: {func}() 的路径参数包含用户输入，存在路径遍历风险。",
                            }
                            finding.update(tree_sitter_node_to_range(node))
                            context.add_finding(finding)
                            return
                        inner = self._unwrap(arg)
                        if inner.type == "variable_name":
                            var = self._text(inner).lstrip("$")
                            if context.is_var_tainted(var) or context.is_var_tainted("$" + var):
                                self._reported.add(line)
                                finding = {
                                    "type": "PATH_TRAVERSAL",
                                    "rule_id": self.rule_id,
                                    "severity": self.severity,
                                    "line": line,
                                    "details": f"PHP: {func}() 的路径变量 ${var} 被污染，存在路径遍历风险。",
                                }
                                finding.update(tree_sitter_node_to_range(node))
                                context.add_finding(finding)
                                return
                        arg_index += 1

    def _path_arg_uses_only_safe_randomized_upload_vars(
        self,
        arg: Any,
        context: AnalysisContext,
        line: int,
    ) -> bool:
        expr = self._text(arg)
        var_names = {name for name in re.findall(r"\$([A-Za-z_]\w*)", expr)}
        tainted_vars = [
            name for name in var_names if context.is_var_tainted(name) or context.is_var_tainted("$" + name)
        ]
        if not tainted_vars:
            return False

        lines = str(context.extras.get("source", "")).splitlines()
        return all(
            self._is_uploaded_tmp_path_var(name, lines, line)
            or self._is_safe_randomized_upload_filename(name, lines, line)
            for name in tainted_vars
        )

    def _is_uploaded_tmp_path_var(self, var_name: str, lines: list[str], sink_line: int) -> bool:
        assignment = self._find_latest_assignment_expr(var_name, lines, sink_line)
        if assignment is None:
            return False
        _, expr = assignment
        return bool(
            re.search(
                r"\$_FILES\s*\[[^\]]+\]\s*\[\s*['\"]tmp_name['\"]\s*\]",
                expr,
                re.IGNORECASE,
            )
        )

    def _is_safe_randomized_upload_filename(self, var_name: str, lines: list[str], sink_line: int) -> bool:
        assignment = self._find_latest_assignment_expr(var_name, lines, sink_line)
        if assignment is None:
            return False

        assign_idx, expr = assignment
        if not re.search(r"\b(md5|sha1|hash|uniqid|bin2hex|random_bytes)\s*\(", expr, re.IGNORECASE):
            return False

        extension_vars = set(
            re.findall(
                r"\.\s*['\"]\.['\"]\s*\.\s*\$([A-Za-z_]\w*)",
                expr,
                re.IGNORECASE,
            )
        )
        if not extension_vars:
            return True

        return all(self._has_extension_allowlist(name, lines, assign_idx, sink_line) for name in extension_vars)

    @staticmethod
    def _find_latest_assignment_expr(var_name: str, lines: list[str], before_line: int) -> tuple[int, str] | None:
        assign_re = re.compile(rf"\${re.escape(var_name)}\s*=\s*(.+?)\s*;?\s*$")
        for index in range(min(before_line - 1, len(lines) - 1), -1, -1):
            matched = assign_re.search(lines[index])
            if matched is not None:
                return index, matched.group(1).strip()
        return None

    @staticmethod
    def _has_extension_allowlist(ext_var: str, lines: list[str], assign_idx: int, sink_line: int) -> bool:
        window = "\n".join(lines[assign_idx : min(sink_line, len(lines))])
        escaped = re.escape(ext_var)
        comparison_re = re.compile(
            rf"strtolower\s*\(\s*\${escaped}\s*\)\s*={{2,3}}\s*['\"][A-Za-z0-9]+['\"]",
            re.IGNORECASE,
        )
        in_array_re = re.compile(
            rf"in_array\s*\(\s*strtolower\s*\(\s*\${escaped}\s*\)\s*,",
            re.IGNORECASE,
        )
        return bool(comparison_re.search(window) or in_array_re.search(window))

    @staticmethod
    def _path_arg_indexes(func: str) -> set[int]:
        if func in {"copy", "rename"}:
            return {0, 1}
        return {0}

    @staticmethod
    def _unwrap(arg: Any) -> Any:
        if arg.type == "argument":
            for c in arg.children:
                if c.type not in (",", "(", ")"):
                    return c
        return arg

    @staticmethod
    def _get_func_name(node: Any) -> str | None:
        for c in node.children:
            if c.type == "name":
                return c.text.decode("utf-8") if hasattr(c, "text") else None
        return None

    @staticmethod
    def _text(node: Any) -> str:
        if hasattr(node, "text"):
            raw = node.text
            return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        return ""


__all__ = ["PhpPathTraversalAstRule"]
