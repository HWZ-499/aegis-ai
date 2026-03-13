"""PHP Hardcoded Credentials AST rule — Tree-sitter based."""

from __future__ import annotations

import re
from typing import Any

from ...base import AnalysisContext, SecurityRule, tree_sitter_node_to_range

try:
    from tree_sitter import Node

    _TS = True
except ImportError:
    _TS = False
    Node = Any

_CREDENTIAL_RE = re.compile(
    r"(password|passwd|pwd|secret|api_?key|token|auth|credential|private_?key)",
    re.IGNORECASE,
)
_SAFE_VALUES = frozenset({"", "null", "none", "false", "true", "test", "example", "xxx", "changeme"})


class PhpHardcodedCredentialsAstRule(SecurityRule):
    """Detect hardcoded credentials in PHP."""

    def __init__(self) -> None:
        super().__init__(rule_id="HARDCODED_CREDENTIALS_PHP_AST", severity="Medium", languages=["php"])
        self._reported: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not _TS or not isinstance(node, Node):
            return

        # define("DB_PASSWORD", "literal")
        if node.type == "function_call_expression":
            func_name = self._get_func_name(node)
            if func_name == "define":
                self._check_define(node, context)
        # $password = "secret123";
        elif node.type == "assignment_expression":
            self._check_assignment(node, context)

    def _check_define(self, node: Any, context: AnalysisContext) -> None:
        line = node.start_point[0] + 1
        if line in self._reported:
            return
        args = self._get_args(node)
        if len(args) < 2:
            return
        name_text = self._text(args[0]).strip("\"'")
        value_text = self._text(args[1]).strip("\"'")
        if not _CREDENTIAL_RE.search(name_text):
            return
        # Value must be a non-trivial string literal
        inner_val = self._unwrap(args[1])
        if inner_val.type not in ("string", "encapsed_string"):
            return
        if value_text.lower() in _SAFE_VALUES:
            return
        if len(value_text) < 3:
            return
        self._reported.add(line)
        finding = {
            "type": "HARDCODED_CREDENTIALS",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line,
            "details": f"PHP: define('{name_text}', ...) 硬编码了凭证值，建议使用 getenv() 或配置文件。",
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)

    def _check_assignment(self, node: Any, context: AnalysisContext) -> None:
        line = node.start_point[0] + 1
        if line in self._reported:
            return
        var_node = None
        val_node = None
        for child in node.children:
            if child.type == "variable_name" and var_node is None:
                var_node = child
            elif child.type in ("string", "encapsed_string"):
                val_node = child
            elif child.type not in ("=",):
                if val_node is None:
                    val_node = child
        if var_node is None or val_node is None:
            return
        var_name = self._text(var_node).lstrip("$")
        if not _CREDENTIAL_RE.search(var_name):
            return
        if val_node.type not in ("string", "encapsed_string"):
            return
        val_text = self._text(val_node).strip("\"'")
        if val_text.lower() in _SAFE_VALUES:
            return
        if len(val_text) < 3:
            return
        self._reported.add(line)
        finding = {
            "type": "HARDCODED_CREDENTIALS",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line,
            "details": f"PHP: 变量 ${var_name} 硬编码了凭证值，建议使用 getenv() 或配置文件。",
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)

    @staticmethod
    def _get_args(node: Any) -> list[Any]:
        for child in node.children:
            if child.type == "arguments":
                return [c for c in child.children if c.type == "argument"]
        return []

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


__all__ = ["PhpHardcodedCredentialsAstRule"]
