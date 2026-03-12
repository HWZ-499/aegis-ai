"""
hardcoded_credentials.go_ast_rule

Go 硬编码凭证 AST 规则。

检测目标：
1. Tree-sitter AST 节点级分析（visit）：
   - short_var_declaration: password := "secret123"
   - assignment_statement:  password = "secret123"
   - var_declaration → var_spec: var password = "secret123"
   - const_declaration → const_spec: const apiKey = "secret123"
2. after_file 源码扫描兜底（针对 Tree-sitter 不可用的情况）。
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

# 凭证关键词（子串匹配）
_SECRET_KEYWORDS = ("password", "passwd", "pwd", "secret", "token", "apisecret")

# key 相关的精确匹配模式
_KEY_PATTERNS = ("_key", "key_", "api_key", "apikey", "secretkey", "secret_key")

# 已知误报变量名（小写）
_FALSE_POSITIVES = frozenset(
    {
        "keypanspeed",
        "keyboard",
        "keycode",
        "keydown",
        "keyup",
        "keyevent",
        "hotkey",
        "shortcutkey",
        "keypress",
        "keybinding",
        "keystroke",
    }
)

# 占位符精确匹配
_PLACEHOLDERS = frozenset(
    {
        "",
        "your_key",
        "your_password",
        "placeholder",
        "xxx",
        "***",
        "changeme",
        "change_me",
        "change_this",
        "replace_me",
        "replace_this",
        "secret",
        "mysecret",
        "mypassword",
        "mykey",
        "topsecret",
    }
)

_PLACEHOLDER_PREFIXES = (
    "your_",
    "change_",
    "replace_",
    "put_your_",
    "insert_your_",
    "enter_your_",
)

_ALL_UPPER_RE = re.compile(r"[A-Z0-9_]+")


class GoHardcodedCredentialsAstRule(SecurityRule):
    """
    基于 Tree-sitter AST 的 Go 硬编码凭证检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="HARDCODED_CREDENTIALS_GO_AST",
            severity="High",
            languages=["go"],
        )
        self._reported_lines: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported_lines = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        # password := "secret123"
        if node.type == "short_var_declaration":
            self._check_short_var_declaration(node, context)
        # password = "secret123"
        elif node.type == "assignment_statement":
            self._check_assignment_statement(node, context)
        # var password = "secret123" / var password string = "secret123"
        elif node.type == "var_spec":
            self._check_var_or_const_spec(node, context)
        # const apiKey = "secret123"
        elif node.type == "const_spec":
            self._check_var_or_const_spec(node, context)

    # ------------------------------------------------------------------
    # 检测方法
    # ------------------------------------------------------------------

    def _check_short_var_declaration(self, node: Any, context: AnalysisContext) -> None:
        """
        检测 short_var_declaration: name := value

        AST 结构:
          short_var_declaration
            expression_list
              identifier: password
            :=
            expression_list
              interpreted_string_literal: "secret123"
        """
        expr_lists = [c for c in node.children if c.type == "expression_list"]
        if len(expr_lists) < 2:
            return

        left_list = expr_lists[0]
        right_list = expr_lists[1]

        # 左侧可以有多个变量 (a, b := ...)，逐个检查
        left_ids = [c for c in left_list.children if c.type == "identifier"]
        right_vals = [c for c in right_list.children if c.type not in (",",)]

        for i, id_node in enumerate(left_ids):
            var_name = self._get_node_text(id_node)
            if not var_name or not self._looks_like_secret_name(var_name):
                continue

            # 取对应位置的右值
            val_node = right_vals[i] if i < len(right_vals) else None
            if val_node is None:
                continue

            value_str = self._extract_string_value(val_node)
            if value_str is not None and not self._is_placeholder(value_str):
                self._report(node, context, var_name)

    def _check_assignment_statement(self, node: Any, context: AnalysisContext) -> None:
        """
        检测 assignment_statement: name = value

        AST 结构:
          assignment_statement
            expression_list
              identifier: password
            =
            expression_list
              interpreted_string_literal: "secret123"
        """
        expr_lists = [c for c in node.children if c.type == "expression_list"]
        if len(expr_lists) < 2:
            return

        left_list = expr_lists[0]
        right_list = expr_lists[1]

        # 左侧可以是 identifier 或 selector_expression (obj.field)
        for left_child in left_list.children:
            if left_child.type == "identifier":
                var_name = self._get_node_text(left_child)
            elif left_child.type == "selector_expression":
                # 取最后一个 field_identifier
                var_name = None
                for sub in left_child.children:
                    if sub.type == "field_identifier":
                        var_name = self._get_node_text(sub)
            else:
                continue

            if not var_name or not self._looks_like_secret_name(var_name):
                continue

            # 检查右侧是否为字符串字面量
            for right_child in right_list.children:
                value_str = self._extract_string_value(right_child)
                if value_str is not None and not self._is_placeholder(value_str):
                    self._report(node, context, var_name)
                    return

    def _check_var_or_const_spec(self, node: Any, context: AnalysisContext) -> None:
        """
        检测 var_spec / const_spec:
          var password string = "secret123"
          const apiKey = "xxx"

        AST 结构:
          var_spec / const_spec
            name: identifier
            type: type_identifier (可选)
            value: expression_list
              interpreted_string_literal: "secret123"
        """
        var_name = None
        value_node = None

        for child in node.children:
            if child.type == "identifier" and var_name is None:
                var_name = self._get_node_text(child)
            elif child.type == "expression_list":
                # 值在 expression_list 中
                for sub in child.children:
                    if sub.type not in (",",):
                        value_node = sub
                        break

        if not var_name or not self._looks_like_secret_name(var_name):
            return

        if value_node is None:
            return

        value_str = self._extract_string_value(value_node)
        if value_str is not None and not self._is_placeholder(value_str):
            self._report(node, context, var_name)

    # ------------------------------------------------------------------
    # after_file: 源码扫描兜底
    # ------------------------------------------------------------------

    def after_file(self, context: AnalysisContext) -> None:
        """当 Tree-sitter 不可用时，回退到源码行级扫描。"""
        if TREE_SITTER_AVAILABLE:
            return  # AST 分析已覆盖，无需兜底

        source = context.extras.get("source", "")
        if not source:
            return

        for idx, raw_line in enumerate(source.split("\n"), start=1):
            line = raw_line.strip()
            if '"' not in line:
                continue

            if ":=" in line:
                op = ":="
            elif "=" in line:
                op = "="
            else:
                continue

            left, right = line.split(op, 1)
            left = left.strip()
            if not left:
                continue
            name = left.split()[-1]
            if not name:
                continue

            if not self._looks_like_secret_name(name):
                continue

            first_quote = right.find('"')
            last_quote = right.rfind('"')
            if first_quote == -1 or last_quote <= first_quote:
                continue
            value = right[first_quote + 1 : last_quote]
            if self._is_placeholder(value):
                continue

            if idx in self._reported_lines:
                continue

            self._report_line(idx, name, context)

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
    def _extract_string_value(node: Any) -> str | None:
        """从字符串字面量节点中提取值（去除引号）。"""
        if node.type not in (
            "interpreted_string_literal",
            "raw_string_literal",
        ):
            return None
        text = node.text
        if isinstance(text, bytes):
            text = text.decode("utf-8")
        else:
            text = str(text)
        # 去除引号: "xxx" → xxx 或 `xxx` → xxx
        if len(text) >= 2 and ((text[0] == '"' and text[-1] == '"') or (text[0] == "`" and text[-1] == "`")):
            return text[1:-1]
        return text

    @staticmethod
    def _looks_like_secret_name(name: str) -> bool:
        name_lower = name.lower()

        if name_lower in _FALSE_POSITIVES:
            return False

        if "message" in name_lower or "error" in name_lower:
            return False

        if any(k in name_lower for k in _SECRET_KEYWORDS):
            return True

        if "key" in name_lower:
            if name_lower == "key":
                return True
            if any(p in name_lower for p in _KEY_PATTERNS):
                return True

        return False

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        stripped = value.strip()
        if (stripped.startswith("'") and stripped.endswith("'")) or (
            stripped.startswith('"') and stripped.endswith('"')
        ):
            stripped = stripped[1:-1]
        s_lower = stripped.lower()

        if s_lower in _PLACEHOLDERS:
            return True
        if s_lower.endswith("_here"):
            return True
        if stripped.startswith("<") and stripped.endswith(">"):
            return True
        if any(s_lower.startswith(pfx) for pfx in _PLACEHOLDER_PREFIXES):
            return True
        if _ALL_UPPER_RE.fullmatch(stripped or ""):
            return True

        return False

    def _report(self, node: Any, context: AnalysisContext, var_name: str) -> None:
        line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
        if line in self._reported_lines:
            return
        self._reported_lines.add(line)
        finding: dict[str, Any] = {
            "type": "HARDCODED_CREDENTIALS",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line,
            "details": (f"发现 Go 代码中疑似硬编码凭证变量 '{var_name}'，建议改为从环境变量或安全配置加载。"),
        }
        context.add_finding(finding)

    def _report_line(self, line: int, var_name: str, context: AnalysisContext) -> None:
        if line in self._reported_lines:
            return
        self._reported_lines.add(line)
        finding: dict[str, Any] = {
            "type": "HARDCODED_CREDENTIALS",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line,
            "details": (f"发现 Go 代码中疑似硬编码凭证变量 '{var_name}'，建议改为从环境变量或安全配置加载。"),
        }
        context.add_finding(finding)


__all__ = ["GoHardcodedCredentialsAstRule"]
