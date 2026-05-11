"""
hardcoded_credentials.java_ast_rule

Java 硬编码凭证 AST 规则。

检测目标：
- 将明显是“密码 / 密钥 / Token 等”的变量，直接赋值为常量字符串/数字；
- 与 JavaScriptHardcodedCredentialsAstRule 逻辑对齐，但适配 Java 语法节点。
"""

from __future__ import annotations

import re
from typing import Any

from ...base import AnalysisContext, SecurityRule

# Tree-sitter Node 类型
try:
    from tree_sitter import Node

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any  # type: ignore[misc,assignment]


class JavaHardcodedCredentialsAstRule(SecurityRule):
    """
    基于 Tree-sitter AST 的 Java 硬编码凭证检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="HARDCODED_CREDENTIALS_JAVA_AST",
            severity="High",
            languages=["java"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """
        访问 Tree-sitter AST 节点。
        """
        if not TREE_SITTER_AVAILABLE:
            return

        if not isinstance(node, Node):
            return

        # 局部变量/类字段声明：String password = "xxx";
        if node.type in {"local_variable_declaration", "field_declaration"}:
            self._check_local_variable_declaration(node, context)

        # 赋值表达式：config.password = "xxx";
        elif node.type == "assignment_expression":
            self._check_assignment(node, context)

    # ------------------------------------------------------------------
    # 检测方法
    # ------------------------------------------------------------------
    def _check_local_variable_declaration(self, node: Node, context: AnalysisContext) -> None:
        """检测局部变量声明中的硬编码凭证。"""
        for child in node.children:
            if child.type != "variable_declarator":
                continue
            var_name_node = None
            value_node = None
            passed_eq = False
            for sub in child.children:
                if sub.type == "identifier" and var_name_node is None:
                    var_name_node = sub
                elif sub.type == "=":
                    passed_eq = True
                elif passed_eq and value_node is None:
                    value_node = sub
                    break

            if not var_name_node or not value_node:
                continue

            var_name = self._get_node_text(var_name_node)
            if not var_name or not self._looks_like_secret_name(var_name):
                continue

            value_str = self._get_node_text(value_node)
            if value_str and not self._is_placeholder(value_str):
                line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
                severity = self._effective_severity(context)
                finding: dict[str, Any] = {
                    "type": "HARDCODED_CREDENTIALS",
                    "rule_id": self.rule_id,
                    "severity": severity,
                    "line": line_no,
                    "details": f"发现疑似硬编码凭证变量 '{var_name}'，建议使用环境变量或安全配置管理。",
                }
                context.add_finding(finding)

    def _check_assignment(self, node: Node, context: AnalysisContext) -> None:
        """检测赋值表达式中的硬编码凭证。"""
        left_node = None
        right_node = None
        passed_eq = False

        for child in node.children:
            if child.type == "=":
                passed_eq = True
                continue
            if not passed_eq:
                # 左侧可以是 identifier 或 field_access（obj.field）
                if child.type in ("identifier", "field_access"):
                    left_node = child
            else:
                right_node = child
                break

        if not left_node or not right_node:
            return

        # 从左侧提取变量/字段名
        var_name = None
        if left_node.type == "identifier":
            var_name = self._get_node_text(left_node)
        elif left_node.type == "field_access":
            # field_access: qualifier '.' field
            for sub in left_node.children:
                if sub.type == "identifier":
                    var_name = self._get_node_text(sub)
        if not var_name or not self._looks_like_secret_name(var_name):
            return

        value_str = self._get_node_text(right_node)
        if value_str and not self._is_placeholder(value_str):
            line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
            severity = self._effective_severity(context)
            finding: dict[str, Any] = {
                "type": "HARDCODED_CREDENTIALS",
                "rule_id": self.rule_id,
                "severity": severity,
                "line": line_no,
                "details": f"发现疑似硬编码凭证变量 '{var_name}'，建议使用环境变量或安全配置管理。",
            }
            context.add_finding(finding)

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    _TEST_FILE_RE = re.compile(
        r"[\\/](tests?|test_\w+|conftest|__tests__)[\\/]|[\\/]test_[^/\\]+\.\w+$|Test\.java$",
        re.IGNORECASE,
    )

    def _effective_severity(self, context: AnalysisContext) -> str:
        """配置类文件降级为 Medium，测试文件降级为 Low。"""
        fp = getattr(context, "file_path", None) or ""
        path_lower = str(fp).lower().replace("\\", "/")
        if self._TEST_FILE_RE.search(path_lower):
            return "Low"
        if "config" in path_lower:
            return "Medium"
        return self.severity

    @staticmethod
    def _get_node_text(node: Node) -> str | None:
        if hasattr(node, "text"):
            raw = node.text
            return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        return None

    # 已知误报：变量名含 key/Keyboard 等但非凭证（降低误报）
    CREDENTIAL_FALSE_POSITIVES = frozenset(
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
            # 非凭证的 password/token/secret/key 衍生词
            "passwordhash",
            "passwordsalt",
            "passwordlength",
            "passwordpolicy",
            "passwordregex",
            "passwordvalidator",
            "passwordfield",
            "passwordinput",
            "passwordlabel",
            "passwordplaceholder",
            "tokentype",
            "tokenizer",
            "tokenlength",
            "tokenexpiry",
            "tokenrefreshinterval",
            "secretname",
            "secretref",
            "secretpath",
            "keylength",
            "keysize",
            "keyalgorithm",
            "keystore",
            "keypath",
            "keyname",
        }
    )

    @staticmethod
    def _looks_like_secret_name(name: str) -> bool:
        """
        检查变量名是否像敏感凭证。
        """
        name_lower = name.lower()

        # 排除已知误报（如 keyPanSpeed, keyboard）
        if name_lower in JavaHardcodedCredentialsAstRule.CREDENTIAL_FALSE_POSITIVES:
            return False

        # 排除包含 Message, Error 的变量名
        if "message" in name_lower or "error" in name_lower:
            return False

        # 明确凭证关键词（子串匹配）
        keywords_substring = [
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "apisecret",
        ]
        if any(k in name_lower for k in keywords_substring):
            return True

        # key 仅整词或 api_key/apikey 形态
        if "key" in name_lower:
            if name_lower == "key":
                return True
            if "_key" in name_lower or "key_" in name_lower:
                return True
            if "api_key" in name_lower or "apikey" in name_lower:
                return True
            if "secretkey" in name_lower or "secret_key" in name_lower:
                return True

        return False

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        """
        判断值是否为占位符或纯演示字符串，避免对无害的示例凭证误报。
        """
        stripped = value.strip()
        if (stripped.startswith("'") and stripped.endswith("'")) or (
            stripped.startswith('"') and stripped.endswith('"')
        ):
            stripped = stripped[1:-1]
        s_lower = stripped.lower()

        # 精确匹配
        placeholders = frozenset(
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
        if s_lower in placeholders:
            return True

        # _here 结尾
        if s_lower.endswith("_here"):
            return True

        # <...> 占位符包装
        if stripped.startswith("<") and stripped.endswith(">"):
            return True

        # 含提示性前缀
        placeholder_prefixes = (
            "your_",
            "change_",
            "replace_",
            "put_your_",
            "insert_your_",
            "enter_your_",
        )
        if any(s_lower.startswith(pfx) for pfx in placeholder_prefixes):
            return True

        # 全大写下划线格式（如 YOUR_SECRET_KEY、MY_API_KEY_HERE）
        if re.fullmatch(r"[A-Z0-9_]+", stripped or ""):
            return True

        return False


__all__ = ["JavaHardcodedCredentialsAstRule"]
