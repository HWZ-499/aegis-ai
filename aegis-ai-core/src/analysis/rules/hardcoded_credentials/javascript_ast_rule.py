"""
hardcoded_credentials.javascript_ast_rule

JavaScript/TypeScript 硬编码凭证 AST 规则。

检测目标：
- 将明显是“密码 / 密钥 / Token 等”的变量，直接赋值为常量字符串。
- 对象字面量中的凭证属性（如 createConnection({ password: "login" })）。

说明：
- 使用 Tree-sitter Node；
- 与 Python 版本逻辑类似，但适配 JS/TS 的语法。
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
    Node = Any


class JavaScriptHardcodedCredentialsAstRule(SecurityRule):
    """
    基于 Tree-sitter AST 的 JavaScript/TypeScript 硬编码凭证检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="HARDCODED_CREDENTIALS_JS_AST",
            severity="High",
            languages=["javascript", "typescript"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """
        访问 Tree-sitter AST 节点。
        """
        if not TREE_SITTER_AVAILABLE:
            return

        if not isinstance(node, Node):
            return

        # 检测变量声明（const/let/var）
        if node.type in ("variable_declaration", "lexical_declaration"):
            self._check_variable_declaration(node, context)

        # 检测赋值表达式（obj.key = ...）
        elif node.type == "assignment_expression":
            self._check_assignment(node, context)

        # 检测对象字面量中的凭证属性（如 { password: "login" }）
        elif node.type == "pair":
            self._check_object_pair(node, context)

    # ------------------------------------------------------------------
    # 检测方法
    # ------------------------------------------------------------------
    def _check_object_pair(self, node: Node, context: AnalysisContext) -> None:
        """检测对象字面量中的硬编码凭证属性（如 createConnection({ password: "login" })）。"""
        key_name = None
        value_node = None
        for child in node.children:
            if child.type == "property_identifier":
                key_name = self._get_node_text(child)
            elif child.type == "string":
                raw = self._get_node_text(child)
                if key_name is None:
                    key_name = raw.strip("'\"").lower() if raw else None
                else:
                    value_node = child
            elif child.type == "number":
                value_node = child
        if not key_name or not value_node:
            return
        # 对象字面量中除变量名规则外，额外将 user/username 视为敏感（如 DB 配置）
        key_lower = key_name.lower() if isinstance(key_name, str) else ""
        if not self._looks_like_secret_name(key_name) and key_lower not in ("user", "username"):
            return
        value_str = self._get_node_text(value_node)
        if not value_str or self._is_placeholder(value_str):
            return
        line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
        finding: dict[str, Any] = {
            "type": "HARDCODED_CREDENTIALS",
            "rule_id": self.rule_id,
            "severity": self._effective_severity(context),
            "line": line_no,
            "details": f"发现对象字面量中疑似硬编码凭证属性 '{key_name}'，建议使用环境变量或安全配置管理。",
        }
        context.add_finding(finding)

    def _check_variable_declaration(self, node: Node, context: AnalysisContext) -> None:
        """检测变量声明中的硬编码凭证。"""
        # 提取变量名和值
        var_name = None
        value_node = None

        for child in node.children:
            if child.type == "variable_declarator":
                for subchild in child.children:
                    if subchild.type == "identifier":
                        var_name = self._get_node_text(subchild)
                    elif subchild.type in ("string", "number"):
                        value_node = subchild

        if not var_name or not value_node:
            return

        if not self._looks_like_secret_name(var_name):
            return

        value_str = self._get_node_text(value_node)
        if value_str and not self._is_placeholder(value_str):
            line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
            finding: dict[str, Any] = {
                "type": "HARDCODED_CREDENTIALS",
                "rule_id": self.rule_id,
                "severity": self._effective_severity(context),
                "line": line_no,
                "details": f"发现疑似硬编码凭证变量 '{var_name}'，建议使用环境变量或安全配置管理。",
            }
            context.add_finding(finding)

    def _check_assignment(self, node: Node, context: AnalysisContext) -> None:
        """检测赋值表达式中的硬编码凭证。"""
        # 提取左侧（变量名）和右侧（值）
        left_node = None
        right_node = None

        for child in node.children:
            if child.type == "member_expression":
                # obj.key 形式
                for subchild in child.children:
                    if subchild.type == "property_identifier":
                        left_node = subchild
            elif child.type == "identifier":
                left_node = child
            elif child.type in ("string", "number"):
                right_node = child

        if not left_node or not right_node:
            return

        var_name = self._get_node_text(left_node)
        if not var_name or not self._looks_like_secret_name(var_name):
            return

        value_str = self._get_node_text(right_node)
        if value_str and not self._is_placeholder(value_str):
            line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
            finding: dict[str, Any] = {
                "type": "HARDCODED_CREDENTIALS",
                "rule_id": self.rule_id,
                "severity": self._effective_severity(context),
                "line": line_no,
                "details": f"发现疑似硬编码凭证变量 '{var_name}'，建议使用环境变量或安全配置管理。",
            }
            context.add_finding(finding)

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    def _effective_severity(self, context: AnalysisContext) -> str:
        """配置类文件降级为 Medium，测试文件降级为 Low。"""
        fp = getattr(context, "file_path", None) or ""
        path_lower = str(fp).lower().replace("\\", "/")
        if self._TEST_FILE_RE.search(path_lower):
            return "Low"
        if "config" in path_lower:
            return "Medium"
        return self.severity

    _TEST_FILE_RE = re.compile(
        r"[\\/](tests?|test_\w+|conftest|__tests__)[\\/]|[\\/]test_[^/\\]+\.\w+$|\.test\.[jt]sx?$|\.spec\.[jt]sx?$",
        re.IGNORECASE,
    )

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

        【修复】排除 Message/Error；key 仅整词或 api_key/apikey 形态；排除已知误报列表。
        """
        name_lower = name.lower()

        # 排除已知误报（如 keyPanSpeed, keyboard）
        if name_lower in JavaScriptHardcodedCredentialsAstRule.CREDENTIAL_FALSE_POSITIVES:
            return False

        # 排除包含 Message, Error 的变量名（如 invalidPasswordErrorMessage, passwordError）
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

        # key 仅整词或 api_key/apikey 形态，避免匹配 keyPanSpeed, keyCode 等
        if "key" in name_lower:
            if name_lower == "key":
                return True
            if "_key" in name_lower or "key_" in name_lower:
                return True
            if "api_key" in name_lower or "apikey" in name_lower:
                return True
            # 其他含 key 的形态（如 secretkey）保留；keyPanSpeed 等已由 CREDENTIAL_FALSE_POSITIVES 排除
            if "secretkey" in name_lower or "secret_key" in name_lower:
                return True

        return False

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        """
        检查值是否为占位符或纯演示字符串，避免对无害的示例凭证误报。

        Tree-sitter 提取的字符串节点文本包含引号（如 ``"'abc'"`` / ``'""'``），
        所以需要先剥离外层引号再判断。

        判断逻辑（满足任一即视为占位符）：
        1. 精确匹配已知占位符词
        2. 以 ``_here`` / ``_here"`` 结尾（如 ``session_cookie_secret_key_here``）
        3. 以 ``<``/``>`` 包围（如 ``<your_key>``）
        4. 含 ``your_`` / ``change_`` / ``replace_`` / ``changeme`` / ``change me`` 前缀
        5. 仅由字母数字和下划线组成且全大写（如 ``YOUR_SECRET_KEY``）
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

        # _here 结尾（如 session_cookie_secret_key_here、a_secure_key_for_crypto_here）
        if s_lower.endswith("_here"):
            return True

        # <...> 占位符包装（如 <your_api_key>）
        if stripped.startswith("<") and stripped.endswith(">"):
            return True

        # 含提示性前缀
        placeholder_prefixes = ("your_", "change_", "replace_", "put_your_", "insert_your_", "enter_your_")
        if any(s_lower.startswith(pfx) for pfx in placeholder_prefixes):
            return True

        # 全大写下划线格式（如 YOUR_SECRET_KEY、MY_API_KEY_HERE）
        if re.match(r"^[A-Z][A-Z0-9_]*$", stripped) and len(stripped) >= 6:
            return True

        # 低熵检测：纯小写字母、短于 8 字符、不含数字 → 极可能是测试/演示字符串
        # 例如 "admin"、"test"、"login" 等（这些不算真实密钥）
        if len(stripped) < 8 and re.match(r"^[a-z]+$", stripped):
            return True

        return False

    @staticmethod
    def _get_node_text(node: Node) -> str | None:
        """提取节点的文本内容。"""
        if hasattr(node, "text"):
            return node.text.decode("utf-8")
        return None


__all__ = ["JavaScriptHardcodedCredentialsAstRule"]
