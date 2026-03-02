"""
hardcoded_credentials.ast_rule

Python 硬编码凭证 AST 规则（增强版）。

检测目标：
- 将明显是"密码 / 密钥 / Token 等"的变量，直接赋值为常量字符串/数值。
- ``createConnection({ password: "login" })`` 等函数关键字参数形式。
- AES / RSA / JWT 签名密钥硬编码。
- 高熵字符串指纹（Base64、Hex 模式 + 最短长度）识别真实密钥。

改进：
- 扩充敏感变量名关键词（含 JWT / auth / bearer / credential / cert / private_key）；
- 扩充占位符排除列表；
- 高熵/长度指纹：长度 >= 16 的字母数字字符串默认认为是真实密钥；
- 函数调用关键字参数检测（password= / secret= / key= 等）；
- 在测试文件（test_/tests/）中降级到 Low（测试凭证不是真正安全风险）；
- 赋值类型支持：ast.Assign / ast.AnnAssign（Python 3.6+）。
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any, Dict, Optional

from ...base import AnalysisContext, SecurityRule


# ── 敏感变量名关键词 ──────────────────────────────────────────────
_SECRET_KEYWORDS: frozenset[str] = frozenset([
    "password", "passwd", "pwd", "passphrase",
    "secret", "private_key", "privkey",
    "token", "access_token", "refresh_token", "id_token",
    "api_key", "apikey", "api_secret",
    "auth", "auth_token", "bearer",
    "credential", "credentials",
    "cert", "certificate",
    "encryption_key", "signing_key",
    "jwt_secret",
    "client_secret",
    "db_pass", "db_password",
    "mysql_pwd", "postgres_pass",
])

# ── 占位符/示例值排除列表 ─────────────────────────────────────────
_PLACEHOLDER_RE = re.compile(
    r"^("
    r"your[_\-\s]?\w*|"       # your_key / your_password / your-secret
    r"<\w+>|"                  # <SECRET>
    r"\[.*?\]|"                # [YOUR_TOKEN]
    r"placeholder|"
    r"changeme|"
    r"change.me|"
    r"todo|"
    r"fixme|"
    r"example|"
    r"test|"
    r"dummy|"
    r"fake|"
    r"sample|"
    r"n/?a|"
    r"none|"
    r"null|"
    r"undefined|"
    r"secret_here|"
    r"insert.*here|"
    r"env\(|"
    # 安全工具/框架内置的"不安全占位符"前缀，用于提示开发者而非真实密钥
    r"django-insecure-.*|"
    r"development-only-.*|"
    r"insecure-.*"
    r")$",
    re.IGNORECASE,
)

# 高熵/真实密钥的最短长度门槛（短于此认为是测试用占位符）
_MIN_REAL_SECRET_LEN = 12

# 高熵指纹：base64 / hex / 普通强密码模式
_HIGH_ENTROPY_RE = re.compile(
    r"^[A-Za-z0-9+/=_\-!@#$%^&*]{16,}$|"  # base64 / URL-safe base64 / 密码特殊字符
    r"^[0-9a-fA-F]{32,}$"                   # hex 32+ 字符
)

# 关键字参数名（函数调用中的 password=... 等）
_KW_KEYWORDS: frozenset[str] = frozenset([
    "password", "passwd", "pwd", "secret", "token", "key",
    "api_key", "apikey", "auth", "credential",
])

# 测试文件模式
_TEST_FILE_RE = re.compile(r"[\\/](tests?|test_\w+|conftest)[\\/]|[\\/]test_[^/\\]+\.py$",
                           re.IGNORECASE)


def _is_test_file(file_path: Optional[str]) -> bool:
    """判断文件是否为测试文件（降级严重度）。"""
    if not file_path:
        return False
    return bool(_TEST_FILE_RE.search(file_path))


def _extract_str_value(node: ast.AST) -> Optional[str]:
    """提取字符串/数值常量。"""
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (str, int, float)):
            return str(node.value)
    if isinstance(node, ast.Str):  # Python 3.7 兼容
        return node.s
    return None


def _is_placeholder(value: str) -> bool:
    """判断是否是典型占位符。"""
    stripped = value.strip()
    if not stripped:
        return True
    return bool(_PLACEHOLDER_RE.match(stripped))


def _is_real_secret(value: str) -> bool:
    """
    用长度 + 高熵指纹判断是否像真实密钥。

    短于 _MIN_REAL_SECRET_LEN 的普通字符串通常是占位符或测试值。
    """
    if len(value) < _MIN_REAL_SECRET_LEN:
        return False
    return bool(_HIGH_ENTROPY_RE.match(value)) or len(value) >= 20


def _looks_like_secret_name(name: str) -> bool:
    """检查变量名是否含敏感关键词。"""
    lower = name.lower()
    return any(kw in lower for kw in _SECRET_KEYWORDS)


class PythonHardcodedCredentialsAstRule(SecurityRule):
    """
    基于 Python AST 的硬编码凭证检测规则（增强版）。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="HARDCODED_CREDENTIALS_PY_AST",
            severity="High",
            languages=["python"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if isinstance(node, ast.Assign):
            self._check_assign(node, context)
        elif isinstance(node, ast.AnnAssign):
            self._check_ann_assign(node, context)
        elif isinstance(node, ast.Call):
            self._check_call_kwargs(node, context)

    # ------------------------------------------------------------------
    # 子检测方法
    # ------------------------------------------------------------------
    def _check_assign(self, node: ast.Assign, context: AnalysisContext) -> None:
        """检测普通赋值：password = "xxx"。"""
        if not node.targets:
            return
        for target in node.targets:
            name = self._extract_name(target)
            if name and _looks_like_secret_name(name):
                self._check_value(node.value, name, node, context)

    def _check_ann_assign(self, node: ast.AnnAssign, context: AnalysisContext) -> None:
        """检测带类型注解的赋值：password: str = "xxx"。"""
        if node.value is None:
            return
        name = self._extract_name(node.target)
        if name and _looks_like_secret_name(name):
            self._check_value(node.value, name, node, context)

    def _check_call_kwargs(self, node: ast.Call, context: AnalysisContext) -> None:
        """检测函数调用关键字参数：connect(password="xxx")。"""
        for kw in node.keywords:
            if not kw.arg:
                continue
            if kw.arg.lower() not in _KW_KEYWORDS:
                continue
            value_str = _extract_str_value(kw.value)
            if value_str is None:
                continue
            if _is_placeholder(value_str):
                continue
            if not _is_real_secret(value_str):
                continue
            self._emit(kw.arg, value_str, node, context)

    def _check_value(
        self,
        value_node: ast.AST,
        var_name: str,
        stmt_node: ast.AST,
        context: AnalysisContext,
    ) -> None:
        value_str = _extract_str_value(value_node)
        if value_str is None:
            return
        if _is_placeholder(value_str):
            return
        if not _is_real_secret(value_str):
            return
        self._emit(var_name, value_str, stmt_node, context)

    def _emit(
        self,
        var_name: str,
        value: str,
        node: ast.AST,
        context: AnalysisContext,
    ) -> None:
        line_no = getattr(node, "lineno", 0) or 0
        file_path: Optional[str] = context.extras.get("file_path")

        severity = self.severity
        detail_suffix = ""
        if _is_test_file(file_path):
            severity = "Low"
            detail_suffix = "（测试文件中的凭证，但仍建议避免硬编码。）"

        finding: Dict[str, Any] = {
            "type":     "HARDCODED_CREDENTIALS",
            "rule_id":  self.rule_id,
            "severity": severity,
            "line":     line_no,
            "details":  (
                f"发现疑似硬编码凭证变量 '{var_name}'（值长度 {len(value)}），"
                f"建议从环境变量（os.environ）或 Vault 等安全配置中读取。{detail_suffix}"
            ),
        }
        context.add_finding(finding)

    @staticmethod
    def _extract_name(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None


__all__ = ["PythonHardcodedCredentialsAstRule"]
