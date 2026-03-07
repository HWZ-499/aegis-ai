"""
hardcoded_credentials.go_ast_rule

Go 硬编码凭证 AST 规则。

检测目标：
- 将明显是“密码 / 密钥 / Token 等”的变量，直接赋值为常量字符串。
"""

from __future__ import annotations

from typing import Any

from ...base import AnalysisContext, SecurityRule


class GoHardcodedCredentialsAstRule(SecurityRule):
    """
    基于源码扫描的 Go 硬编码凭证检测规则。

    说明：
    - 为降低复杂度，当前实现不依赖 Tree-sitter，而是在 after_file 中对源码做简单正则扫描；
      与 AST 规则共享同一 SecurityRule 接口。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="HARDCODED_CREDENTIALS_GO_AST",
            severity="High",
            languages=["go"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """本规则不使用逐节点访问。"""
        return

    def after_file(self, context: AnalysisContext) -> None:
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

            lower_name = name.lower()
            if not any(
                key in lower_name for key in ("password", "passwd", "pwd", "secret", "token", "api_key", "apikey")
            ):
                continue

            first_quote = right.find('"')
            last_quote = right.rfind('"')
            if first_quote == -1 or last_quote <= first_quote:
                continue
            value = right[first_quote + 1 : last_quote]
            if self._is_placeholder(value):
                continue

            details = f"发现 Go 代码中疑似硬编码凭证变量 '{name}'，建议改为从环境变量或安全配置加载。"
            finding: dict[str, Any] = {
                "type": "HARDCODED_CREDENTIALS",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": idx,
                "details": details,
            }
            context.add_finding(finding)

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        """复用与 Java/JS 类似的占位符判断逻辑（简化版）。"""
        v = value.strip().lower()
        if not v:
            return True
        placeholders = {
            "your_password",
            "your_key",
            "changeme",
            "change_me",
            "change_this",
            "replace_me",
            "replace_this",
        }
        if v in placeholders:
            return True
        if v.endswith("_here"):
            return True
        if v.startswith("<") and v.endswith(">"):
            return True
        return False


__all__ = ["GoHardcodedCredentialsAstRule"]
