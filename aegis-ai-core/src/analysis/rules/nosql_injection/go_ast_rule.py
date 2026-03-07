"""
nosql_injection.go_ast_rule

Go NoSQL 注入规则（行级模式匹配版）。

当前 PoC 目标：
- 覆盖典型模式：MongoDB/ODM 查询方法的参数直接包含 `r.FormValue(...)`
  或 `r.URL.Query().Get(...)` 等用户输入。
"""

from __future__ import annotations

import re
from typing import Any

from ...base import AnalysisContext, SecurityRule


class GoNoSQLInjectionAstRule(SecurityRule):
    """基于源码行级模式的 Go NoSQL 注入检测规则。

    该规则不依赖 TaintGraph，仅在 `after_file` 钩子中扫描源码，
    用于补齐 Go 语言的 NoSQL 注入检测能力。
    """

    _GO_NOSQL_RE = re.compile(
        r"""
        \.\s*
        (?:Find|FindOne|Update|UpdateOne|UpdateMany|DeleteOne|DeleteMany|Aggregate)
        \s*\(
            [\s\S]*?
            (?:r\.FormValue\s*\(|r\.URL\.Query\(\)\.Get\s*\()
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    def __init__(self) -> None:
        """初始化 Go NoSQL 注入规则。"""
        super().__init__(
            rule_id="NOSQL_INJECTION_GO_AST",
            severity="High",
            languages=["go"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:  # type: ignore[override]
        """Go NoSQL 规则不依赖逐节点访问，在 after_file 中统一处理。"""

    def after_file(self, context: AnalysisContext) -> None:  # type: ignore[override]
        """在文件分析结束后执行行级 NoSQL 注入模式匹配。

        Args:
            context: 分析上下文。
        """
        source = context.extras.get("source", "")
        if not source:
            return

        for match in self._GO_NOSQL_RE.finditer(source):
            line_no = source[: match.start()].count("\n") + 1
            finding: dict[str, Any] = {
                "type": "NOSQL_INJECTION",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": (
                    "检测到 Go 代码中使用 HTTP 请求参数直接构造 NoSQL 查询条件，"
                    "存在 NoSQL 注入风险，建议进行白名单过滤或参数绑定。"
                ),
            }
            context.add_finding(finding)


__all__ = ["GoNoSQLInjectionAstRule"]
