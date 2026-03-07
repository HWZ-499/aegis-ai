"""
nosql_injection.java_ast_rule

Java NoSQL 注入规则（行级模式匹配版）。

当前 PoC 目标：
- 覆盖典型模式：MongoDB/ODM 查询方法的参数直接包含 `request.getParameter(...)`。
"""

from __future__ import annotations

import re
from typing import Any

from ...base import AnalysisContext, SecurityRule


class JavaNoSQLInjectionAstRule(SecurityRule):
    """基于源码行级模式的 Java NoSQL 注入检测规则。

    该规则不依赖 TaintGraph，只在 `after_file` 钩子中对源码进行轻量正则扫描，
    用于补齐 Java 语言的 NoSQL 注入检测能力。
    """

    _JAVA_NOSQL_RE = re.compile(
        r"""
        \.\s*
        (?:find|findOne|update|updateOne|updateMany|deleteOne|deleteMany|aggregate)
        \s*\(
            [^;]*request\.getParameter\s*\(
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    def __init__(self) -> None:
        """初始化 Java NoSQL 注入规则。"""
        super().__init__(
            rule_id="NOSQL_INJECTION_JAVA_AST",
            severity="High",
            languages=["java"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:  # type: ignore[override]
        """Java NoSQL 规则不依赖逐节点访问，在 after_file 中统一处理。"""

    def after_file(self, context: AnalysisContext) -> None:  # type: ignore[override]
        """在文件分析结束后执行行级 NoSQL 注入模式匹配。

        Args:
            context: 分析上下文。
        """
        source = context.extras.get("source", "")
        if not source:
            return

        lines = source.split("\n")
        for idx, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not self._JAVA_NOSQL_RE.search(line):
                continue

            finding: dict[str, Any] = {
                "type": "NOSQL_INJECTION",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": idx,
                "details": (
                    "检测到 Java 代码中使用 request.getParameter 直接构造 NoSQL 查询条件，"
                    "存在 NoSQL 注入风险，建议进行白名单过滤或参数绑定。"
                ),
            }
            context.add_finding(finding)


__all__ = ["JavaNoSQLInjectionAstRule"]
