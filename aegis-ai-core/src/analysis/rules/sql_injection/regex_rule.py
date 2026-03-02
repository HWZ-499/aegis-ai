"""
sql_injection.regex_rule

示例规则：基于正则的 SQL 注入检测（行级），用于演示新规则架构。

说明：
- 这是一个“过渡期”规则：仍然按行扫描，但封装到独立模块；
- 后续可以逐步用更智能的 AST / 污点分析规则替换或补充它。
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List

from ...base import AnalysisContext, SecurityRule


class SQLInjectionRegexRule(SecurityRule):
    """
    基于正则表达式的 SQL 注入检测规则（跨语言）。

    注意：
    - 这里只抽取了当前项目中最核心的一部分 SQL 注入正则模式；
    - 目标是演示“规则拆分 + 新基类”的用法，而不是完全替代旧实现。
    """

    # 核心危险模式（简化版），主要覆盖“字符串拼接构造 SQL”场景
    _PATTERNS: Iterable[str] = (
        # Python
        r"execute\s*\(\s*['\"].*%s.*['\"]\s*%\s*",
        r"\.execute\s*\(\s*['\"].*\+.*['\"]\s*\)",
        # Node.js / 通用
        r"\.query\s*\(\s*['\"].*\+.*['\"]\s*\)",
        r"db\.query\s*\(\s*['\"].*\+.*['\"]\s*\)",
        r"`SELECT.*\$\{.*\}.*`",
    )

    def __init__(self) -> None:
        super().__init__(rule_id="SQL_INJECTION_REGEX", severity="High")
        # 预编译正则，避免每行重复编译
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self._PATTERNS]

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """
        这里为了示例，暂不直接依赖 AST 结构，而是：
        - 由上层遍历器把“整文件源码”放到 context.extras["source"];
        - 本规则只在 before_file/after_file 中做一次按行扫描。
        """
        # 行级规则不在每个节点都执行，逻辑放在 after_file 中
        return

    # 豁免模式：Python % 字符串格式化操作数为 ORM/框架内部受控标识符时不报告。
    # 匹配形如：execute("...%s" % table) / execute("...%s" % self._table, [...])
    # 用 ["'] 匹配 SQL 字符串结束引号，之后紧跟 Python 格式化操作符 %，再跟标识符。
    _SAFE_INTERPOLATION = re.compile(
        r"""execute\s*\(.*["']\s*%\s+(?:self\.\w+|\w*[Tt]able\w*|tbl|schema|col(?:umn)?|field)\b""",
        re.IGNORECASE,
    )

    def after_file(self, context: AnalysisContext) -> None:
        """
        在整文件 AST 遍历完成后，对源代码做一次按行扫描。
        """
        source: str = context.extras.get("source") or ""
        if not source:
            return

        lines = source.splitlines()
        for idx, line in enumerate(lines, start=1):
            code = line.strip()
            if not code:
                continue

            # 简单过滤：跳过明显的注释行
            if code.startswith("#") or code.startswith("//") or code.startswith("--"):
                continue

            # 豁免：execute() 中 % 插值为框架内部受控变量（self.xxx、table_name 等）
            if self._SAFE_INTERPOLATION.search(code):
                continue

            for regex in self._compiled:
                if regex.search(code):
                    finding: Dict[str, Any] = {
                        "type": "SQL_INJECTION",
                        "rule_id": self.rule_id,
                        "severity": self.severity,
                        "line": idx,
                        "code": line,
                        "details": "检测到可能的 SQL 字符串拼接（简化版规则）",
                    }
                    context.add_finding(finding)
                    # 一行命中一个模式就足够了，避免重复噪音
                    break

