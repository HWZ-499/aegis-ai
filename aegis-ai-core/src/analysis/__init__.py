"""
Analysis package.

Architecture:
- base:         提供 AnalysisContext / SecurityRule 等基础设施
- rules:        按漏洞类型拆分的规则库（sql_injection / rce / ...）
- analyzers:    按语言划分的分析器（PythonAnalyzer / JavaScriptAnalyzer / PhpAnalyzer）
- taint:        污点分析系统（TaintAnalyzer / TaintGraph / CrossFileAnalyzer）
- cfg:          控制流图与支配树（CFG / DominatorTree）
- rule_engine:  汇总并提供默认规则集、统一的分析入口

Public callers should use ``rule_engine.analyze_source``. The
``multi_language_ast`` module remains only as a thin source-compatible adapter
for callers that have not migrated to the canonical entry point yet.
"""

from .base import AnalysisContext, SecurityRule

__all__ = ["AnalysisContext", "SecurityRule"]
