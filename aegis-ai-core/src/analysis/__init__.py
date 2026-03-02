"""
analysis 包

旧实现：
- ast_analyzer / multi_language_ast / security_rules 等仍然可用。

新架构：
- base:         提供 AnalysisContext / SecurityRule 等基础设施
- rules:        按漏洞类型拆分的规则库（sql_injection / rce / ...）
- analyzers:    按语言划分的分析器（PythonAnalyzer / JavaScriptAnalyzer / PhpAnalyzer）
- taint:        污点分析系统（TaintAnalyzer / TaintGraph / CrossFileAnalyzer）
- cfg:          控制流图与支配树（CFG / DominatorTree）
- rule_engine:  汇总并提供默认规则集、统一的分析入口
"""

from .base import AnalysisContext, SecurityRule

__all__ = ["AnalysisContext", "SecurityRule"]

