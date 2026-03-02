"""
analysis.rules

规则库命名空间：
- 按漏洞类型（sql_injection / rce / xss 等）组织子包；
- 每个子包内部可以同时包含多种实现方式（正则、AST、数据流分析等）。
- php/ 子包提供基于 PhpTaintGraph 的精确 PHP 规则。
"""

from .sql_injection import SQLInjectionRegexRule, PythonSQLInjectionAstRule, JavaScriptSQLInjectionAstRule
from .rce import PythonRCEAstRule, JavaScriptRCEAstRule
from .xss import PythonXSSAstRule, JavaScriptXSSAstRule
from .path_traversal import PythonPathTraversalAstRule, JavaScriptPathTraversalAstRule
from .hardcoded_credentials import PythonHardcodedCredentialsAstRule, JavaScriptHardcodedCredentialsAstRule
from .deserialization import PythonDeserializationAstRule, JavaScriptDeserializationAstRule
from .nosql_injection import JavaScriptNoSQLInjectionAstRule
from .php import PhpSQLInjectionRule, PhpRCERule, PhpXSSRule, PhpOpenRedirectRule

__all__ = [
    "SQLInjectionRegexRule",
    "PythonSQLInjectionAstRule",
    "JavaScriptSQLInjectionAstRule",
    "PythonRCEAstRule",
    "JavaScriptRCEAstRule",
    "PythonXSSAstRule",
    "JavaScriptXSSAstRule",
    "PythonPathTraversalAstRule",
    "JavaScriptPathTraversalAstRule",
    "PythonHardcodedCredentialsAstRule",
    "JavaScriptHardcodedCredentialsAstRule",
    "PythonDeserializationAstRule",
    "JavaScriptDeserializationAstRule",
    "JavaScriptNoSQLInjectionAstRule",
    # PHP TaintGraph 规则
    "PhpSQLInjectionRule",
    "PhpRCERule",
    "PhpXSSRule",
    "PhpOpenRedirectRule",
]


