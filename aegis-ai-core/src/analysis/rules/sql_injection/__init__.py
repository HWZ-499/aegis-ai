"""
sql_injection 规则子包。

当前包含：
- SQLInjectionRegexRule: 基于正则的 SQL 注入检测（行级）。
- PythonSQLInjectionAstRule: 基于 Python AST 的 SQL 注入检测（字符串拼接）。
- JavaScriptSQLInjectionAstRule: 基于 Tree-sitter AST 的 JavaScript/TypeScript SQL 注入检测。
"""

from .regex_rule import SQLInjectionRegexRule
from .ast_rule import PythonSQLInjectionAstRule
from .javascript_ast_rule import JavaScriptSQLInjectionAstRule

__all__ = ["SQLInjectionRegexRule", "PythonSQLInjectionAstRule", "JavaScriptSQLInjectionAstRule"]

