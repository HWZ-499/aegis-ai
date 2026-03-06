"""
nosql_injection 规则子包。

当前包含：
- JavaScriptNoSQLInjectionAstRule: 基于 Tree-sitter AST 的 JavaScript/TypeScript NoSQL 注入检测。
- PythonNoSQLInjectionAstRule: 基于 Python AST 的 pymongo/motor NoSQL 注入检测。
"""

from .javascript_ast_rule import JavaScriptNoSQLInjectionAstRule
from .python_ast_rule import PythonNoSQLInjectionAstRule

__all__ = ["JavaScriptNoSQLInjectionAstRule", "PythonNoSQLInjectionAstRule"]

