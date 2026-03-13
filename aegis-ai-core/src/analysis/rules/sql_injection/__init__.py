"""
sql_injection 规则子包。

当前包含：
- SQLInjectionRegexRule: 基于正则的 SQL 注入检测（行级）。
- PythonSQLInjectionAstRule: 基于 Python AST 的 SQL 注入检测（字符串拼接）。
- JavaScriptSQLInjectionAstRule: 基于 Tree-sitter AST 的 JavaScript/TypeScript SQL 注入检测。
- JavaSQLInjectionAstRule: 基于 TaintGraph 的 Java SQL 注入检测。
- GoSQLInjectionAstRule: 基于 TaintGraph 的 Go SQL 注入检测。
"""

from .ast_rule import PythonSQLInjectionAstRule
from .go_ast_rule import GoSQLInjectionAstRule
from .java_ast_rule import JavaSQLInjectionAstRule
from .javascript_ast_rule import JavaScriptSQLInjectionAstRule
from .regex_rule import SQLInjectionRegexRule

from .php_ast_rule import PhpSQLInjectionAstRule

__all__ = [
    "SQLInjectionRegexRule",
    "PythonSQLInjectionAstRule",
    "JavaScriptSQLInjectionAstRule",
    "JavaSQLInjectionAstRule",
    "GoSQLInjectionAstRule",
    "PhpSQLInjectionAstRule",
]
