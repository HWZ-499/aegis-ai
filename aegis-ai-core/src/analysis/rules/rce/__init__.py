"""
rce 规则子包。

当前包含：
- PythonRCEAstRule: 基于 Python AST 的 RCE 检测规则。
- JavaScriptRCEAstRule: 基于 Tree-sitter AST 的 JavaScript/TypeScript RCE 检测规则。
"""

from .ast_rule import PythonRCEAstRule
from .javascript_ast_rule import JavaScriptRCEAstRule

__all__ = ["PythonRCEAstRule", "JavaScriptRCEAstRule"]

