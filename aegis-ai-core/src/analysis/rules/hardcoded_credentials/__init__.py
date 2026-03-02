"""
hardcoded_credentials 规则子包。

当前包含：
- PythonHardcodedCredentialsAstRule: 基于 Python AST 的硬编码凭证检测。
- JavaScriptHardcodedCredentialsAstRule: 基于 Tree-sitter AST 的 JavaScript/TypeScript 硬编码凭证检测。
未来将扩展：
- 更智能的上下文判断（区分字段名 vs 真正的凭证值）。
"""

from .ast_rule import PythonHardcodedCredentialsAstRule
from .javascript_ast_rule import JavaScriptHardcodedCredentialsAstRule

__all__ = ["PythonHardcodedCredentialsAstRule", "JavaScriptHardcodedCredentialsAstRule"]

