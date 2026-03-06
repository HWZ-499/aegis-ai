"""
xss 规则子包。

当前包含：
- PythonXSSAstRule: 基于 Python AST 的 XSS 风险检测（用户输入直接输出）。
- JavaScriptXSSAstRule: 基于 Tree-sitter AST 的 JavaScript/TypeScript XSS 风险检测。
- JavaXSSAstRule: 基于 TaintGraph 的 Java XSS 风险检测。
- GoXSSAstRule: 基于 TaintGraph 的 Go XSS 风险检测。
未来将扩展：
- 基于正则的 XSS 检测规则；
- 基于 AST / 数据流的 XSS 规则（包括框架特定规则，如 React/Vue/Angular 等）。
"""

from .ast_rule import PythonXSSAstRule
from .javascript_ast_rule import JavaScriptXSSAstRule
from .java_ast_rule import JavaXSSAstRule
from .go_ast_rule import GoXSSAstRule

__all__ = ["PythonXSSAstRule", "JavaScriptXSSAstRule", "JavaXSSAstRule", "GoXSSAstRule"]

