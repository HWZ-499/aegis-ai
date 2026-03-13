"""
deserialization 规则子包。

当前包含：
- PythonDeserializationAstRule: 基于 Python AST 的反序列化风险检测。
- JavaScriptDeserializationAstRule: 基于 Tree-sitter AST 的 JavaScript/TypeScript 反序列化风险检测。
- JavaDeserializationAstRule: 基于 TaintGraph 的 Java 反序列化风险检测。
未来将扩展：
- 其他语言 / 序列化框架的反序列化规则；
- 配合数据流分析识别“反序列化不可信数据”的场景。
"""

from .ast_rule import PythonDeserializationAstRule
from .go_ast_rule import GoDeserializationAstRule
from .java_ast_rule import JavaDeserializationAstRule
from .javascript_ast_rule import JavaScriptDeserializationAstRule

from .php_ast_rule import PhpDeserializationAstRule

__all__ = [
    "PythonDeserializationAstRule",
    "JavaScriptDeserializationAstRule",
    "JavaDeserializationAstRule",
    "GoDeserializationAstRule",
    "PhpDeserializationAstRule",
]
