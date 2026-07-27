"""
ssrf 规则子包（Server-Side Request Forgery，服务端请求伪造）。

当前覆盖 Python、JavaScript/TypeScript、PHP、Java、Go。
"""

from .go_ast_rule import GoSSRFAstRule
from .java_ast_rule import JavaSSRFAstRule
from .javascript_ast_rule import JavaScriptSSRFAstRule
from .php_ast_rule import PhpSSRFAstRule
from .python_ast_rule import PythonSSRFAstRule

__all__ = [
    "PythonSSRFAstRule",
    "JavaScriptSSRFAstRule",
    "PhpSSRFAstRule",
    "JavaSSRFAstRule",
    "GoSSRFAstRule",
]
