"""
open_redirect 规则子包。

当前包含：
- PythonOpenRedirectAstRule: 基于 TaintGraph 的 Python Open Redirect 检测规则。
- JavaScriptOpenRedirectAstRule: 基于 TaintGraph 的 JS/TS Open Redirect 检测规则。
- JavaOpenRedirectAstRule: 基于 TaintGraph 的 Java Open Redirect 检测规则。
- GoOpenRedirectAstRule: 基于 TaintGraph 的 Go Open Redirect 检测规则。
"""

from .go_ast_rule import GoOpenRedirectAstRule
from .java_ast_rule import JavaOpenRedirectAstRule
from .javascript_ast_rule import JavaScriptOpenRedirectAstRule
from .python_ast_rule import PythonOpenRedirectAstRule

from .php_ast_rule import PhpOpenRedirectAstRule

__all__ = [
    "PythonOpenRedirectAstRule",
    "JavaScriptOpenRedirectAstRule",
    "JavaOpenRedirectAstRule",
    "GoOpenRedirectAstRule",
    "PhpOpenRedirectAstRule",
]
