"""
open_redirect 规则子包。

当前包含：
- JavaOpenRedirectAstRule: 基于 TaintGraph 的 Java Open Redirect 检测规则。
- GoOpenRedirectAstRule: 基于 TaintGraph 的 Go Open Redirect 检测规则。
"""

from .java_ast_rule import JavaOpenRedirectAstRule
from .go_ast_rule import GoOpenRedirectAstRule

__all__ = ["JavaOpenRedirectAstRule", "GoOpenRedirectAstRule"]

