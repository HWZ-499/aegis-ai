"""
ssrf 规则子包（Server-Side Request Forgery，服务端请求伪造）。

当前包含：
- PythonSSRFAstRule: 基于 TaintGraph 的 Python SSRF 检测规则（CWE-918）。
- JavaScriptSSRFAstRule: 基于 TaintGraph 的 JS/TS SSRF 检测规则（CWE-918）。
"""

from .javascript_ast_rule import JavaScriptSSRFAstRule
from .python_ast_rule import PythonSSRFAstRule

__all__ = [
    "PythonSSRFAstRule",
    "JavaScriptSSRFAstRule",
]
