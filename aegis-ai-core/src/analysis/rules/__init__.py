"""
analysis.rules

规则库命名空间：
- 按漏洞类型（sql_injection / rce / xss 等）组织子包；
- 每个子包内部可以同时包含多种实现方式（正则、AST、数据流分析等）。
- php/ 子包提供基于 PhpTaintGraph 的精确 PHP 规则。
"""

from .sql_injection import (
    SQLInjectionRegexRule,
    PythonSQLInjectionAstRule,
    JavaScriptSQLInjectionAstRule,
    JavaSQLInjectionAstRule,
    GoSQLInjectionAstRule,
)
from .rce import PythonRCEAstRule, JavaScriptRCEAstRule, JavaRCEAstRule, GoRCEAstRule
from .xss import PythonXSSAstRule, JavaScriptXSSAstRule, JavaXSSAstRule, GoXSSAstRule
from .path_traversal import (
    PythonPathTraversalAstRule,
    JavaScriptPathTraversalAstRule,
    JavaPathTraversalAstRule,
    GoPathTraversalAstRule,
)
from .hardcoded_credentials import (
    PythonHardcodedCredentialsAstRule,
    JavaScriptHardcodedCredentialsAstRule,
    JavaHardcodedCredentialsAstRule,
    GoHardcodedCredentialsAstRule,
)
from .deserialization import (
    PythonDeserializationAstRule,
    JavaScriptDeserializationAstRule,
    JavaDeserializationAstRule,
    GoDeserializationAstRule,
)
from .nosql_injection import JavaScriptNoSQLInjectionAstRule, PythonNoSQLInjectionAstRule
from .open_redirect import JavaOpenRedirectAstRule, GoOpenRedirectAstRule
from .php import (
    PhpSQLInjectionRule,
    PhpRCERule,
    PhpXSSRule,
    PhpOpenRedirectRule,
    PhpPathTraversalRule,
    PhpDeserializationRule,
    PhpHardcodedCredentialsRule,
)

__all__ = [
    "SQLInjectionRegexRule",
    "PythonSQLInjectionAstRule",
    "JavaScriptSQLInjectionAstRule",
    "JavaSQLInjectionAstRule",
    "GoSQLInjectionAstRule",
    "PythonRCEAstRule",
    "JavaScriptRCEAstRule",
    "JavaRCEAstRule",
    "GoRCEAstRule",
    "PythonXSSAstRule",
    "JavaScriptXSSAstRule",
    "JavaXSSAstRule",
    "GoXSSAstRule",
    "PythonPathTraversalAstRule",
    "JavaScriptPathTraversalAstRule",
    "JavaPathTraversalAstRule",
    "GoPathTraversalAstRule",
    "PythonHardcodedCredentialsAstRule",
    "JavaScriptHardcodedCredentialsAstRule",
    "JavaHardcodedCredentialsAstRule",
    "GoHardcodedCredentialsAstRule",
    "PythonDeserializationAstRule",
    "JavaScriptDeserializationAstRule",
    "JavaDeserializationAstRule",
    "GoDeserializationAstRule",
    "JavaScriptNoSQLInjectionAstRule",
    "PythonNoSQLInjectionAstRule",
    "JavaOpenRedirectAstRule",
    "GoOpenRedirectAstRule",
    # PHP TaintGraph 规则
    "PhpSQLInjectionRule",
    "PhpRCERule",
    "PhpXSSRule",
    "PhpOpenRedirectRule",
    "PhpPathTraversalRule",
    "PhpDeserializationRule",
    "PhpHardcodedCredentialsRule",
]


