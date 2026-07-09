"""
analysis.rules

规则库命名空间：
- 按漏洞类型（sql_injection / rce / xss 等）组织子包；
- 每个子包内部可以同时包含多种实现方式（正则、AST、数据流分析等）。
- php/ 子包提供基于 PhpTaintGraph 的精确 PHP 规则。
"""

from .deserialization import (
    GoDeserializationAstRule,
    JavaDeserializationAstRule,
    JavaScriptDeserializationAstRule,
    PhpDeserializationAstRule,
    PythonDeserializationAstRule,
)
from .hardcoded_credentials import (
    GoHardcodedCredentialsAstRule,
    JavaHardcodedCredentialsAstRule,
    JavaScriptHardcodedCredentialsAstRule,
    PhpHardcodedCredentialsAstRule,
    PythonHardcodedCredentialsAstRule,
)
from .nosql_injection import (
    GoNoSQLInjectionAstRule,
    JavaNoSQLInjectionAstRule,
    JavaScriptNoSQLInjectionAstRule,
    PhpNoSQLInjectionAstRule,
    PythonNoSQLInjectionAstRule,
)
from .open_redirect import (
    GoOpenRedirectAstRule,
    JavaOpenRedirectAstRule,
    JavaScriptOpenRedirectAstRule,
    PhpOpenRedirectAstRule,
    PythonOpenRedirectAstRule,
)
from .path_traversal import (
    GoPathTraversalAstRule,
    JavaPathTraversalAstRule,
    JavaScriptPathTraversalAstRule,
    PhpPathTraversalAstRule,
    PythonPathTraversalAstRule,
)
from .php import (
    PhpDeserializationRule,
    PhpHardcodedCredentialsRule,
    PhpNoSQLInjectionRule,
    PhpOpenRedirectRule,
    PhpPathTraversalRule,
    PhpRCERule,
    PhpSQLInjectionRule,
    PhpXSSRule,
)
from .rce import GoRCEAstRule, JavaRCEAstRule, JavaScriptRCEAstRule, PhpRCEAstRule, PythonRCEAstRule
from .sql_injection import (
    GoSQLInjectionAstRule,
    JavaScriptSQLInjectionAstRule,
    JavaSQLInjectionAstRule,
    PhpSQLInjectionAstRule,
    PythonSQLInjectionAstRule,
    SQLInjectionRegexRule,
)
from .ssrf import (
    GoSSRFAstRule,
    JavaScriptSSRFAstRule,
    JavaSSRFAstRule,
    PhpSSRFAstRule,
    PythonSSRFAstRule,
)
from .xss import GoXSSAstRule, JavaScriptXSSAstRule, JavaXSSAstRule, PhpXSSAstRule, PythonXSSAstRule

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
    "JavaNoSQLInjectionAstRule",
    "GoNoSQLInjectionAstRule",
    "PythonOpenRedirectAstRule",
    "JavaScriptOpenRedirectAstRule",
    "JavaOpenRedirectAstRule",
    "GoOpenRedirectAstRule",
    "PythonSSRFAstRule",
    "JavaScriptSSRFAstRule",
    "PhpSSRFAstRule",
    "JavaSSRFAstRule",
    "GoSSRFAstRule",
    # PHP TaintGraph 规则（旧，保留兼容）
    "PhpSQLInjectionRule",
    "PhpRCERule",
    "PhpXSSRule",
    "PhpOpenRedirectRule",
    "PhpPathTraversalRule",
    "PhpDeserializationRule",
    "PhpNoSQLInjectionRule",
    "PhpHardcodedCredentialsRule",
    # PHP AST 规则（新）
    "PhpSQLInjectionAstRule",
    "PhpRCEAstRule",
    "PhpXSSAstRule",
    "PhpOpenRedirectAstRule",
    "PhpPathTraversalAstRule",
    "PhpDeserializationAstRule",
    "PhpNoSQLInjectionAstRule",
    "PhpHardcodedCredentialsAstRule",
]
