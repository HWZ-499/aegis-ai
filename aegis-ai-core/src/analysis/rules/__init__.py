"""
analysis.rules

规则库命名空间：
- 按漏洞类型（sql_injection / rce / xss 等）组织子包；
- 每个子包内部可以包含 AST、数据流和声明式 DSL 等实现方式。
- PHP 规则与其他语言一样按漏洞类型组织。
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
from .rce import GoRCEAstRule, JavaRCEAstRule, JavaScriptRCEAstRule, PhpRCEAstRule, PythonRCEAstRule
from .sql_injection import (
    GoSQLInjectionAstRule,
    JavaScriptSQLInjectionAstRule,
    JavaSQLInjectionAstRule,
    PhpSQLInjectionAstRule,
    PythonSQLInjectionAstRule,
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
    # PHP AST/taint rules
    "PhpSQLInjectionAstRule",
    "PhpRCEAstRule",
    "PhpXSSAstRule",
    "PhpOpenRedirectAstRule",
    "PhpPathTraversalAstRule",
    "PhpDeserializationAstRule",
    "PhpNoSQLInjectionAstRule",
    "PhpHardcodedCredentialsAstRule",
]
