"""
analysis.rules.php

PHP 安全规则子包。

基于 PhpTaintGraph（行级赋值链追踪）提供高精度检测：
- PhpSQLInjectionRule : SQL 注入（Source→query/execute Sink）
- PhpRCERule          : 命令执行（Source→shell_exec/system 等 Sink）
- PhpXSSRule          : XSS（Source→echo/print Sink，未经 htmlspecialchars）
- PhpOpenRedirectRule : 开放重定向（Source→header("Location: ") Sink）

与 security_rules.scan_code_locally 的分工：
- scan_code_locally  宽泛正则匹配（高召回）
- 本包规则           精确数据流判断（高精度），结果中携带污点链信息
"""

from .php_taint_rules import (
    PhpSQLInjectionRule,
    PhpRCERule,
    PhpXSSRule,
    PhpOpenRedirectRule,
)

__all__ = [
    "PhpSQLInjectionRule",
    "PhpRCERule",
    "PhpXSSRule",
    "PhpOpenRedirectRule",
]
