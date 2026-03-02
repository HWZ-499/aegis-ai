"""
nosql_injection 规则子包。

当前包含：
- JavaScriptNoSQLInjectionAstRule: 基于 Tree-sitter AST 的 JavaScript/TypeScript NoSQL 注入检测。
未来将扩展：
- MongoDB / Mongoose / DynamoDB 等 NoSQL 注入检测规则；
- ORM/ODM 场景下的参数化 / 查询构造安全检查。
"""

from .javascript_ast_rule import JavaScriptNoSQLInjectionAstRule

__all__ = ["JavaScriptNoSQLInjectionAstRule"]

