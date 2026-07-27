"""
FP: 使用参数化查询传入用户输入，不应视为 SQL 注入。
期望: 无 SQL_INJECTION
"""

from typing import Any


def safe_query(request: Any, cursor: Any) -> None:
    user = request.GET.get("name")
    sql = "SELECT * FROM users WHERE name = %s"
    # 参数化传入用户输入
    cursor.execute(sql, (user,))
