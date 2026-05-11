"""
TP: params protect values, but not SQL fragments already concatenated into
the query variable.
Expected: SQL_INJECTION
"""

from typing import Any


def list_users(request: Any, cursor: Any) -> None:
    sort = request.GET.get("sort")
    status = request.GET.get("status")
    query = "SELECT * FROM users WHERE status = %s ORDER BY " + sort
    cursor.execute(query, (status,))
