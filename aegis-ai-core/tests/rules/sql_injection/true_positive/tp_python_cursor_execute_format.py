"""True positive: Python SQL injection via string format in cursor.execute."""
import sqlite3


def get_user(request):
    username = request.GET.get("name")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '%s'" % username
    cursor.execute(query)
    return cursor.fetchall()
