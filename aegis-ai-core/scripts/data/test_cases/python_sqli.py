"""
Python SQL 注入合成测试用例
规则: TP（直接注入）/ TN（净化后安全）/ 传播污点
每组注释说明预期检测结果
"""

# ── TP-1: 直接字符串拼接 ──────────────────────────────────────
# EXPECT: SQL_INJECTION, line 17
def sqli_tp1(request):
    uid = request.GET["id"]
    cursor.execute("SELECT * FROM users WHERE id = " + uid)


# ── TP-2: %s 格式化 ──────────────────────────────────────────
# EXPECT: SQL_INJECTION, line 24
def sqli_tp2(request):
    name = request.POST.get("name")
    query = "SELECT * FROM users WHERE name = '%s'" % name
    cursor.execute(query)


# ── TP-3: f-string 注入 ──────────────────────────────────────
# EXPECT: SQL_INJECTION, line 31
def sqli_tp3(request):
    sid = request.GET.get("session_id")
    cursor.execute(f"DELETE FROM sessions WHERE sid = '{sid}'")


# ── TP-4: 多级变量传播 ────────────────────────────────────────
# EXPECT: SQL_INJECTION, line 40
def sqli_tp4(request):
    raw = request.GET["q"]
    search = raw.strip()            # strip 不是净化，仍 tainted
    query = "SELECT * FROM items WHERE name LIKE '%" + search + "%'"
    cursor.execute(query)


# ── TN-1: 参数化查询（安全）────────────────────────────────────
# EXPECT: no SQL_INJECTION finding
def sqli_tn1(request):
    uid = request.GET["id"]
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))


# ── TN-2: 整型转换净化 ────────────────────────────────────────
# EXPECT: no SQL_INJECTION finding
def sqli_tn2(request):
    uid = int(request.GET["id"])
    cursor.execute("SELECT * FROM users WHERE id = " + str(uid))


# ── TN-3: ORM 查询（安全）────────────────────────────────────
# EXPECT: no SQL_INJECTION finding (不含 execute)
def sqli_tn3(request):
    uid = request.GET["id"]
    User.objects.filter(id=uid)     # ORM 不是 Sink


# ── PROP-1: 跨变量污点传播 ────────────────────────────────────
# EXPECT: SQL_INJECTION, line 67
def sqli_prop1(request):
    a = request.GET["x"]
    b = a                           # 传播
    c = b.upper()                   # 仍 tainted
    cursor.execute("SELECT * FROM t WHERE x = '" + c + "'")


# ── PROP-2: 函数返回值传播 ────────────────────────────────────
# EXPECT: SQL_INJECTION, line 76
def sqli_prop2(request):
    def extract_param(req):
        return req.args.get("p")
    value = extract_param(request)
    cursor.execute("DELETE FROM logs WHERE id = " + value)
