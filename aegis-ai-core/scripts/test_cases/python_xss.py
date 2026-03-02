"""
Python XSS 合成测试用例
规则: TP（直接输出）/ TN（HTML 转义）/ 传播污点
"""

from markupsafe import Markup, escape as html_escape


# ── TP-1: 直接 HttpResponse 输出用户输入 ────────────────────────
# EXPECT: XSS_RISK, line 14
def xss_tp1(request):
    name = request.GET.get("name")
    return HttpResponse(name)           # 直接写入响应 → XSS


# ── TP-2: render 模板未转义（直接拼接） ─────────────────────────
# EXPECT: XSS_RISK, line 20
def xss_tp2(request):
    msg = request.POST.get("msg")
    response.write("<p>" + msg + "</p>")


# ── TP-3: f-string 输出 ──────────────────────────────────────
# EXPECT: XSS_RISK, line 27
def xss_tp3(request):
    user = request.args.get("user")
    response.write(f"<h1>Hello {user}</h1>")


# ── TN-1: html.escape 净化 ────────────────────────────────────
# EXPECT: no XSS finding
def xss_tn1(request):
    import html
    name = request.GET.get("name")
    safe_name = html.escape(name)
    return HttpResponse(safe_name)


# ── TN-2: markupsafe escape ──────────────────────────────────
# EXPECT: no XSS finding
def xss_tn2(request):
    name = request.GET.get("name")
    safe = html_escape(name)
    return HttpResponse(safe)


# ── TN-3: Django 模板（自动转义，不直接写入响应） ─────────────────
# EXPECT: no XSS finding
def xss_tn3(request):
    name = request.GET.get("name")
    return render(request, "template.html", {"name": name})


# ── PROP-1: 赋值传播后输出 ────────────────────────────────────
# EXPECT: XSS_RISK, line 54
def xss_prop1(request):
    raw = request.GET.get("comment")
    sanitized_attempt = raw.strip()     # strip 不净化 XSS
    content = "<div>" + sanitized_attempt + "</div>"
    response.write(content)


# ── PROP-2: 字典传播 ──────────────────────────────────────────
# EXPECT: XSS_RISK, line 62
def xss_prop2(request):
    payload = {"msg": request.POST.get("msg")}
    response.write(payload["msg"])
