"""
Python 路径遍历合成测试用例
规则: TP（直接路径操作）/ TN（basename/realpath 净化）/ 传播污点
"""
import os
from pathlib import Path
from flask import send_file, send_from_directory


# ── TP-1: open() 直接读取用户路径 ────────────────────────────
# EXPECT: PATH_TRAVERSAL, line 14
def pt_tp1(request):
    filename = request.GET.get("file")
    with open("/uploads/" + filename) as f:
        return f.read()


# ── TP-2: send_file() 用户路径 ───────────────────────────────
# EXPECT: PATH_TRAVERSAL, line 21
def pt_tp2(request):
    path = request.args.get("path")
    return send_file(path)


# ── TP-3: os.path.join + 用户输入 ────────────────────────────
# EXPECT: PATH_TRAVERSAL, line 28
def pt_tp3(request):
    name = request.GET.get("name")
    full_path = os.path.join("/data/files/", name)
    with open(full_path) as f:
        return f.read()


# ── TP-4: f-string 路径拼接 ──────────────────────────────────
# EXPECT: PATH_TRAVERSAL, line 36
def pt_tp4(request):
    filename = request.args.get("filename")
    return send_file(f"/static/{filename}")


# ── TN-1: os.path.basename 净化 ──────────────────────────────
# EXPECT: no PATH_TRAVERSAL finding
def pt_tn1(request):
    filename = request.GET.get("file")
    safe_name = os.path.basename(filename)
    with open("/uploads/" + safe_name) as f:
        return f.read()


# ── TN-2: Path.name 净化 ─────────────────────────────────────
# EXPECT: no PATH_TRAVERSAL finding
def pt_tn2(request):
    user_path = request.args.get("path")
    safe_path = Path(user_path).name
    with open("/static/" + safe_path) as f:
        return f.read()


# ── TN-3: send_from_directory（指定目录限制） ──────────────────
# EXPECT: no PATH_TRAVERSAL finding (send_from_directory 自带路径限制)
def pt_tn3(request):
    filename = request.args.get("filename")
    return send_from_directory("/safe/dir/", filename)


# ── PROP-1: 变量传播后路径操作 ───────────────────────────────
# EXPECT: PATH_TRAVERSAL, line 66
def pt_prop1(request):
    raw = request.GET.get("dir")
    subdir = raw.strip()
    full = os.path.join("/uploads", subdir)
    return send_file(full)


# ── PROP-2: 赋值链传播 ──────────────────────────────────────
# EXPECT: PATH_TRAVERSAL, line 74
def pt_prop2(request):
    name = request.args.get("name")
    path = "/files/" + name
    with open(path, "rb") as f:
        data = f.read()
    return data
