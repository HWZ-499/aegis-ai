"""
Python RCE / 命令执行合成测试用例
规则: TP（直接执行）/ TN（净化）/ 传播污点
"""
import os
import subprocess
import shlex


# ── TP-1: os.system 直接注入 ──────────────────────────────────
# EXPECT: RCE_COMMAND_EXEC, line 13
def rce_tp1(request):
    cmd = request.GET.get("host")
    os.system("ping " + cmd)


# ── TP-2: subprocess.call 注入 ────────────────────────────────
# EXPECT: RCE_COMMAND_EXEC, line 20
def rce_tp2(request):
    args = request.POST.get("args")
    subprocess.call("ls " + args, shell=True)


# ── TP-3: eval() 用户输入 ────────────────────────────────────
# EXPECT: RCE_COMMAND_EXEC, line 27
def rce_tp3(request):
    code = request.GET.get("expr")
    eval(code)


# ── TN-1: shlex.quote 净化 ────────────────────────────────────
# EXPECT: no RCE finding
def rce_tn1(request):
    host = request.GET.get("host")
    safe_host = shlex.quote(host)
    os.system("ping " + safe_host)


# ── TN-2: subprocess 列表模式（无 shell=True） ─────────────────
# EXPECT: no RCE finding (列表参数不经 shell 解析)
def rce_tn2(request):
    host = request.GET.get("host")
    subprocess.run(["ping", host])


# ── TN-3: 白名单验证 ─────────────────────────────────────────
# EXPECT: no RCE finding
_ALLOWED_CMDS = {"ls", "pwd", "whoami"}

def rce_tn3(request):
    cmd = request.GET.get("cmd")
    if cmd not in _ALLOWED_CMDS:
        return
    subprocess.run([cmd])


# ── PROP-1: 变量传播后执行 ────────────────────────────────────
# EXPECT: RCE_COMMAND_EXEC, line 57
def rce_prop1(request):
    raw = request.args.get("cmd")
    sanitized = raw.strip()         # strip 不净化 RCE
    full_cmd = "bash -c '" + sanitized + "'"
    os.system(full_cmd)


# ── PROP-2: exec() 传播 ───────────────────────────────────────
# EXPECT: RCE_COMMAND_EXEC, line 65
def rce_prop2(request):
    payload = request.POST.get("payload")
    code = compile(payload, "<string>", "exec")
    exec(code)
