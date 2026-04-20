"""
FP: CLI/本地工具场景下从 PYTHONSTARTUP 读取本地脚本并 eval/compile，
输入来源为运维环境变量，不应判定为远程代码执行漏洞。
期望: 无 RCE_COMMAND_EXEC
"""

import os


def shell_command():
    ctx = {}
    startup = os.environ.get("PYTHONSTARTUP")
    if startup and os.path.isfile(startup):
        with open(startup) as f:
            eval(compile(f.read(), startup, "exec"), ctx)
