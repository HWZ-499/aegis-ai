"""
TP: subprocess.run 使用 shell=True 执行包含用户输入的命令，存在命令注入风险。
期望检测: RCE_COMMAND_EXEC (Critical/High)
"""

import subprocess
from flask import request


def run_cmd():
    cmd = request.args.get("cmd")
    # 用户可控参数直接拼接进 shell 命令
    subprocess.run("sh -c '" + cmd + "'", shell=True)

