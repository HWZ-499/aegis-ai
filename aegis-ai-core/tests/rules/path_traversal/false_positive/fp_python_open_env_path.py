"""
FP: 读取运维环境变量指定的本地文件路径（如 PYTHONSTARTUP），
不应按远程用户输入触发 PATH_TRAVERSAL。
期望: 无 PATH_TRAVERSAL
"""

import os


def load_local_startup():
    startup = os.environ.get("PYTHONSTARTUP")
    if startup:
        with open(startup, "r") as f:
            return f.read()
    return ""
