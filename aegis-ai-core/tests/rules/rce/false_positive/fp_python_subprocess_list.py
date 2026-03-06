"""
FP: subprocess.run 使用参数列表且不依赖用户输入，为安全用法。
期望: 无 RCE_COMMAND_EXEC
"""

import subprocess


def safe_ls():
    # 常量命令 + 参数列表，shell=False（默认）
    subprocess.run(["ls", "-la"])

