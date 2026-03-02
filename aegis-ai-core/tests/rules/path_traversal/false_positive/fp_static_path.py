"""
FP: 读取静态文件路径，不含用户输入。
期望: 无 PATH_TRAVERSAL
"""
import os


def get_config():
    with open(os.path.join(os.path.dirname(__file__), "config.json"), "r") as f:
        return f.read()
