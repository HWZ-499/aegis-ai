"""
FP: 从环境变量读取密码，不属于硬编码凭证。
期望: 无 HARDCODED_CREDENTIALS
"""

import os


def load_password():
    password = os.environ.get("DB_PASSWORD")
    return password
