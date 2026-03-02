"""
FP: json.loads 解析数据 — 不存在反序列化 RCE 风险。
期望: 无 DESERIALIZATION
"""
import json
from flask import request


def parse_data():
    raw = request.get_data(as_text=True)
    return json.loads(raw)
