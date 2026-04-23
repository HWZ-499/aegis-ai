"""
FP: json.loads() 解析普通参数（未绑定用户输入源）不应按反序列化风险告警。
期望: 无 DESERIALIZATION
"""
import json


def parse_payload(data: str):
    return json.loads(data)
