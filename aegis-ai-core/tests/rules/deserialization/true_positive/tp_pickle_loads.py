"""
TP: pickle.loads() 直接对 request.data 反序列化，存在 RCE 漏洞。
期望检测: DESERIALIZATION (Critical)
"""
import pickle
from flask import request


def load_session():
    return pickle.loads(request.data)
