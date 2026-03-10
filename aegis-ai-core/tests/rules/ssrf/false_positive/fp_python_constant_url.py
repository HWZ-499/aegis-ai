# 假阳性：URL 为硬编码常量，不存在 SSRF
import requests


def fetch_api():
    # 安全：URL 为常量，不受用户控制
    response = requests.get("https://api.example.com/data")
    return response.json()
