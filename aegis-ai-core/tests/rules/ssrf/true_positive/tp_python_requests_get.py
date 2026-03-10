# 真阳性：用户可控的 URL 直接传入 requests.get（SSRF）
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/proxy")
def proxy():
    target_url = request.args.get("url")
    # 危险：直接将用户输入作为 HTTP 请求目标
    response = requests.get(target_url)
    return response.text
