# 真阳性：用户可控的 URL 传入 requests.post（SSRF via POST）
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch", methods=["POST"])
def fetch_resource():
    data = request.json
    webhook_url = data["callback_url"]
    # 危险：将用户提供的 webhook URL 直接用于请求
    resp = requests.post(webhook_url, json={"status": "ok"})
    return resp.text
