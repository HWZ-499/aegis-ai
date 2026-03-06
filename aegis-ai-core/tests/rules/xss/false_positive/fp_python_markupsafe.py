"""
FP: 使用 html.escape 对用户输入进行转义后再输出，不应视为 XSS 漏洞。
期望: 无 XSS_RISK
"""

import html
from flask import Flask, request

app = Flask(__name__)


@app.route("/xss_safe")
def safe_xss():
    name = request.args.get("name")
    safe_name = html.escape(name or "", quote=True)
    return f"<h1>Hello {safe_name}</h1>"

