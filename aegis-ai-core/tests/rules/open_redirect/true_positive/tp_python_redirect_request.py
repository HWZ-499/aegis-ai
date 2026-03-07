# TP: 用户可控的 next 参数直接用于 redirect，存在开放重定向风险。
from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/go")
def go_tp():
    next_url = request.args.get("next", "/")
    return redirect(next_url)
