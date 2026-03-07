# FP: redirect 目标为常量路径，不受用户输入控制。
from flask import Flask, redirect

app = Flask(__name__)


@app.route("/home")
def home_fp():
    return redirect("/dashboard")
