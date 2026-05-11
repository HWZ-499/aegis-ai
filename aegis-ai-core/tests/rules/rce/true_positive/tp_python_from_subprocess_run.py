from flask import request
from subprocess import run


def run_diagnostic():
    cmd = request.form["cmd"]
    run(cmd, shell=True)
