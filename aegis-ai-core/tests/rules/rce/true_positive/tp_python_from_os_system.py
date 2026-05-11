from flask import request
from os import system


def run_diagnostic():
    cmd = request.args["cmd"]
    system(cmd)
