from flask import request
import subprocess as sp


def run_diagnostic():
    cmd = request.args["cmd"]
    sp.run(cmd, shell=True)
