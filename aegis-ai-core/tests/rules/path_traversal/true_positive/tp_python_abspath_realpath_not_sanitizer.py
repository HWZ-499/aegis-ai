"""
TP: os.path.abspath/realpath only resolve a path; they do not prove it stays
inside an allowed directory.
Expected: PATH_TRAVERSAL
"""

import os
from flask import request


def read_absolute_path():
    return open(os.path.abspath(request.args["path"]), "rb").read()


def read_real_path():
    return open(os.path.realpath(request.args["path"]), "rb").read()
