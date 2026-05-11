"""
TP: Flask send_from_directory(directory, path) takes the user-controlled
filename/path as the second positional argument.
Expected: PATH_TRAVERSAL
"""

from flask import request, send_from_directory


UPLOAD_DIR = "/srv/uploads"


def download_upload():
    return send_from_directory(UPLOAD_DIR, request.args["file"])
