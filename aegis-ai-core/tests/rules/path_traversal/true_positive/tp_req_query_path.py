"""
TP: 直接用 request.args.get('path') 读取文件，未净化。
期望检测: PATH_TRAVERSAL (High/Critical)
"""
import os
from flask import request, send_file


def get_file():
    file_path = request.args.get("path")
    return open(os.path.join("/var/www", file_path), "rb").read()
