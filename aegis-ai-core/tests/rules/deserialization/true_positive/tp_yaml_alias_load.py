from flask import request
import yaml as y


def parse_config():
    return y.load(request.data)
