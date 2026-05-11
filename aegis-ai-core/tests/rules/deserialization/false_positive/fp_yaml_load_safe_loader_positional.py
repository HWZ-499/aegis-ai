from flask import request
from yaml import SafeLoader, load


def parse_config():
    return load(request.data, SafeLoader)
