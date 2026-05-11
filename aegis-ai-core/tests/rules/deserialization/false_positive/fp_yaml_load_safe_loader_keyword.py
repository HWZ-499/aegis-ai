from flask import request
import yaml


def parse_config():
    return yaml.load(request.data, Loader=yaml.SafeLoader)
