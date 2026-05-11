from flask import request
from pickle import loads


def restore_session():
    return loads(request.data)
