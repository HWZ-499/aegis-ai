from flask import request
import pickle as p


def restore_session():
    return p.loads(request.data)
