from flask import request


def find_user(collection):
    return collection.find_one({"name": request.json["name"]})
