from flask import request


def search(collection):
    return collection.find({"$where": request.args["q"]})
