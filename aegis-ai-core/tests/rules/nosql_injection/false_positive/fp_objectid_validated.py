"""
FP: 使用 bson.ObjectId 净化用户输入后再查询，不应报 NoSQL 注入。
期望: 无 NOSQL_INJECTION
"""
from bson import ObjectId
from flask import request
from pymongo import MongoClient

db = MongoClient().mydb


def get_by_id():
    uid = request.args.get("id")
    oid = ObjectId(uid)
    return db.users.find_one({"_id": oid})
