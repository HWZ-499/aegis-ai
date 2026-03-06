"""
TP: pymongo find() 直接使用 request.json 作为查询条件，存在 NoSQL 注入风险。
期望检测: NOSQL_INJECTION (High)
"""
from flask import request
from pymongo import MongoClient

client = MongoClient()
db = client.mydb


def get_user():
    q = request.json
    return db.users.find_one(q)
