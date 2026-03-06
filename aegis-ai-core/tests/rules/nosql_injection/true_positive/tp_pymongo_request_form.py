"""
TP: pymongo find() 使用 request.form 构造的查询，存在 NoSQL 注入风险。
期望检测: NOSQL_INJECTION (High)
"""
from flask import request
from pymongo import MongoClient

db = MongoClient().mydb


def search():
    query = {"name": request.form.get("name")}
    return list(db.users.find(query))
