"""
FP: 纯字面量/常量查询，无用户输入，不应报 NoSQL 注入。
期望: 无 NOSQL_INJECTION
"""
from pymongo import MongoClient

db = MongoClient().mydb


def get_admins():
    return list(db.users.find({"role": "admin"}))
