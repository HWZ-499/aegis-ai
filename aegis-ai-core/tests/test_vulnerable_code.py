# test_vulnerable_code.py - 用于测试 AST 规则引擎的漏洞代码
"""
这个文件包含多种安全漏洞，用于测试 AST 规则引擎的检测能力。
"""

import os
import subprocess
import pickle
import json

# ===== 1. 代码注入漏洞 =====
user_input = input("Enter code: ")
eval(user_input)  # 应该被检测到：Code Injection
exec(user_input)  # 应该被检测到：Code Injection

# ===== 2. 命令注入漏洞 =====
command = input("Enter command: ")
os.system(command)  # 应该被检测到：Command Injection
subprocess.call(command, shell=True)  # 应该被检测到：Command Injection

# ===== 3. SQL 注入漏洞 =====
user_id = input("Enter user ID: ")
query = "SELECT * FROM users WHERE id = " + user_id  # 应该被检测到：SQL Injection Risk
execute(query)

# ===== 4. XSS 风险 =====
user_comment = input("Enter comment: ")
print(user_comment)  # 应该被检测到：XSS Risk（未转义输出）

# ===== 5. 硬编码凭证 =====
password = "admin123"  # 应该被检测到：Hardcoded Credentials
api_key = "sk-1234567890abcdef"  # 应该被检测到：Hardcoded Credentials
secret_token = "my_secret_token_123"  # 应该被检测到：Hardcoded Credentials

# ===== 6. 路径遍历风险 =====
filename = input("Enter filename: ")
with open(filename, 'r') as f:  # 应该被检测到：Path Traversal Risk
    content = f.read()

# ===== 7. 反序列化风险 =====
data = input("Enter serialized data: ")
obj = pickle.loads(data)  # 应该被检测到：Deserialization Risk
user_data = json.loads(data)  # 应该被检测到：Deserialization Risk（如果 data 是用户输入）

# ===== 8. 不安全的库 =====
import telnetlib  # 应该被检测到：Insecure Library
import md5  # 应该被检测到：Insecure Library

# ===== 9. 弱加密算法 =====
import hashlib
hash_value = hashlib.md5("password".encode()).hexdigest()  # 应该被检测到：Weak Cryptography
hash_value2 = hashlib.sha1("password".encode()).hexdigest()  # 应该被检测到：Weak Cryptography

# ===== 10. 调试代码 =====
if __debug__:
    print("Debug mode")  # 应该被检测到：Debug Code

DEBUG = True
if DEBUG:
    print("Debug info")  # 应该被检测到：Debug Code
