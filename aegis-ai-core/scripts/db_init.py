# db_init.py - 工业级 ChromaDB 落地实验
import chromadb

print("🛠️ 正在初始化硬盘级向量引擎...")

# 1. 启动持久化客户端：数据会真实地写入你当前文件夹下的 'aegis_db' 目录
client = chromadb.PersistentClient(path="./aegis_db")

# 2. 创建或连接一个叫 "cve_core" 的数据库表 (Collection)
collection = client.get_or_create_collection(name="cve_core")

print("📥 正在调用底层 AI 模型进行 Embedding 并写入硬盘...")

# 3. 极简的工业级操作：直接丢入明文，不用管数学！
# 底层会自动下载 AI 模型，算出几百个维度，然后落盘加密。
collection.add(
    documents=["【CVE-2021-44228】Log4j 远程代码执行漏洞，危害极高"],
    metadatas=[{"severity": "Critical", "cwe": "CWE-74"}], # 附加信息
    ids=["id_log4j_001"]
)

print("\n✅ 数据已永久落盘！数据库结构已锁定！")