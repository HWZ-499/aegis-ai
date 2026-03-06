# db_query.py - 工业级语义检索测试
import chromadb

print("🔍 正在连接硬盘数据库...")
# 连接刚才生成的硬盘文件
client = chromadb.PersistentClient(path="./aegis_db")
collection = client.get_collection(name="cve_core")

# ⚠️ 注意看！这段查询词里，【没有】出现 "Log4j" 这个词！
# 我们是在用极其口语化的描述，去考验 AI 的语义理解能力。
query_text = "帮我找一下那个能让服务器中招的、Java生态的远程代码执行漏洞"

print(f"🗣️ 用户提问: {query_text}")
print("🧠 正在调用模型进行特征计算与检索...\n")

# 工业级查询
results = collection.query(
    query_texts=[query_text], # 把提问丢进去
    n_results=1,              # 只拿最匹配的1条
    where={"severity": "Critical"} # 附加条件：只要"极度危险"级别的漏洞！
)

# 打印战果
print("🎯 检索结果：")
print(f"匹配到的数据 ID: {results['ids'][0][0]}")
print(f"原始漏洞描述: {results['documents'][0][0]}")
print(f"漏洞关联数据: {results['metadatas'][0][0]}")
print(f"数学空间距离: {results['distances'][0][0]} (越小代表越相似)")