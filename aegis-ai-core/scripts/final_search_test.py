# final_search_test.py - 验收时刻
import chromadb

print("🔌 连接大脑...")
# 连接刚才存入数据的那个数据库
client = chromadb.PersistentClient(path="./aegis_db")
collection = client.get_collection(name="cve_core")

# 打印一下现在库里总共有多少条数据
count = collection.count()
print(f"📊 当前知识库拥有真实情报数: {count} 条")

# =========================================================
# 🗣️ 你的提问 (注意：我故意没写 Fastjson 这个词)
# =========================================================
query = "帮我找一下那个阿里巴巴出的、和JSON解析有关的严重漏洞"

print(f"\n❓ 用户提问: {query}")
print("🧠 AI 正在进行向量语义检索...")

results = collection.query(
    query_texts=[query],
    n_results=1 # 只拿最匹配的那条
)

print("\n✅ 检索成功！AI 找到了这条情报：")
print("-" * 40)
print(f"🆔 漏洞ID: {results['ids'][0][0]}")
print(f"📦 来源: {results['metadatas'][0][0]}")
print(f"📄 内容摘要: {results['documents'][0][0]}")
print("-" * 40)