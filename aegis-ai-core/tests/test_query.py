# test_query.py - 向量数据库查询演示
import chromadb

print("🔍 连接向量数据库并查询已存储的漏洞...")
client = chromadb.PersistentClient(path="./aegis_db")
collection = client.get_or_create_collection(name="cve_core")

# 查看数据库中有多少条数据
count = collection.count()
print(f"\n📊 数据库中共有 {count} 条漏洞记录\n")

# 演示 1: 查看所有数据
print("=" * 60)
print("演示 1: 查看所有存储的漏洞")
print("=" * 60)
results = collection.get()
for cve_id, doc in zip(results["ids"], results["documents"]):
    print(f"\n🔴 {cve_id}")
    print(f"   内容: {doc[:100]}...")

# 演示 2: 向量语义搜索
print("\n" + "=" * 60)
print("演示 2: 向量语义搜索（AI 理解内容）")
print("=" * 60)

search_queries = ["远程代码执行漏洞", "反序列化问题", "JSON 解析缺陷"]

for query in search_queries:
    print(f"\n🔍 搜索: '{query}'")
    results = collection.query(
        query_texts=[query],
        n_results=2,  # 返回最相关的 2 条
    )

    if results["ids"] and results["ids"][0]:
        for cve_id, distance, document in zip(results["ids"][0], results["distances"][0], results["documents"][0]):
            print(f"   ✓ {cve_id} (相似度: {distance:.3f})")
            # 提取摘要，处理多种文档格式
            lines = document.split("\n")
            summary = lines[1] if len(lines) > 1 else lines[0]
            print(f"     内容: {summary[:60]}...")
    else:
        print("   (无结果)")

print("\n" + "=" * 60)
print("✅ 查询演示完成！")
print("=" * 60)
