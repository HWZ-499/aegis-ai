# show_vectors.py - 展示向量和相似度的工作原理
import chromadb

client = chromadb.PersistentClient(path="./aegis_db")
collection = client.get_collection(name="cve_core")

print("="*60)
print("🔬 向量数据库工作原理演示")
print("="*60)

# 查看一条数据的元数据
results = collection.get(limit=1)
print(f"\n📊 存储在数据库中的数据示例：")
print(f"   ID: {results['ids'][0]}")
print(f"   内容: {results['documents'][0][:80]}...")
print(f"   元数据: {results['metadatas'][0]}")

print("\n" + "="*60)
print("🎯 演示多个搜索和它们的相似度匹配")
print("="*60)

test_queries = [
    ("fastjson 漏洞", "直接搜索关键词"),
    ("阿里巴巴 JSON", "搜索公司和技术"),
    ("远程代码执行", "搜索漏洞类型"),
    ("反序列化 安全", "搜索技术问题"),
    ("Python 数据分析", "搜索无关主题"),
]

for query, description in test_queries:
    print(f"\n🔍 查询: '{query}'")
    print(f"   描述: {description}")
    
    results = collection.query(
        query_texts=[query],
        n_results=2,
        include=["documents", "distances", "metadatas"]
    )
    
    for i, (cve_id, distance, doc, meta) in enumerate(zip(
        results['ids'][0],
        results['distances'][0],
        results['documents'][0],
        results['metadatas'][0]
    )):
        # 相似度：距离越小越相似
        similarity_score = (2 - distance) / 2 * 100  # 转换为百分比
        match_indicator = "🟢" if distance < 1.0 else "🟡" if distance < 1.3 else "🔴"
        
        print(f"\n   {i+1}. {match_indicator} {cve_id}")
        print(f"      相似度: {similarity_score:.1f}%")
        print(f"      距离分数: {distance:.3f}")
        summary = doc.split('\n')[1] if '\n' in doc else doc[:50]
        print(f"      匹配内容: {summary[:50]}...")

print("\n" + "="*60)
print("💡 相似度说明：")
print("   距离 < 1.0  🟢 优秀匹配")
print("   距离 1.0-1.3 🟡 良好匹配")
print("   距离 > 1.3  🔴 较弱匹配")
print("="*60)
