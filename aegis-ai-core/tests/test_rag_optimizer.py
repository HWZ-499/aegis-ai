# test_rag_optimizer.py - 测试优化的 RAG 检索流程
"""
测试新的 RAG 优化功能：
1. 多轮检索
2. 重排序
3. 上下文融合
"""
import sys
sys.path.insert(0, '.')

import chromadb
from src.rag.rag_optimizer import optimized_rag_retrieval, keyword_match_score, severity_score, freshness_score

print("="*70)
print("🧪 优化的 RAG 检索流程测试")
print("="*70)

# 连接数据库
print("\n[1] 连接向量数据库...")
client = chromadb.PersistentClient(path="./data/aegis_db")
collection = client.get_collection(name="cve_core")
print(f"✅ 连接成功，知识库中有 {collection.count()} 条记录")

# 测试查询
test_queries = [
    "Fastjson 有什么安全问题",
    "SQL 注入漏洞",
    "Log4j 漏洞",
]

print("\n[2] 测试优化的 RAG 检索...")
for i, query in enumerate(test_queries, 1):
    print(f"\n{'='*70}")
    print(f"测试 {i}: {query}")
    print(f"{'='*70}")
    
    # 使用优化的 RAG 检索
    result = optimized_rag_retrieval(
        collection=collection,
        query=query,
        top_k=5,
        return_top_n=3
    )
    
    print(f"\n📊 检索结果：")
    print(f"   最佳距离: {result['distance']:.4f}")
    print(f"   是否有匹配: {result['has_match']}")
    print(f"   候选数量: {result['total_candidates']}")
    print(f"   返回数量: {len(result['ranked_results'])}")
    
    if result['ranked_results']:
        print(f"\n📋 排序后的结果（带分数）：")
        for j, (candidate, score) in enumerate(result['ranked_results'], 1):
            print(f"   [{j}] {candidate['id']}")
            print(f"       相关度分数: {score:.3f}")
            print(f"       向量距离: {candidate['distance']:.4f}")
            print(f"       文档长度: {len(candidate['document'])} 字符")
    
    if result['context']:
        print(f"\n📄 融合后的上下文（前 300 字符）：")
        print(result['context'][:300])
        print("...")

print("\n" + "="*70)
print("✅ 测试完成！")
print("="*70)

# 测试辅助函数
print("\n[3] 测试辅助函数...")

# 测试关键词匹配
print("\n📝 关键词匹配测试：")
test_cases = [
    ("fastjson 漏洞", "Fastjson 是一个 Java JSON 库，存在反序列化漏洞"),
    ("SQL 注入", "SQL 注入是一种常见的 Web 安全漏洞"),
    ("不相关查询", "这是一个完全不相关的内容"),
]

for query, doc in test_cases:
    score = keyword_match_score(query, doc)
    print(f"   查询: '{query}'")
    print(f"   文档: '{doc[:50]}...'")
    print(f"   匹配分数: {score:.3f}")

# 测试严重程度
print("\n📊 CVE 严重程度测试：")
cve_ids = ["CVE-2021-44228", "CVE-2017-5638", "CVE-2014-0160"]
for cve_id in cve_ids:
    score = severity_score(cve_id)
    print(f"   {cve_id}: {score:.3f}")

# 测试新鲜度
print("\n📅 时间新鲜度测试：")
dates = ["2024-01-01", "2020-01-01", "2015-01-01", None]
for date in dates:
    score = freshness_score(date)
    print(f"   {date}: {score:.3f}")

print("\n" + "="*70)
print("✅ 所有测试完成！")
print("="*70)
