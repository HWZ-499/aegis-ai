# test_embedding_models.py - 测试和对比不同的 embedding 模型
"""
测试和对比不同的 sentence-transformers 模型效果
"""
import sys
sys.path.insert(0, '.')

from src.rag.local_embedding import LocalEmbedder, EmbeddingModelComparator, DEFAULT_MODEL

print("="*70)
print("🧪 Embedding 模型测试与对比")
print("="*70)

# 检查是否安装了 sentence-transformers
try:
    from sentence_transformers import SentenceTransformer
    print("\n✅ sentence-transformers 已安装")
except ImportError:
    print("\n❌ sentence-transformers 未安装")
    print("   安装命令: pip install sentence-transformers")
    print("   注意: 首次使用会自动下载模型（约 100-500 MB）")
    import pytest
    pytest.skip("sentence-transformers 未安装，跳过 embedding 模型测试", allow_module_level=True)

# 测试文本
test_texts = [
    "Fastjson 反序列化漏洞",
    "SQL 注入攻击",
    "Log4j 远程代码执行漏洞",
    "XSS 跨站脚本攻击",
    "CVE-2021-44228"
]

print(f"\n[1] 测试默认模型: {DEFAULT_MODEL}")
print("-"*70)

try:
    embedder = LocalEmbedder(DEFAULT_MODEL)
    
    if embedder.model:
        print(f"✅ 模型加载成功")
        print(f"   向量维度: {embedder.get_embedding_dimension()}")
        
        # 测试向量化
        print(f"\n[2] 测试向量化（{len(test_texts)} 个文本）...")
        embeddings = embedder.encode(test_texts, show_progress=True)
        print(f"✅ 向量化完成")
        print(f"   输出形状: {embeddings.shape}")
        print(f"   向量示例（前 10 维）: {embeddings[0][:10]}")
        
        # 测试相似度
        print(f"\n[3] 测试相似度计算...")
        from sklearn.metrics.pairwise import cosine_similarity
        
        # 计算第一个和第二个文本的相似度
        similarity = cosine_similarity([embeddings[0]], [embeddings[1]])[0][0]
        print(f"   '{test_texts[0]}' vs '{test_texts[1]}'")
        print(f"   相似度: {similarity:.4f}")
        
        # 计算所有文本之间的相似度矩阵
        print(f"\n[4] 相似度矩阵（前 3 个文本）:")
        similarity_matrix = cosine_similarity(embeddings[:3])
        for i in range(3):
            print(f"   {test_texts[i][:30]:30s}", end="")
            for j in range(3):
                print(f" {similarity_matrix[i][j]:.3f}", end="")
            print()
        
    else:
        print("❌ 模型加载失败")
        
except Exception as e:
    print(f"❌ 错误: {e}")
    import traceback
    traceback.print_exc()

# 模型对比（如果安装了多个模型）
print(f"\n[5] 模型对比（可选）")
print("-"*70)
print("💡 提示: 可以对比不同模型的效果")
print("   常用模型:")
print("   - paraphrase-multilingual-MiniLM-L12-v2 (多语言，推荐)")
print("   - all-MiniLM-L6-v2 (英文，速度快)")
print("   - distiluse-base-multilingual-cased (多语言，质量高)")

print("\n" + "="*70)
print("✅ 测试完成！")
print("="*70)
print("\n💡 使用建议:")
print("   1. 中文查询：使用 paraphrase-multilingual-MiniLM-L12-v2")
print("   2. 英文查询：使用 all-MiniLM-L6-v2（更快）")
print("   3. 高质量：使用 distiluse-base-multilingual-cased（更慢）")
