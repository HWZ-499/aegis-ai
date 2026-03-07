# rag_system.py - 完整的 RAG (Retrieval-Augmented Generation) 系统演示
import chromadb

print("=" * 70)
print("🚀 完整 RAG 系统演示")
print("=" * 70)

# ========== STEP 1: 连接向量数据库 ==========
print("\n[Step 1] 🔌 Retrieval - 连接向量知识库...")
client = chromadb.PersistentClient(path="./data/aegis_db")
collection = client.get_collection(name="cve_core")
print(f"✅ 连接成功，知识库中有 {collection.count()} 条记录")

# ========== STEP 2: 检索相关数据 ==========
user_question = "我想了解 fastjson 有什么安全问题"

print("\n[Step 2] 🔍 Retrieval - 检索相关数据")
print(f"📝 用户问题: {user_question}")
print("⏳ 正在搜索相关漏洞...")

search_results = collection.query(
    query_texts=[user_question],
    n_results=3,  # 检索前 3 条最相关的
)

print(f"✅ 找到 {len(search_results['ids'][0])} 条相关记录")

# ========== STEP 3: 整理检索到的上下文 ==========
print("\n[Step 3] 📋 Augmented - 整理增强上下文")

context = ""
for i, (cve_id, distance, document) in enumerate(
    zip(search_results["ids"][0], search_results["distances"][0], search_results["documents"][0]), 1
):
    relevance = 100 - (distance * 30)  # 转换为相关度百分比
    context += f"\n【信息源 {i}】(相关度: {relevance:.0f}%)\n{document}\n"

print("上下文内容：")
print("-" * 70)
print(context)
print("-" * 70)

# ========== STEP 4: 用 LLM 生成答案（这是 Generation 部分）==========
print("\n[Step 4] 🧠 Generation - LLM 生成答案")
print("⚠️  注意：这里演示了 RAG 的完整流程")
print("   (实际 LLM 调用需要 OpenAI/Claude 等 API Key)\n")

# 模拟 LLM 的回答
simulated_answer = """
根据我们的漏洞知识库，fastjson 存在以下主要安全问题：

1️⃣ **远程代码执行 (RCE)**
   - CVE-2023-50505：fastjson 的 parse 函数存在反序列化缺陷
   - 攻击者可以通过构造恶意 JSON 触发任意代码执行
   - 受影响版本：<= 1.2.80

2️⃣ **反序列化漏洞**
   - CVE-2022-21413：JdbcRowSetImpl 类处理不当
   - CVE-2021-26295：@type 属性类型绕过
   - 攻击者可以绕过安全限制进行代码执行

3️⃣ **模板注入漏洞**
   - CVE-2020-11974：VelocityTemplate 处理缺陷
   - 可能导致远程代码执行

建议：
✓ 升级到最新版本
✓ 避免在处理不受信任数据时使用自动类型检测
✓ 对用户输入进行严格验证
"""

print("🤖 AI 助手的回答：")
print("=" * 70)
print(simulated_answer)
print("=" * 70)

# ========== 总结 ==========
print("\n[完成] ✅ RAG 流程总结")
print("""
┌─────────────────────────────────────────┐
│  用户提问                                │
│  ↓                                       │
│  [RETRIEVAL] 向量搜索 ✓                  │
│  ↓                                       │
│  [AUGMENTED] 整理上下文 ✓                │
│  ↓                                       │
│  [GENERATION] LLM 生成答案 ✓             │
│  ↓                                       │
│  最终回答                                │
└─────────────────────────────────────────┘

这就是完整的 RAG 系统！
""")

print("\n💡 关键区别：")
print("-" * 70)
print("""
📌 普通向量搜索 (你现在有的)：
   用户问题 → 搜索相关数据 → 直接返回

📌 完整 RAG 系统 (我们演示的)：
   用户问题 → 搜索相关数据 → 用 LLM 理解和总结 → 返回答案
   
优势：
  ✓ 答案更自然、连贯
  ✓ 可以回答数据库中没有的问题
  ✓ 支持多条数据综合分析
  ✓ 用户体验更像与 AI 对话
""")
print("-" * 70)
