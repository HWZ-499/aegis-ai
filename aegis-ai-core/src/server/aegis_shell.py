# aegis_shell.py - 最终分流版 (DeepSeek 直连 + 证书修复)
import os
import sys
import certifi 

_current_file = os.path.abspath(__file__)
_current_dir = os.path.dirname(_current_file)  # src/server
_project_root = os.path.dirname(os.path.dirname(_current_dir))  # aegis-ai-core (向上两级)

# =================================================================
# 1. 证书修复 (保留，防止 FileNotFoundError)
# =================================================================
valid_cert_path = certifi.where()
os.environ["REQUESTS_CA_BUNDLE"] = valid_cert_path
os.environ["SSL_CERT_FILE"] = valid_cert_path

# =================================================================
# 2. 🔑 加载环境变量（支持 .env 文件）
# =================================================================
try:
    from dotenv import load_dotenv

    # 尝试从当前目录或父目录加载 .env 文件
    load_dotenv()
    load_dotenv(os.path.join(_project_root, ".env"))
except ImportError:
    # 如果没有安装 python-dotenv，只使用系统环境变量
    pass

import httpx
import chromadb
import json
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =================================================================
# 🔑 配置区（API Key 必须通过环境变量或 .env 文件设置，禁止硬编码）
# =================================================================
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
API_URL = os.getenv("DEEPSEEK_API_URL", "https://api.deepseek.com/chat/completions")

print("\n🔌 [System] 正在挂载本地向量数据库...")
client = chromadb.PersistentClient(path="./data/aegis_db")
collection = client.get_collection(name="cve_core")

def ask_deepseek_rag(user_query, context_text):
    if not DEEPSEEK_API_KEY or "sk-xxxx" in (DEEPSEEK_API_KEY or ""):
        print("❌ [Error] 请设置环境变量 DEEPSEEK_API_KEY")
        return

    # ☢️ 核心修改：升级 System Prompt (提示词工程)
    # 我们教 AI 学会“判断上下文相关性”
    system_prompt = """你是一个高级安全专家，也是一个有情商的助手。
    
    你的任务流程如下：
    1. 用户会提出问题。
    2. 系统会自动提供一些【参考资料】（可能相关，也可能完全不相关）。
    3. 请先判断：【参考资料】是否真的能回答【用户问题】？
       - 如果能回答：请基于资料，用专业黑客风格回答。
       - 如果资料不相关（例如用户在问好，资料却是漏洞）：请忽略资料，直接用礼貌、幽默的方式回应用户（例如："收到，这里是 Aegis 终端，请下达指令。"）。
       - 绝不要强行把"你好"和"Fastjson漏洞"扯在一起！
    """

    user_message = f"""
    【参考资料】:
    {context_text}

    【用户问题】:
    {user_query}
    """

    print("   🤖 [DeepSeek] 正在进行二次语义校验...", end="", flush=True)
    
    try:
        with httpx.Client(
            timeout=30.0,
            verify=valid_cert_path,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            resp = client.post(
                API_URL,
                json={
                    "model": "deepseek-chat",
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message},
                    ],
                    "stream": False,
                },
                headers={"Authorization": f"Bearer {DEEPSEEK_API_KEY}"},
            )

        print(" ✅")
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"]
        return f"❌ API 报错: {resp.status_code}"

    except httpx.HTTPError as e:
        return f"❌ 网络错误: {e}"

# 1. 新增一个“纯聊天”函数 (放在 ask_deepseek_rag 后面)
def ask_deepseek_pure_chat(user_query):
    print("   🤖 [DeepSeek] 数据库无相关资料，切换为【纯聊天模式】...", end="", flush=True)
    
    # 这里不需要 system_prompt 那么复杂，就让它自由发挥
    pure_prompt = "你是一个黑客风格的AI助手。用户在跟你闲聊，请用简练、酷酷的语气回应。"
    
    try:
        with httpx.Client(
            timeout=30.0,
            verify=valid_cert_path,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            resp = client.post(
                API_URL,
                json={
                    "model": "deepseek-chat",
                    "messages": [
                        {"role": "system", "content": pure_prompt},
                        {"role": "user", "content": user_query},
                    ],
                    "stream": False,
                },
                headers={"Authorization": f"Bearer {DEEPSEEK_API_KEY}"},
            )
        print(" ✅")
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"]
    except httpx.HTTPError as e:
        return f"❌ 网络错误: {e}"

print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print(f"🛡️  Aegis-AI RAG Terminal (Direct Mode)")
print(f"📂  本地情报库: {collection.count()} 条")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

while True:
    try:
        user_query = input("\n🕵️  Human > ").strip()
        if not user_query: continue
        if user_query.lower() in ['exit', 'quit']: break

        print(f"   🔍 优化的 RAG 检索（Top-5 → 重排序 → Top-3）...")
        
        # === 🔥 使用优化的 RAG 检索流程 ===
        from rag_optimizer import optimized_rag_retrieval
        
        rag_result = optimized_rag_retrieval(
            collection=collection,
            query=user_query,
            top_k=5,  # 初始检索 5 条
            return_top_n=3  # 返回前 3 条
        )
        
        distance = rag_result['distance']
        print(f"   📏 [最佳距离] {distance:.4f}")
        print(f"   📊 [候选数] {rag_result['total_candidates']}, [返回数] {len(rag_result['ranked_results'])}")

        if rag_result['has_match']:
            # 情况 A: 搜到了专业资料 -> 专家模式（RAG）
            print(f"   ✅ [HIT] 命中情报，使用 RAG 模式")
            if rag_result['ranked_results']:
                print(f"   📋 使用 {len(rag_result['ranked_results'])} 条相关参考")
                for i, (candidate, score) in enumerate(rag_result['ranked_results'], 1):
                    print(f"      [{i}] {candidate['id']} (相关度: {score:.2f})")
            
            # 使用融合后的上下文
            answer = ask_deepseek_rag(user_query, rag_result['context'])
        else:
            # 情况 B: 搜到了但距离太远 -> 兜底陪聊模式
            print(f"   ⚠️ [MISS] 距离过远，判断为闲聊模式")
            answer = ask_deepseek_pure_chat(user_query)

        print("\n🤖 Aegis 回复:")
        print("────────────────────────────────────────")
        print(answer)
        print("────────────────────────────────────────")

    except KeyboardInterrupt:
        break
    except Exception as e:
        print(f"Error: {e}")