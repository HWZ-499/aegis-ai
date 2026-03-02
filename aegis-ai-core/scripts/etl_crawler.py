# etl_crawler_final.py - 终极修复版 (环境净化 + 修正包名)
import os
import sys

# =================================================================
# 💉 【手术刀修复区】
# 在引入 requests 之前，先强行删掉可能导致报错的环境变量！
# 这能解决 FileNotFoundError(2, 'No such file or directory')
# =================================================================
keys_to_remove = ['REQUESTS_CA_BUNDLE', 'SSL_CERT_FILE', 'CURL_CA_BUNDLE']
for key in keys_to_remove:
    if key in os.environ:
        print(f"🧹 发现干扰变量 {key}，正在清除...")
        os.environ.pop(key)

import requests
import chromadb
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =========================================================
# ⚠️ 再次确认你的端口！刚才你说 debug 成功的是 7897
# =========================================================
PROXY_PORT = 7897  
PROXIES = {
    "http": f"http://127.0.0.1:{PROXY_PORT}",
    "https": f"http://127.0.0.1:{PROXY_PORT}"
}

print("🔌 正在连接本地向量知识库...")
client = chromadb.PersistentClient(path="./aegis_db")
collection = client.get_or_create_collection(name="cve_core")

# ✅ 目标：Fastjson (全名)
TARGET_PACKAGE = "com.alibaba:fastjson"
ECOSYSTEM = "Maven"

def fetch_real_data():
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": TARGET_PACKAGE,
            "ecosystem": ECOSYSTEM
        }
    }
    
    print(f"📡 [Extract] 正在查询 {TARGET_PACKAGE} ...")
    
    try:
        # verify=False 是关键
        response = requests.post(url, json=payload, proxies=PROXIES, verify=False, timeout=20)
        
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulns", [])
            print(f"✅ 成功连通！抓取到了 {len(vulns)} 条真实数据！")
            return vulns
        else:
            print(f"❌ 状态码异常: {response.status_code}")
            return []
            
    except FileNotFoundError:
        print("❌ 依然报 FileNotFoundError？这意味着你的 Python 环境损坏了。")
        print("👉 请尝试运行: pip install --upgrade certifi")
        return []
    except Exception as e:
        print(f"❌ 其他错误: {e}")
        return []

def run_etl_pipeline():
    vuln_list = fetch_real_data()
    
    if not vuln_list:
        return

    print(f"\n⚙️ [Transform] 正在清洗 {len(vuln_list)} 条数据...")
    
    ids = []
    documents = []
    metadatas = []

    for vuln in vuln_list:
        cve_id = vuln.get("id", "UNKNOWN")
        summary = vuln.get("summary") or "无摘要"
        details = vuln.get("details", "")[:300].replace("\n", " ")
        
        embed_text = f"漏洞ID: {cve_id}; 摘要: {summary}; 详情: {details}"
        
        ids.append(cve_id)
        documents.append(embed_text)
        metadatas.append({"source": "Google_OSV_Live", "package": TARGET_PACKAGE})
        
        print(f"   -> 捕获: {cve_id}")

    print(f"\n💾 [Load] 正在注入硬盘...")
    collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
    print(f"🎉 成功！Aegis 知识库已新增 {len(ids)} 条数据！")

if __name__ == "__main__":
    run_etl_pipeline()