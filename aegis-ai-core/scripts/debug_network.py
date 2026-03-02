# debug_network.py - 网络连通性终极诊断
import requests
import urllib3

# 禁用烦人的 SSL 警告 (因为我们要强制忽略证书验证)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================================================
# ⚠️ 这里的端口必须和你软件上显示的一模一样！
# 如果你是 v2rayN，这里通常要改成 10809
# ==================================================
PROXY_PORT = 7897

proxies = {
    "http": f"http://127.0.0.1:{PROXY_PORT}",
    "https": f"http://127.0.0.1:{PROXY_PORT}" #哪怕是https请求，代理协议通常也走http
}

target_url = "https://www.google.com" # 最好的测试标靶

print(f"🩺 开始网络诊断...")
print(f"🔌 尝试使用的代理端口: {PROXY_PORT}")
print(f"🎯 目标测试地址: {target_url}")

try:
    print("\n⏳ 发起请求中 (timeout=5s)...")
    
    # 核心魔法：verify=False (忽略证书报错)
    resp = requests.get(target_url, proxies=proxies, timeout=5, verify=False)
    
    print("-" * 30)
    if resp.status_code == 200:
        print(f"✅✅✅ 成功连通！状态码: {resp.status_code}")
        print("🎉 恭喜！你的 Python 已经彻底打通了 Google 的网络！")
        print("👉 现在你可以放心地去运行 etl_crawler.py 了 (记得加上 verify=False)")
    else:
        print(f"⚠️ 连上了，但 Google 返回了异常状态码: {resp.status_code}")

except requests.exceptions.ProxyError:
    print("❌ [错误类型：ProxyError]")
    print("原因：Python 找不到你的代理软件。")
    print("解决方案：")
    print(f"1. 确认你的代理软件开没开？")
    print(f"2. 确认你的端口真的是 {PROXY_PORT} 吗？去软件设置里看一眼！")

except requests.exceptions.SSLError:
    print("❌ [错误类型：SSLError]")
    print("原因：SSL 证书握手失败。")
    print("解决方案：代码里必须加上 verify=False 参数！")

except requests.exceptions.ConnectTimeout:
    print("❌ [错误类型：Timeout]")
    print("原因：连接超时。")
    print("解决方案：你的节点可能太慢了，或者节点本身就是挂的。换个节点试试。")

except Exception as e:
    print(f"❌ [未知错误]: {e}")