# test_nvd_api.py - 测试 NVD API Key 配置
"""
快速测试 NVD API Key 是否配置正确
"""
import os
import sys

# 加载环境变量
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import requests

print("="*70)
print("🧪 NVD API Key 配置测试")
print("="*70)

# 1. 检查 API Key
api_key = os.getenv("NVD_API_KEY", "")
if not api_key:
    print("\n❌ API Key 未设置")
    print("\n💡 设置方法：")
    print("   Windows PowerShell: $env:NVD_API_KEY = 'your-key'")
    print("   Linux/Mac: export NVD_API_KEY='your-key'")
    print("   或创建 .env 文件: NVD_API_KEY=your-key")
    sys.exit(1)

print(f"\n✅ API Key 已设置（长度: {len(api_key)}）")

# 2. 测试 API 请求
print("\n[2] 测试 API 请求...")
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
headers = {"apiKey": api_key}
params = {
    "startIndex": 0,
    "resultsPerPage": 1
}

try:
    response = requests.get(url, headers=headers, params=params, timeout=10)
    
    print(f"   状态码: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        total_results = data.get('totalResults', 0)
        print(f"   ✅ API 请求成功！")
        print(f"   📊 数据库中共有 {total_results} 条 CVE 记录")
        
        if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
            cve_id = data['vulnerabilities'][0].get('cve', {}).get('id', '')
            print(f"   📝 示例 CVE: {cve_id}")
        
        print("\n" + "="*70)
        print("✅ 配置正确！可以开始使用爬虫了")
        print("="*70)
        print("\n💡 运行爬虫：")
        print("   python cve_crawler_auto.py --days 7 --max-results 10")
        
    elif response.status_code == 401:
        print(f"   ❌ 认证失败：API Key 无效")
        print(f"   💡 请检查 API Key 是否正确")
        
    elif response.status_code == 403:
        print(f"   ❌ 访问被拒绝：API Key 可能无效或已过期")
        print(f"   💡 请重新申请 API Key: https://nvd.nist.gov/developers/request-an-api-key")
        
    else:
        print(f"   ❌ 请求失败：{response.status_code}")
        print(f"   响应: {response.text[:200]}")
        
except requests.exceptions.SSLError as e:
    print(f"   ❌ SSL 错误: {e}")
    print(f"   💡 如果使用代理，请关闭代理或配置 PROXY_PORT")
    
except requests.exceptions.RequestException as e:
    print(f"   ❌ 请求失败: {e}")
    print(f"   💡 请检查网络连接")

print("\n" + "="*70)
