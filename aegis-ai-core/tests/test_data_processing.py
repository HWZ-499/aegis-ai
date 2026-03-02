# test_data_processing.py - 测试数据清洗和结构化流程
"""
演示 CVE 数据清洗和结构化的完整流程
"""
import os
import sys
import json

# 添加项目根目录到 Python 路径
_current_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_current_dir)  # aegis-ai-core
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from src.crawler.cve_crawler_auto import CVECrawler

print("="*70)
print("🧪 CVE 数据清洗与结构化流程演示")
print("="*70)

# 创建爬虫实例（不连接数据库，只测试数据处理）
crawler = CVECrawler()

# 模拟 API 2.0 原始数据
sample_raw_data = {
    "id": "CVE-2021-44228",
    "descriptions": [
        {
            "lang": "en",
            "value": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled."
        },
        {
            "lang": "es",
            "value": "Apache Log4j2 vulnerabilidad..."
        }
    ],
    "metrics": {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "baseSeverity": "CRITICAL",
                    "baseScore": 10.0,
                    "attackVector": "NETWORK",
                    "attackComplexity": "LOW",
                    "privilegesRequired": "NONE",
                    "userInteraction": "NONE",
                    "scope": "UNCHANGED",
                    "confidentialityImpact": "HIGH",
                    "integrityImpact": "HIGH",
                    "availabilityImpact": "HIGH"
                }
            }
        ]
    },
    "published": "2021-12-10T00:00:00.000Z",
    "weaknesses": [
        {
            "source": "nvd@nist.gov",
            "type": "Primary",
            "description": [
                {
                    "lang": "en",
                    "value": "CWE-502"
                },
                {
                    "lang": "en",
                    "value": "CWE-74"
                }
            ]
        }
    ]
}

print("\n[1] 原始数据（API 2.0 格式）")
print("-"*70)
print(json.dumps(sample_raw_data, indent=2, ensure_ascii=False)[:500])
print("...")

# 步骤 1：解析和清洗
print("\n[2] 步骤 1：解析和清洗 (parse_cve_data)")
print("-"*70)
structured_data = crawler.parse_cve_data(sample_raw_data)

if structured_data:
    print("✅ 解析成功！")
    print("\n结构化后的数据：")
    print(json.dumps(structured_data, indent=2, ensure_ascii=False))
    
    print("\n📊 提取的关键字段：")
    print(f"   CVE ID: {structured_data['id']}")
    print(f"   描述长度: {len(structured_data['description'])} 字符")
    print(f"   严重程度: {structured_data['severity']}")
    print(f"   CVSS 分数: {structured_data['cvss_score']}")
    print(f"   发布日期: {structured_data['published']}")
    print(f"   CWE IDs: {structured_data['cwe_ids']}")
else:
    print("❌ 解析失败")

# 步骤 2：格式化文档
print("\n[3] 步骤 2：格式化文档 (format_document)")
print("-"*70)
if structured_data:
    document = crawler.format_document(structured_data)
    print("✅ 格式化成功！")
    print("\n格式化后的文档字符串：")
    print("-"*70)
    print(document)
    print("-"*70)
    print(f"\n文档长度: {len(document)} 字符")

# 步骤 3：元数据准备
print("\n[4] 步骤 3：元数据准备（用于数据库存储）")
print("-"*70)
if structured_data:
    metadata = {
        'severity': structured_data['severity'],
        'cvss_score': str(structured_data['cvss_score']),
        'published': structured_data['published'],
        'cwe_ids': ','.join(structured_data['cwe_ids']),
        'source': 'NVD_API',
        'crawled_at': '2026-02-03T16:55:55'
    }
    print("✅ 元数据准备完成！")
    print("\n元数据：")
    print(json.dumps(metadata, indent=2, ensure_ascii=False))

# 总结
print("\n" + "="*70)
print("📋 数据流程总结")
print("="*70)
print("""
原始数据 (JSON)
    ↓ parse_cve_data()
结构化数据 (Dict)
    - id: CVE-2021-44228
    - description: Apache Log4j2...
    - severity: CRITICAL
    - cvss_score: 10.0
    - cwe_ids: ['CWE-502', 'CWE-74']
    ↓ format_document()
文档字符串 (String)
    - "漏洞编号: CVE-2021-44228; 摘要: ...; 严重程度: CRITICAL; ..."
    ↓ ChromaDB 向量化
向量数据库
    - 文档：用于检索
    - 元数据：用于过滤和排序
""")

print("\n" + "="*70)
print("✅ 演示完成！")
print("="*70)
