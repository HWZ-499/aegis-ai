# 🔧 CVE 数据清洗与结构化实现详解

## 📋 概述

CVE 数据从 NVD API 获取后，需要经过**清洗**和**结构化**处理，才能存入向量数据库。这个过程包括：

1. **数据解析**：从 API 原始 JSON 中提取关键字段
2. **数据清洗**：处理缺失值、格式统一、数据验证
3. **结构化**：转换为统一的格式
4. **格式化**：转换为适合向量化的文档字符串

---

## 🔍 数据流程

```
NVD API 原始数据 (JSON)
    ↓
【步骤 1】parse_cve_data() - 解析和清洗
    ↓
结构化数据 (Dict)
    ↓
【步骤 2】format_document() - 格式化
    ↓
文档字符串 (String)
    ↓
【步骤 3】向量化 (ChromaDB 自动)
    ↓
存入向量数据库
```

---

## 📊 步骤 1：数据解析与清洗 (`parse_cve_data`)

### 1.1 原始数据结构

**NVD API 2.0 返回的原始数据**（简化示例）：
```json
{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2021-44228",
        "descriptions": [
          {
            "lang": "en",
            "value": "Apache Log4j2 2.0-beta9 through 2.15.0..."
          }
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "cvssData": {
                "baseSeverity": "CRITICAL",
                "baseScore": 10.0
              }
            }
          ]
        },
        "published": "2021-12-10T00:00:00.000Z",
        "weaknesses": [
          {
            "description": [
              {
                "lang": "en",
                "value": "CWE-502"
              }
            ]
          }
        ]
      }
    }
  ]
}
```

### 1.2 解析过程

#### 步骤 A：识别 API 版本

```python
# 判断是 API 2.0 还是 1.0（格式不同）
if 'id' in cve_item:
    # API 2.0 格式
    cve_id = cve_item.get('id', '')
    descriptions = cve_item.get('descriptions', [])
    metrics = cve_item.get('metrics', {})
    published = cve_item.get('published', '')
    weaknesses = cve_item.get('weaknesses', [])
else:
    # API 1.0 格式（兼容旧版本）
    cve_id = cve_item.get('CVE_data_meta', {}).get('ID', '')
    descriptions = cve_item.get('description', {}).get('description_data', [])
    # ...
```

**技术要点**：
- 支持两种 API 版本的格式
- 通过字段名判断版本（`id` vs `CVE_data_meta`）

---

#### 步骤 B：提取描述（清洗）

```python
# 获取英文描述
description = ""
for desc in descriptions:
    if desc.get('lang') == 'en' or desc.get('lang') == 'en-US':
        description = desc.get('value', '') or desc.get('description', '')
        break
```

**清洗逻辑**：
- ✅ 优先选择英文描述（`lang == 'en'`）
- ✅ 处理缺失值（`or desc.get('description', '')`）
- ✅ 如果找不到英文，返回空字符串

**示例**：
```python
# 输入：多个语言的描述
descriptions = [
    {"lang": "es", "value": "Vulnerabilidad..."},
    {"lang": "en", "value": "Apache Log4j2 vulnerability..."},
    {"lang": "fr", "value": "Vulnérabilité..."}
]

# 输出：只取英文
description = "Apache Log4j2 vulnerability..."
```

---

#### 步骤 C：提取严重程度和 CVSS 分数（结构化）

```python
severity = "Unknown"
cvss_score = 0.0

# 优先级：CVSS v3.1 > CVSS v3.0 > CVSS v2.0
if 'cvssMetricV31' in metrics:
    cvss_data = metrics['cvssMetricV31'][0]
    severity = cvss_data.get('cvssData', {}).get('baseSeverity', 'Unknown')
    cvss_score = cvss_data.get('cvssData', {}).get('baseScore', 0.0)
elif 'cvssMetricV2' in metrics:
    cvss_data = metrics['cvssMetricV2'][0]
    severity = cvss_data.get('baseSeverity', 'Unknown')
    cvss_score = cvss_data.get('cvssData', {}).get('baseScore', 0.0)
```

**清洗逻辑**：
- ✅ 优先级：v3.1 > v3.0 > v2.0（新版本更准确）
- ✅ 默认值：`severity = "Unknown"`, `cvss_score = 0.0`（处理缺失）
- ✅ 统一格式：`CRITICAL` → `Critical`（API 1.0 需要转换）

**示例**：
```python
# 输入：API 2.0 格式
metrics = {
    "cvssMetricV31": [{
        "cvssData": {
            "baseSeverity": "CRITICAL",
            "baseScore": 10.0
        }
    }]
}

# 输出：结构化数据
severity = "CRITICAL"  # 或转换为 "Critical"
cvss_score = 10.0
```

---

#### 步骤 D：提取 CWE ID（清洗和验证）

```python
cwe_ids = []
if weaknesses:
    # API 2.0 格式
    if isinstance(weaknesses, list) and len(weaknesses) > 0:
        for weakness in weaknesses[0].get('description', []):
            if weakness.get('lang') == 'en':
                cwe_id = weakness.get('value', '')
                if cwe_id.startswith('CWE-'):  # 验证格式
                    cwe_ids.append(cwe_id)
```

**清洗逻辑**：
- ✅ 只提取英文 CWE 描述
- ✅ 验证格式：必须以 `CWE-` 开头
- ✅ 返回列表：一个 CVE 可能有多个 CWE

**示例**：
```python
# 输入：原始数据
weaknesses = [{
    "description": [
        {"lang": "en", "value": "CWE-502"},
        {"lang": "en", "value": "CWE-74"}
    ]
}]

# 输出：清洗后的列表
cwe_ids = ["CWE-502", "CWE-74"]
```

---

#### 步骤 E：返回结构化数据

```python
return {
    'id': cve_id,                    # CVE 编号
    'description': description,       # 漏洞描述
    'severity': severity,            # 严重程度
    'cvss_score': cvss_score,       # CVSS 分数
    'published': published,          # 发布日期
    'cwe_ids': cwe_ids,             # CWE 编号列表
    'raw_data': cve_item            # 保留原始数据（可选）
}
```

**结构化后的数据格式**：
```python
{
    'id': 'CVE-2021-44228',
    'description': 'Apache Log4j2 2.0-beta9 through 2.15.0...',
    'severity': 'CRITICAL',
    'cvss_score': 10.0,
    'published': '2021-12-10T00:00:00.000Z',
    'cwe_ids': ['CWE-502'],
    'raw_data': {...}  # 原始 JSON
}
```

---

## 📝 步骤 2：格式化文档 (`format_document`)

### 2.1 目的

将结构化的 CVE 数据转换为**适合向量化的文档字符串**。

### 2.2 实现

```python
def format_document(self, cve_data: Dict) -> str:
    """格式化 CVE 数据为文档字符串（用于向量化）"""
    parts = [
        f"漏洞编号: {cve_data['id']}",
        f"摘要: {cve_data['description'][:200]}",  # 截断到 200 字符
        f"严重程度: {cve_data['severity']}",
        f"CVSS 分数: {cve_data['cvss_score']}"
    ]
    
    if cve_data['cwe_ids']:
        parts.append(f"CWE: {', '.join(cve_data['cwe_ids'])}")
    
    return "; ".join(parts)
```

### 2.3 格式化后的文档示例

**输入**（结构化数据）：
```python
{
    'id': 'CVE-2021-44228',
    'description': 'Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.',
    'severity': 'CRITICAL',
    'cvss_score': 10.0,
    'cwe_ids': ['CWE-502']
}
```

**输出**（文档字符串）：
```
漏洞编号: CVE-2021-44228; 摘要: Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.; 严重程度: CRITICAL; CVSS 分数: 10.0; CWE: CWE-502
```

**技术要点**：
- ✅ 使用分号分隔字段（`; `）
- ✅ 描述截断到 200 字符（避免过长）
- ✅ 包含关键信息：ID、描述、严重程度、分数、CWE

---

## 🔄 步骤 3：数据验证与去重

### 3.1 数据验证

在 `update_database` 方法中：

```python
# 验证必需字段
if not cve_data.get('id'):
    logger.warning(f"⚠️ CVE ID 缺失，跳过")
    continue

# 验证日期格式
try:
    datetime.fromisoformat(cve_data['published'].replace('Z', '+00:00'))
except:
    logger.warning(f"⚠️ 日期格式错误: {cve_data['published']}")
```

### 3.2 增量更新（去重）

```python
# 获取现有 ID
existing_ids = set()
if incremental:
    existing_data = self.collection.get()
    existing_ids = set(existing_data.get('ids', []))

# 跳过已存在的
if incremental and cve_id in existing_ids:
    skip_count += 1
    continue
```

**去重逻辑**：
- ✅ 基于 CVE ID（唯一标识）
- ✅ 使用 `upsert` 方法（如果存在则更新，不存在则插入）

---

## 📊 完整数据流程示例

### 输入：API 原始数据

```json
{
  "cve": {
    "id": "CVE-2021-44228",
    "descriptions": [
      {"lang": "en", "value": "Apache Log4j2 vulnerability..."}
    ],
    "metrics": {
      "cvssMetricV31": [{
        "cvssData": {
          "baseSeverity": "CRITICAL",
          "baseScore": 10.0
        }
      }]
    },
    "published": "2021-12-10T00:00:00.000Z",
    "weaknesses": [{
      "description": [
        {"lang": "en", "value": "CWE-502"}
      ]
    }]
  }
}
```

### 步骤 1：解析和清洗

```python
{
    'id': 'CVE-2021-44228',
    'description': 'Apache Log4j2 vulnerability...',
    'severity': 'CRITICAL',
    'cvss_score': 10.0,
    'published': '2021-12-10T00:00:00.000Z',
    'cwe_ids': ['CWE-502']
}
```

### 步骤 2：格式化

```
漏洞编号: CVE-2021-44228; 摘要: Apache Log4j2 vulnerability...; 严重程度: CRITICAL; CVSS 分数: 10.0; CWE: CWE-502
```

### 步骤 3：存入数据库

```python
collection.upsert(
    ids=["CVE-2021-44228"],
    documents=["漏洞编号: CVE-2021-44228; 摘要: ..."],
    metadatas=[{
        'severity': 'CRITICAL',
        'cvss_score': '10.0',
        'published': '2021-12-10T00:00:00.000Z',
        'cwe_ids': 'CWE-502',
        'source': 'NVD_API',
        'crawled_at': '2026-02-03T16:55:55'
    }]
)
```

---

## 🎯 技术亮点（面试要点）

### 1. 多版本 API 兼容

**实现**：
- 自动识别 API 版本（1.0 vs 2.0）
- 统一处理不同格式的数据

**简历描述**：
> "实现了 NVD API 1.0 和 2.0 的兼容解析，自动识别 API 版本并统一处理不同格式的数据结构。"

### 2. 数据清洗与验证

**实现**：
- 处理缺失值（默认值）
- 格式验证（CWE ID 格式）
- 数据截断（描述长度限制）

**简历描述**：
> "实现了完整的数据清洗流程，包括缺失值处理、格式验证、数据截断，确保数据质量。"

### 3. 结构化数据提取

**实现**：
- 提取关键字段（ID、描述、严重程度、CVSS、CWE）
- 优先级处理（CVSS v3.1 > v3.0 > v2.0）
- 多语言处理（优先英文）

**简历描述**：
> "设计了结构化数据提取算法，从复杂的 JSON 结构中提取关键安全信息，支持多版本 CVSS 和 CWE 分类。"

### 4. 增量更新机制

**实现**：
- 基于 CVE ID 去重
- 只添加新数据，不覆盖已有数据

**简历描述**：
> "实现了增量更新机制，基于 CVE ID 去重，避免重复数据，提高更新效率。"

---

## 📝 代码位置

- **解析函数**：`cve_crawler_auto.py` → `parse_cve_data()` (第 211-301 行)
- **格式化函数**：`cve_crawler_auto.py` → `format_document()` (第 303-323 行)
- **更新函数**：`cve_crawler_auto.py` → `update_database()` (第 410-460 行)

---

## 🔍 数据质量保证

### 1. 错误处理

```python
try:
    cve_data = self.parse_cve_data(cve_item)
    if cve_data:
        all_cves.append(cve_data)
except Exception as e:
    logger.error(f"❌ 解析 CVE 数据失败: {e}")
    continue  # 跳过错误数据，继续处理其他数据
```

### 2. 数据验证

- ✅ CVE ID 格式验证
- ✅ 日期格式验证
- ✅ CVSS 分数范围验证（0-10）
- ✅ CWE ID 格式验证（`CWE-XXX`）

### 3. 默认值处理

- ✅ 缺失描述：空字符串
- ✅ 缺失严重程度：`"Unknown"`
- ✅ 缺失 CVSS 分数：`0.0`
- ✅ 缺失 CWE：空列表 `[]`

---

## 💡 优化建议（未来）

1. **数据标准化**：
   - 统一严重程度格式（`CRITICAL` → `Critical`）
   - 统一日期格式

2. **数据增强**：
   - 提取受影响的产品和版本
   - 提取修复建议

3. **数据质量评分**：
   - 根据字段完整度评分
   - 过滤低质量数据

---

**最后更新**：2026-02-03  
**相关文件**：`cve_crawler_auto.py`
