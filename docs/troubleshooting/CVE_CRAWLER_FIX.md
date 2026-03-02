# 🔧 CVE 爬虫问题修复说明

## ❌ 遇到的问题

### 问题 1：NVD API 2.0 返回 404
- **原因**：NVD API 2.0 需要 API Key，且 URL 格式不同
- **解决**：改用 NVD API 1.0（不需要 Key）

### 问题 2：NVD API 1.0 返回 403 Forbidden
- **原因**：NVD API 可能已限制访问，或需要认证
- **解决**：创建简化版爬虫，支持测试模式和文件导入

### 问题 3：SSL 错误
- **原因**：代理或证书问题
- **解决**：添加代理支持和 SSL 证书配置

---

## ✅ 解决方案

### 方案 1：简化版爬虫（推荐用于测试）

**文件**：`cve_crawler_simple.py`

**特点**：
- ✅ 测试模式：使用示例 CVE 数据
- ✅ 文件导入：从 JSON 文件导入
- ✅ 手动添加：支持手动添加数据
- ✅ 不需要网络：完全离线工作

**使用**：
```bash
# 测试模式（使用示例数据）
python cve_crawler_simple.py --test --test-count 10

# 从文件导入
python cve_crawler_simple.py --file cve_data.json
```

---

### 方案 2：完整版爬虫（需要 API Key）

**文件**：`cve_crawler_auto.py`

**使用 NVD API 2.0（需要 API Key）**：

1. **申请 API Key**：
   - 访问：https://nvd.nist.gov/developers/request-an-api-key
   - 填写注册表单
   - 获取 API Key

2. **配置环境变量**：
   ```bash
   # Windows PowerShell
   $env:NVD_API_KEY = "your-api-key-here"
   
   # Linux/Mac
   export NVD_API_KEY="your-api-key-here"
   ```

3. **修改代码**：
   ```python
   USE_API_V2 = True  # 在 cve_crawler_auto.py 中修改
   ```

4. **运行**：
   ```bash
   python cve_crawler_auto.py --days 7 --max-results 100
   ```

---

## 🧪 测试建议

### 步骤 1：使用简化版测试

```bash
# 测试模式（推荐）
python cve_crawler_simple.py --test --test-count 5
```

**预期结果**：
- ✅ 连接数据库成功
- ✅ 添加 5 条示例 CVE 数据
- ✅ 数据库记录数增加

### 步骤 2：验证数据

```bash
# 使用现有的查询脚本
python db_query.py
# 或
python test_rag_optimizer.py
```

### 步骤 3：如果需要真实数据

1. **申请 NVD API Key**（免费）
2. **配置环境变量**
3. **使用完整版爬虫**

---

## 📝 数据格式

### JSON 文件格式

```json
[
  {
    "id": "CVE-2021-44228",
    "description": "漏洞描述...",
    "severity": "Critical",
    "cvss_score": 10.0,
    "published": "2021-12-10T00:00:00.000Z",
    "cwe_ids": ["CWE-502"]
  },
  ...
]
```

### 从其他来源获取数据

1. **MITRE CVE**：https://cve.mitre.org/
2. **CVE Details**：https://www.cvedetails.com/
3. **GitHub Advisory Database**：https://github.com/advisories

---

## 💡 推荐方案

**当前阶段（测试）**：
- ✅ 使用 `cve_crawler_simple.py --test`
- ✅ 快速验证功能
- ✅ 不需要网络和 API Key

**生产环境**：
- ✅ 申请 NVD API Key
- ✅ 使用 `cve_crawler_auto.py`
- ✅ 配置定时任务

---

## 🔍 故障排查

### 问题：数据库连接失败

**解决**：
- 检查 `db_path` 配置
- 确保有写入权限

### 问题：没有新数据

**解决**：
- 使用 `--full` 强制更新
- 检查数据格式是否正确

### 问题：API 请求失败

**解决**：
- 检查网络连接
- 检查代理配置
- 申请 API Key（如果需要）

---

**最后更新**：2026-02-03
