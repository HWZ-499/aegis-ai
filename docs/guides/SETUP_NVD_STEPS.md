# 📝 NVD API Key 配置步骤（详细版）

## ✅ 步骤 1：编辑 .env 文件

你的 `.env` 文件在：`aegis-ai-core\.env`

**打开文件，找到这一行**：
```env
NVD_API_KEY=your-nvd-api-key-here
```

**替换为你的真实 API Key**：
```env
NVD_API_KEY=你的真实API密钥
```

**重要**：
- ❌ 不要加引号
- ❌ 不要有空格
- ✅ 直接写密钥，例如：`NVD_API_KEY=12345678-1234-1234-1234-123456789abc`

---

## ✅ 步骤 2：验证配置

运行测试脚本：

```bash
cd aegis-ai-core
python test_nvd_api.py
```

**成功示例**：
```
✅ API Key 已设置（长度: 36）
✅ API 请求成功！
📊 数据库中共有 200000+ 条 CVE 记录
📝 示例 CVE: CVE-2024-XXXXX
```

**失败示例**：
```
❌ API Key 未设置
```
或
```
❌ 认证失败：API Key 无效
```

---

## ✅ 步骤 3：测试爬虫（小规模）

```bash
# 爬取最近 1 天的数据，最多 5 条（测试用）
python cve_crawler_auto.py --days 1 --max-results 5
```

**成功示例**：
```
✅ 连接数据库成功
ℹ️ 使用 NVD API 2.0（需要 Key）
📊 已获取 5 条 CVE 数据
💾 正在写入数据库：5 条新增
✅ 数据库更新完成！当前共有 15 条记录
```

---

## ✅ 步骤 4：正式运行

### 首次初始化（推荐）

```bash
# 爬取最近 30 天的数据，最多 500 条
python cve_crawler_auto.py --days 30 --max-results 500
```

### 日常更新

```bash
# 自动模式：从上次更新时间开始
python cve_crawler_auto.py --auto --max-results 100
```

---

## 🎯 完整示例

```bash
# 1. 进入目录
cd c:\Users\HT341\aegis-ai\aegis-ai-core

# 2. 编辑 .env 文件，添加你的 NVD_API_KEY

# 3. 验证配置
python test_nvd_api.py

# 4. 测试爬虫（小规模）
python cve_crawler_auto.py --days 1 --max-results 5

# 5. 正式运行（首次）
python cve_crawler_auto.py --days 30 --max-results 500

# 6. 验证数据
python -c "import chromadb; client = chromadb.PersistentClient(path='./aegis_db'); print('记录数:', client.get_collection('cve_core').count())"
```

---

## ⚠️ 如果遇到问题

### 问题 1：API Key 未设置

**检查**：
1. `.env` 文件是否在 `aegis-ai-core` 目录下
2. 格式是否正确：`NVD_API_KEY=密钥`（没有引号）
3. 重启终端

### 问题 2：API 请求失败（401/403）

**解决**：
1. 检查 API Key 是否正确复制（没有多余空格）
2. 重新申请 API Key：https://nvd.nist.gov/developers/request-an-api-key
3. 检查 API Key 是否过期

### 问题 3：SSL 错误

**解决**：
1. 关闭代理
2. 或在 `.env` 中添加：`PROXY_PORT=你的代理端口`

---

## 📞 需要帮助？

运行 `python test_nvd_api.py` 查看详细错误信息！
