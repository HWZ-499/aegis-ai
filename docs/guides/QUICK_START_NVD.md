# 🚀 NVD API Key 快速配置指南

## 方法 1：使用 .env 文件（最简单，推荐）

### 步骤 1：创建或编辑 `.env` 文件

在 `aegis-ai-core` 目录下，创建或编辑 `.env` 文件：

```env
# NVD API Key（从 https://nvd.nist.gov/developers/request-an-api-key 获取）
NVD_API_KEY=你的API密钥在这里

# DeepSeek API Key（如果还没有）
DEEPSEEK_API_KEY=你的DeepSeek密钥
```

**重要**：
- ✅ 将 `你的API密钥在这里` 替换为你的真实 API Key
- ✅ 不要有引号，直接写密钥
- ✅ 文件已自动添加到 `.gitignore`，不会提交到 Git

### 步骤 2：验证配置

```bash
cd aegis-ai-core
python test_nvd_api.py
```

**如果成功**，你会看到：
```
✅ API Key 已设置
✅ API 请求成功！
📊 数据库中共有 XXXX 条 CVE 记录
```

### 步骤 3：运行爬虫

```bash
# 测试运行（小规模）
python cve_crawler_auto.py --days 1 --max-results 5

# 正式运行（最近 7 天，最多 100 条）
python cve_crawler_auto.py --days 7 --max-results 100

# 自动模式（从上次更新时间开始）
python cve_crawler_auto.py --auto --max-results 100
```

---

## 方法 2：使用环境变量（临时）

### Windows PowerShell

```powershell
# 临时设置（当前终端会话有效）
$env:NVD_API_KEY = "你的API密钥"

# 然后运行爬虫
python cve_crawler_auto.py --days 7 --max-results 100
```

### Windows CMD

```cmd
set NVD_API_KEY=你的API密钥
python cve_crawler_auto.py --days 7 --max-results 100
```

### Linux/Mac

```bash
export NVD_API_KEY="你的API密钥"
python cve_crawler_auto.py --days 7 --max-results 100
```

---

## 📋 完整流程示例

### 1. 配置 API Key

```bash
# 进入目录
cd aegis-ai-core

# 创建 .env 文件（如果不存在）
# 编辑 .env，添加：NVD_API_KEY=你的密钥
```

### 2. 测试配置

```bash
python test_nvd_api.py
```

### 3. 运行爬虫

```bash
# 首次运行：爬取最近 30 天的数据
python cve_crawler_auto.py --days 30 --max-results 200

# 日常运行：自动模式（从上次更新时间开始）
python cve_crawler_auto.py --auto --max-results 100
```

### 4. 验证数据

```bash
# 查看数据库记录数
python -c "import chromadb; client = chromadb.PersistentClient(path='./aegis_db'); print('记录数:', client.get_collection('cve_core').count())"

# 测试 RAG 检索
python test_rag_optimizer.py
```

---

## ⚠️ 常见问题

### Q1: API Key 格式是什么？

**A**: NVD API Key 通常是一个 UUID 格式的字符串，例如：
```
12345678-1234-1234-1234-123456789abc
```

### Q2: 如何获取 API Key？

**A**: 
1. 访问：https://nvd.nist.gov/developers/request-an-api-key
2. 填写注册表单（姓名、邮箱等）
3. 提交后，API Key 会发送到你的邮箱
4. 复制 API Key 到 `.env` 文件

### Q3: API Key 设置后还是提示未设置？

**A**: 
1. 检查 `.env` 文件是否在 `aegis-ai-core` 目录下
2. 检查格式是否正确（`NVD_API_KEY=密钥`，没有引号）
3. 重启终端
4. 运行 `python test_nvd_api.py` 验证

### Q4: API 请求返回 401/403？

**A**: 
- 401：API Key 无效，检查是否正确复制
- 403：API Key 可能已过期，重新申请

### Q5: SSL 错误？

**A**: 
- 关闭代理
- 或设置代理端口：在 `.env` 中添加 `PROXY_PORT=7897`

---

## ✅ 配置检查清单

- [ ] 已创建 `.env` 文件
- [ ] 已添加 `NVD_API_KEY=你的密钥`
- [ ] 运行 `python test_nvd_api.py` 显示成功
- [ ] 运行 `python cve_crawler_auto.py --days 1 --max-results 5` 成功获取数据

---

## 🎯 下一步

配置完成后，你可以：

1. **首次初始化**：
   ```bash
   python cve_crawler_auto.py --days 30 --max-results 500
   ```

2. **设置定时任务**（每天自动更新）：
   - Windows：使用任务计划程序
   - Linux/Mac：使用 cron
   - 详见 `CVE_CRAWLER_GUIDE.md`

3. **测试 RAG 功能**：
   ```bash
   python test_rag_optimizer.py
   python aegis_shell.py
   ```

---

**需要帮助？** 运行 `python test_nvd_api.py` 查看详细错误信息
