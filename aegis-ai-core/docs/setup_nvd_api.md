# 🔑 NVD API Key 配置指南

## 📋 步骤 1：设置环境变量

### Windows PowerShell（推荐）

```powershell
# 临时设置（当前会话有效）
$env:NVD_API_KEY = "your-api-key-here"

# 永久设置（需要重启终端）
[System.Environment]::SetEnvironmentVariable('NVD_API_KEY', 'your-api-key-here', 'User')
```

### Windows CMD

```cmd
# 临时设置
set NVD_API_KEY=your-api-key-here

# 永久设置（需要重启终端）
setx NVD_API_KEY "your-api-key-here"
```

### Linux/Mac

```bash
# 临时设置（当前会话有效）
export NVD_API_KEY="your-api-key-here"

# 永久设置（添加到 ~/.bashrc 或 ~/.zshrc）
echo 'export NVD_API_KEY="your-api-key-here"' >> ~/.bashrc
source ~/.bashrc
```

### 使用 .env 文件（推荐）

1. **创建或编辑 `.env` 文件**（在 `aegis-ai-core` 目录下）：

```env
NVD_API_KEY=your-api-key-here
```

2. **代码会自动读取**（已集成 `python-dotenv`）

---

## 📋 步骤 2：验证配置

### 方法 1：Python 验证

```bash
python -c "import os; from dotenv import load_dotenv; load_dotenv(); print('API Key:', os.getenv('NVD_API_KEY', '未设置'))"
```

### 方法 2：运行爬虫测试

```bash
python cve_crawler_auto.py --days 1 --max-results 5
```

**如果配置成功**，你会看到：
```
ℹ️ 使用 NVD API 2.0（需要 Key）
✅ API 请求成功
📊 获取到 X 条 CVE 数据
```

**如果配置失败**，你会看到：
```
ℹ️ 使用 NVD API 1.0（不需要 Key，但功能有限）
❌ API 请求失败: 403 Forbidden
```

---

## 📋 步骤 3：运行爬虫

### 测试运行（小规模）

```bash
# 爬取最近 1 天的数据，最多 5 条
python cve_crawler_auto.py --days 1 --max-results 5
```

### 正式运行

```bash
# 爬取最近 7 天的数据，最多 100 条
python cve_crawler_auto.py --days 7 --max-results 100

# 自动模式：从上次更新时间开始
python cve_crawler_auto.py --auto --max-results 100
```

---

## 📋 步骤 4：设置定时任务（可选）

### Windows 任务计划程序

1. **创建批处理文件** `run_cve_crawler.bat`：

```batch
@echo off
cd /d C:\Users\HT341\aegis-ai\aegis-ai-core
set NVD_API_KEY=your-api-key-here
python cve_crawler_auto.py --auto --max-results 100
```

2. **在任务计划程序中设置**：
   - 触发器：每天 02:00
   - 操作：运行 `run_cve_crawler.bat`

### Linux/Mac cron

```bash
# 编辑 crontab
crontab -e

# 添加（每天凌晨 2 点运行）
0 2 * * * cd /path/to/aegis-ai/aegis-ai-core && export NVD_API_KEY="your-api-key-here" && python cve_crawler_auto.py --auto --max-results 100 >> /var/log/cve_crawler.log 2>&1
```

---

## ⚠️ 注意事项

1. **API Key 安全**：
   - ❌ 不要提交到 Git
   - ✅ 添加到 `.gitignore`
   - ✅ 使用环境变量或 `.env` 文件

2. **API 限制**：
   - 未认证：每小时 50 次请求
   - 已认证（有 Key）：每小时 5000 次请求
   - 建议：每次请求间隔 1 秒以上

3. **代理问题**：
   - 如果使用代理，可能需要配置 `PROXY_PORT` 环境变量
   - 或者关闭代理后再运行

---

## 🔍 故障排查

### 问题 1：API Key 未生效

**检查**：
```bash
python -c "import os; print(os.getenv('NVD_API_KEY'))"
```

**解决**：
- 确保环境变量已设置
- 重启终端
- 检查 `.env` 文件格式

### 问题 2：API 请求失败（403/401）

**原因**：
- API Key 无效
- API Key 格式错误

**解决**：
- 检查 API Key 是否正确
- 重新申请 API Key
- 检查环境变量是否包含引号

### 问题 3：SSL 错误

**解决**：
- 关闭代理
- 或配置代理端口：`set PROXY_PORT=7897`

---

## ✅ 验证清单

- [ ] API Key 已设置（环境变量或 .env）
- [ ] 验证脚本显示 API Key
- [ ] 测试运行成功
- [ ] 数据成功写入数据库
- [ ] 定时任务已配置（可选）

---

**最后更新**：2026-02-03
