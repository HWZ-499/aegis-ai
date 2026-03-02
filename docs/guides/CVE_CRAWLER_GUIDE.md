# 📚 CVE 数据爬虫使用指南

## 📋 概述

CVE 数据爬虫支持两种模式：
1. **一次性脚本**：手动运行，获取指定时间段的数据
2. **自动化定时任务**：每天/每周自动更新，保持知识库最新

---

## 🚀 快速开始

### 方式 1：一次性运行（手动）

```bash
cd aegis-ai-core

# 爬取最近 7 天的 CVE 数据（最多 100 条）
python cve_crawler_auto.py --days 7 --max-results 100

# 爬取最近 30 天的数据（最多 500 条）
python cve_crawler_auto.py --days 30 --max-results 500

# 全量更新（不增量，会覆盖已有数据）
python cve_crawler_auto.py --days 7 --full
```

### 方式 2：自动模式（从上次更新时间开始）

```bash
# 自动模式：从上次更新时间开始爬取
python cve_crawler_auto.py --auto

# 自动模式 + 指定最大数量
python cve_crawler_auto.py --auto --max-results 200
```

### 方式 3：定时任务（自动化）

#### Windows（使用任务计划程序）

1. **创建批处理文件** `run_cve_crawler.bat`：
```batch
@echo off
cd /d C:\Users\HT341\aegis-ai\aegis-ai-core
python cve_crawler_auto.py --auto --max-results 100
```

2. **使用任务计划程序**：
   - 打开"任务计划程序"
   - 创建基本任务
   - 触发器：每天 02:00
   - 操作：启动程序 → 选择 `run_cve_crawler.bat`

#### Linux/Mac（使用 cron）

1. **编辑 crontab**：
```bash
crontab -e
```

2. **添加定时任务**（每天凌晨 2 点运行）：
```bash
0 2 * * * cd /path/to/aegis-ai/aegis-ai-core && python cve_crawler_auto.py --auto --max-results 100 >> /var/log/cve_crawler.log 2>&1
```

#### Python 调度器（跨平台，推荐）

```bash
# 安装依赖
pip install schedule

# 运行调度器（会一直运行，按 Ctrl+C 停止）
python cve_crawler_scheduler.py
```

**注意**：这种方式需要保持程序运行，适合在服务器上使用 `screen` 或 `tmux`。

---

## 📊 功能说明

### 1. 增量更新

**默认启用**：只添加新的 CVE，不覆盖已有数据

```bash
# 增量更新（默认）
python cve_crawler_auto.py --days 7

# 全量更新（覆盖已有数据）
python cve_crawler_auto.py --days 7 --full
```

### 2. 数据源

- **NVD API**：National Vulnerability Database（官方 CVE 数据库）
- **免费使用**：无需 API Key
- **实时数据**：获取最新的 CVE 信息

### 3. 数据字段

每条 CVE 包含：
- `id`: CVE 编号（如 CVE-2021-44228）
- `description`: 漏洞描述
- `severity`: 严重程度（Critical, High, Medium, Low）
- `cvss_score`: CVSS 分数（0-10）
- `published`: 发布日期
- `cwe_ids`: CWE 编号列表

### 4. 数据清洗与结构化

**详细说明**：请查看 `CVE_DATA_PROCESSING.md`

**核心流程**：
1. **解析**：从 API 原始 JSON 中提取关键字段
2. **清洗**：处理缺失值、格式统一、数据验证
3. **结构化**：转换为统一的格式
4. **格式化**：转换为适合向量化的文档字符串

**演示脚本**：
```bash
python test_data_processing.py
```

这会展示完整的数据转换过程。

---

## 🔧 配置选项

### 命令行参数

```bash
python cve_crawler_auto.py [选项]

选项：
  --days DAYS           爬取最近多少天（默认：7）
  --max-results NUM     最多获取多少条（默认：100）
  --full                全量更新（不增量）
  --auto                自动模式（从上次更新时间开始）
```

### 代码配置

在 `cve_crawler_auto.py` 中可以修改：

```python
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
BATCH_SIZE = 20  # 每次请求的 CVE 数量
MAX_RESULTS = 100  # 每次运行最多获取的 CVE 数量
```

---

## 📝 日志

### 日志文件

爬虫运行时会生成日志文件：`cve_crawler.log`

### 日志内容

- 连接数据库状态
- 爬取进度
- 数据更新情况
- 错误信息

### 查看日志

```bash
# 实时查看日志
tail -f cve_crawler.log

# 查看最近 50 行
tail -n 50 cve_crawler.log
```

---

## 🎯 使用场景

### 场景 1：首次初始化

```bash
# 爬取最近 30 天的数据，初始化知识库
python cve_crawler_auto.py --days 30 --max-results 500
```

### 场景 2：日常维护（手动）

```bash
# 每天手动运行一次，获取最新数据
python cve_crawler_auto.py --auto --max-results 100
```

### 场景 3：自动化维护（推荐）

**Windows**：
- 使用任务计划程序，每天自动运行

**Linux/Mac**：
- 使用 cron，每天自动运行

**Python 调度器**：
- 运行 `cve_crawler_scheduler.py`，程序会持续运行并定时执行

---

## ⚠️ 注意事项

1. **API 限制**：
   - NVD API 有请求频率限制
   - 建议每次请求间隔 1 秒以上
   - 每天最多请求 50 次（未认证）

2. **网络要求**：
   - 需要能访问 NVD API（可能需要代理）
   - 如果使用代理，修改代码中的代理配置

3. **存储空间**：
   - 每条 CVE 约占用 1-2 KB
   - 1000 条 CVE 约占用 1-2 MB
   - 注意数据库文件大小

4. **数据去重**：
   - 使用 `upsert` 方法，相同 ID 会自动更新
   - 增量更新模式会跳过已存在的 CVE

---

## 🔍 故障排查

### 问题 1：API 请求失败

**原因**：网络问题或 API 限制

**解决**：
- 检查网络连接
- 添加代理配置
- 减少请求频率

### 问题 2：数据库连接失败

**原因**：数据库路径错误或权限问题

**解决**：
- 检查 `db_path` 配置
- 确保有写入权限

### 问题 3：没有新数据

**原因**：增量更新模式下，所有数据都已存在

**解决**：
- 使用 `--full` 强制更新
- 增加 `--days` 参数，扩大时间范围

---

## 📈 性能优化

1. **批量处理**：一次处理多条数据，减少数据库操作
2. **增量更新**：只获取新数据，避免重复处理
3. **异步请求**：可以改为异步请求，提高速度（未来优化）

---

## 🎓 技术亮点（面试要点）

1. **自动化数据采集**：
   > "实现了自动化 CVE 数据爬虫，支持定时任务和增量更新，保持知识库最新"

2. **数据清洗与结构化**：
   > "从 NVD API 获取原始数据，进行清洗和结构化处理，提取关键信息（CVE ID、严重程度、CVSS 分数等）"

3. **增量更新机制**：
   > "实现了增量更新机制，避免重复数据，提高更新效率"

4. **定时任务调度**：
   > "支持多种定时任务方式（Windows 任务计划、Linux cron、Python 调度器），实现自动化运维"

---

## 📞 相关文件

- `cve_crawler_auto.py`：主爬虫脚本（支持自动化和手动）
- `cve_crawler_scheduler.py`：定时任务调度器
- `last_update.txt`：记录上次更新时间（自动生成）
- `cve_crawler.log`：日志文件（自动生成）

---

**最后更新**：2026-02-03  
**作者**：Aegis AI 开发团队
