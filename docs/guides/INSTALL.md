# 📦 安装指南 - 第一阶段改进

## 快速安装

### 1. 安装基础依赖

```bash
cd aegis-ai-core
pip install -r requirements.txt
```

### 2. 安装可选依赖（推荐）

为了启用高级功能，建议安装：

```bash
# 结构化 JSON 日志（推荐）
pip install python-json-logger

# 高级重试机制（推荐）
pip install tenacity
```

**注意**：如果不安装这些包，系统会自动降级到基础功能：
- 不使用 `python-json-logger`：使用标准日志格式
- 不使用 `tenacity`：使用简单重试机制（3次，指数退避）

### 3. 验证安装

启动服务，查看日志输出：

```bash
uvicorn aegis_server:app --reload --port 8000
```

如果看到以下信息，说明安装成功：

```
🚀 Aegis Server 启动成功
📊 数据库记录数: X
🔑 API Key 已配置: 是/否
🔄 重试机制: 启用 (tenacity) / 启用 (简单重试)
```

---

## 新功能说明

### ✅ 已实现的功能

1. **错误重试机制**
   - 自动重试 3 次（指数退避：2秒、4秒、8秒）
   - 处理超时、连接错误、HTTP 错误
   - 如果安装了 `tenacity`，使用高级重试策略

2. **结构化日志**
   - 所有请求都有详细日志记录
   - 包含：查询内容、响应时间、错误信息、客户端 IP
   - 如果安装了 `python-json-logger`，输出 JSON 格式（便于日志分析工具）

3. **统一错误处理**
   - 所有异常都有结构化错误响应
   - 前端收到友好的错误信息
   - 后端日志记录完整错误堆栈

4. **健康检查接口**
   - `GET /` 返回系统状态
   - 包含数据库记录数、API Key 配置状态

---

## 日志示例

### 标准日志格式（未安装 python-json-logger）

```
2026-02-02 10:30:15 - aegis - INFO - 收到聊天请求 - query: Fastjson漏洞, client_ip: 127.0.0.1
2026-02-02 10:30:16 - aegis - INFO - 向量检索完成 - distance: 0.85, cve_id: CVE-2023-50505
2026-02-02 10:30:18 - aegis - INFO - 请求处理完成 - mode: expert, total_time_ms: 2500
```

### JSON 日志格式（安装了 python-json-logger）

```json
{"asctime": "2026-02-02 10:30:15", "name": "aegis", "levelname": "INFO", "message": "收到聊天请求", "query": "Fastjson漏洞", "client_ip": "127.0.0.1"}
{"asctime": "2026-02-02 10:30:16", "name": "aegis", "levelname": "INFO", "message": "向量检索完成", "distance": 0.85, "cve_id": "CVE-2023-50505"}
```

---

## 故障排查

### 问题：日志没有输出

**检查**：
1. 确认已设置 `DEEPSEEK_API_KEY` 环境变量
2. 查看终端输出（日志默认输出到控制台）

### 问题：重试机制不工作

**检查**：
1. 如果安装了 `tenacity`，应该看到 "启用 (tenacity)"
2. 如果没有安装，会使用简单重试（功能相同）

### 问题：API 调用仍然失败

**检查日志**：
- 查看错误日志中的 `error` 和 `error_type` 字段
- 确认网络连接正常
- 确认 API Key 有效

---

## 下一步

完成第一阶段后，可以继续：
- 第二阶段：缓存机制、速率限制、前端配置化
- 查看 `ROADMAP.md` 了解完整改进计划
