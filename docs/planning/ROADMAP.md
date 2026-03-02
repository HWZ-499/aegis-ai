# 🗺️ Aegis-AI 改进路线图

## ✅ 已完成（P0 安全修复）

- [x] API Key 改为环境变量（`.env` 文件支持）
- [x] SSL 验证启用（移除 `verify=False`）
- [x] 清理死代码（移除未使用的导入）
- [x] 根目录 README（项目结构说明）

**当前评分**: 安全 25/100 → 60/100 ⬆️

---

## 🎯 第一阶段：可靠性提升（P0 剩余，2-3 小时）

### 1. 错误重试机制 ⏱️ 1 小时

**问题**: API 超时直接崩溃，可用性低

**方案**: 添加指数退避重试

```python
# 使用 tenacity 库
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10)
)
def call_deepseek(...):
    # 现有代码
```

**收益**: 可用性 90% → 99.9%

---

### 2. 结构化日志系统 ⏱️ 1 小时

**问题**: 只有 `print()`，无法追踪问题

**方案**: 使用 Python `logging` + JSON 格式

```python
import logging
from pythonjsonlogger import jsonlogger

logger = logging.getLogger("aegis")
logger.info("query_received", extra={
    "query": user_query,
    "distance": distance,
    "mode": mode,
    "response_time_ms": elapsed
})
```

**收益**: 故障诊断时间 1h → 5min

---

### 3. 错误处理优化 ⏱️ 30 分钟

**问题**: 异常信息不友好，前端只看到字符串错误

**方案**: 
- 后端：统一异常处理，返回结构化错误
- 前端：类型化错误处理

**收益**: 用户体验提升，错误可追踪

---

**第一阶段完成后评分**: 可靠性 40/100 → 75/100 ⬆️

---

## 🚀 第二阶段：性能与成本优化（P1，3-4 小时）

### 4. 缓存机制 ⏱️ 1.5 小时

**问题**: 相同查询重复调用 API，浪费成本

**方案**: Redis 或内存缓存（热点查询）

```python
from functools import lru_cache
import hashlib

@lru_cache(maxsize=100)
def cached_query(query_hash):
    # 查询逻辑
```

**收益**: API 调用减少 50%，成本降低

---

### 5. 速率限制 ⏱️ 1 小时

**问题**: 无限制，可能被 DoS 攻击

**方案**: FastAPI 中间件 + `slowapi`

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/api/chat")
@limiter.limit("10/minute")
async def chat(...):
    # 现有代码
```

**收益**: 防止恶意调用，保护 API 配额

---

### 6. 前端配置化 ⏱️ 1 小时

**问题**: API 地址硬编码 `127.0.0.1:8000`

**方案**: Angular 环境配置

```typescript
// src/environments/environment.ts
export const environment = {
  apiUrl: 'http://127.0.0.1:8000'
};
```

**收益**: 开发/生产环境切换方便

---

**第二阶段完成后评分**: 性能 60/100 → 80/100，成本降低 50% ⬆️

---

## 🏗️ 第三阶段：架构统一（P1-P2，4-6 小时）

### 7. 清理双后端混乱 ⏱️ 1 小时

**问题**: `aegis-backend` (Node) 未被使用，造成混淆

**方案**: 
- 选项 A：删除 `aegis-backend`（推荐）
- 选项 B：在 README 明确标注「仅演示用」

**收益**: 架构清晰，新人上手更快

---

### 8. 前端现代化（可选）⏱️ 3-4 小时

**问题**: 与 `AGENTS.md` 规范不一致（NgModule vs Standalone）

**方案**: 
- 迁移到 Standalone Components
- 使用 Signals 替代传统状态管理
- 使用 `inject()` 替代构造函数注入
- 使用 `@if/@for` 替代 `*ngIf/*ngFor`

**收益**: 代码更现代，符合 Angular 最佳实践

**注意**: 如果当前代码工作正常，可延后到重构阶段

---

### 9. 类型安全提升 ⏱️ 1 小时

**问题**: 前端大量使用 `any`，类型不安全

**方案**: 定义接口类型

```typescript
interface ChatResponse {
  reply: string;
  mode: 'chat' | 'expert' | 'audit';
  distance?: number;
}
```

**收益**: 编译时错误检查，IDE 智能提示

---

**第三阶段完成后评分**: 可维护性 30/100 → 70/100 ⬆️

---

## 📊 第四阶段：生产就绪（P2，6-8 小时）

### 10. 健康检查接口 ⏱️ 30 分钟

```python
@app.get("/health")
def health():
    return {
        "status": "healthy",
        "db_count": collection.count(),
        "api_key_configured": bool(DEEPSEEK_API_KEY)
    }
```

---

### 11. 单元测试 ⏱️ 3-4 小时

**目标**: 核心逻辑测试覆盖率 > 50%

```python
# tests/test_rag.py
def test_vector_search():
    # 测试向量检索逻辑
```

---

### 12. 监控与告警（可选）⏱️ 2-3 小时

- Prometheus metrics
- 错误告警（Sentry 或自定义）
- API 调用统计

---

### 13. 数据库扩容 ⏱️ 1 周（数据收集）

**问题**: 当前只有 7 条 CVE 数据

**方案**: 接入真实 CVE 数据源（MITRE、NVD 等）

---

## 📈 改进效果预期

| 阶段 | 时间 | 安全 | 可靠性 | 性能 | 可维护性 | 综合评分 |
|------|------|------|--------|------|----------|----------|
| **当前** | - | 60 | 40 | 60 | 30 | **47/100** |
| **第一阶段** | 2-3h | 60 | 75 | 60 | 40 | **59/100** ⬆️ |
| **第二阶段** | 3-4h | 60 | 75 | 80 | 50 | **66/100** ⬆️ |
| **第三阶段** | 4-6h | 60 | 75 | 80 | 70 | **71/100** ⬆️ |
| **第四阶段** | 6-8h | 85 | 90 | 85 | 85 | **86/100** ⬆️ |

---

## 🎯 推荐优先级

### 立即做（本周）
1. ✅ **错误重试** - 提升可用性，防止单点故障
2. ✅ **日志系统** - 问题排查必备
3. ✅ **缓存机制** - 节省成本，提升响应速度

### 尽快做（下周）
4. ✅ **速率限制** - 防止滥用
5. ✅ **前端配置化** - 开发体验提升
6. ✅ **清理双后端** - 架构清晰

### 后续优化（按需）
7. 前端现代化（如果团队有时间）
8. 单元测试（长期维护需要）
9. 监控告警（生产环境需要）

---

## 💡 快速开始

### 第一步：安装依赖

```bash
cd aegis-ai-core
pip install tenacity python-json-logger
```

### 第二步：选择改进项

建议从 **第一阶段** 开始，按顺序实施：
- 错误重试（1h）
- 日志系统（1h）
- 错误处理优化（30min）

完成后系统可靠性将显著提升！

---

**最后更新**: 2026-02-02  
**当前版本**: v1.0（P0 安全修复完成）
