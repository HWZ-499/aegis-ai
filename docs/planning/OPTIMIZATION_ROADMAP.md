# Aegis AI — 优化路线图

> 本文档为项目长远优化的指导性文件，涵盖代码质量、架构演进、技术栈升级、目录重构等方面。
> 所有后续更新和优化工作均以此文档为依据。

**创建日期**: 2026-03-05 | **最后更新**: 2026-03-05

---

## 目录

- [Q1 2026 完成状态评估](#q1-2026-完成状态评估)
- [代码质量问题清单](#代码质量问题清单)
- [目录结构优化](#目录结构优化)
- [技术栈升级建议](#技术栈升级建议)
- [架构优化方向](#架构优化方向)
- [CI/CD 改进](#cicd-改进)
- [实施路线图](#实施路线图)
- [变更记录](#变更记录)

---

## Q1 2026 完成状态评估

| Q1 目标 | 状态 | 证据 |
|---------|------|------|
| NoSQL 嵌套对象污点传播修复 | **已完成** | `rules/nosql_injection/javascript_ast_rule.py` 已集成数据流分析 |
| 规则正/负测试用例 | **部分完成** | `tests/rules/` 覆盖 8 类规则，20+ 用例文件；Python 用例仍缺失 |
| VSCode Marketplace 预览版 | **已完成** | `aegis-ai-security-0.2.0.vsix` 已构建 |
| README 基准数据 | **已完成** | README 含 NodeGoat/DVWA/django/flask F1/Recall/Precision 数据 |
| 演示 GIF | **未完成** | 仓库中未发现 GIF 文件 |

### Q1 遗留项

- [ ] 制作演示 GIF（编写漏洞 → 保存 → 诊断 → AI 修复完整流程）并嵌入 README
- [ ] `tests/rules/` 补充 Python 语言的 XSS、SQL 注入正/负用例
- [ ] 清理空规则目录（`buffer_overflow/`、`format_string/`）

---

## 代码质量问题清单

### P0 — 已修复

| # | 问题 | 修复方案 | 状态 |
|---|------|----------|------|
| 1 | `aegis_server.py:137` `try:999` 语法错误 | 移除 `999` | **已修复** |
| 2 | Pydantic 模型不足 | 创建 `src/core/models.py`（Finding、ScanResult、AuditResponse） | **已修复** |
| 3 | `requests` 同步阻塞 | 替换为 `httpx.AsyncClient` | **已修复** |

### P1 — 已修复

| # | 问题 | 修复方案 | 状态 |
|---|------|----------|------|
| 4 | 日志配置分散冲突 | 创建 `src/core/logging_config.py` 统一配置 | **已修复** |
| 5 | `sys.path` 手动操作 | 创建 `pyproject.toml` + `pip install -e .` | **已修复**（pyproject.toml 已创建） |
| 6 | ChromaDB 路径不一致 | `src/core/config.py` 通过 `AegisSettings.db_path` 统一 | **已修复** |
| 7 | 类型注解不完整 | `Finding.from_legacy_dict()` / `to_legacy_dict()` 提供渐进迁移路径 | **部分修复** |

### P2 — 已处理

| # | 问题 | 修复方案 | 状态 |
|---|------|----------|------|
| 8 | 旧引擎未清理 | 标记 deprecated（docstring），计划 v1.5 移除 | **已标记** |
| 9 | aegis-backend 已废弃 | 移至 `_archived/` | **已移动** |
| 10 | 无 pytest 配置 | `pyproject.toml [tool.pytest.ini_options]` | **已修复** |

### 待解决

- [ ] 逐步将各模块的裸 dict Finding 迁移至 `Finding` Pydantic 模型
- [ ] 为 `src/core/` 中所有函数添加完整类型注解
- [ ] `aegis_server.py` 中移除对旧引擎（`ast_analyzer`、`security_rules`）的 import
- [ ] 统一所有入口的日志初始化（crawler 脚本、worker_daemon）

---

## 目录结构优化

### 已执行的变更

```
aegis-ai/
├── pyproject.toml          → 未创建在根级（仅 aegis-ai-core 有）
├── .pre-commit-config.yaml → 新增
├── .dockerignore           → 新增
├── Dockerfile              → 新增
├── docker-compose.yml      → 新增
├── _archived/
│   └── aegis-backend/      → 从根目录移入
├── docs/
│   ├── guides/             → 合并了 aegis-ai-core/docs 中的 INSTALL、QUICK_START 等
│   ├── technical/          → 合并了 DETECTION_QUALITY、TEST_RESULTS 等
│   ├── troubleshooting/    → 合并了 ISSUES_SUMMARY、QUICK_FIX_GUIDE
│   └── planning/
│       └── OPTIMIZATION_ROADMAP.md → 本文档
├── aegis-ai-core/
│   ├── pyproject.toml      → 新增（替代 requirements.txt）
│   └── src/
│       └── core/           → 新增
│           ├── __init__.py
│           ├── config.py
│           ├── logging_config.py
│           └── models.py
```

### 后续待执行

- [ ] `scripts/` 目录按用途分子目录（`benchmark/`、`debug/`、`data/`）
- [ ] 旧引擎代码移至 `analysis/_legacy/`（v1.4 时执行）
- [ ] 合并 `aegis-ai-core/docs/` 中剩余文件后清理该目录

---

## 技术栈升级建议

### 已完成

| 原技术 | 新技术 | 状态 |
|--------|--------|------|
| `requirements.txt` | `pyproject.toml` (PEP 621) | **已创建** |
| `requests` (同步) | `httpx` (异步) | **已替换** |
| 无 linter 配置 | `ruff` (pyproject.toml 内配置) | **已配置** |
| 无 pre-commit | `.pre-commit-config.yaml` | **已创建** |
| 散落 `dotenv` | `pydantic-settings` (AegisSettings) | **已创建** |
| 无 Docker | Dockerfile + docker-compose.yml | **已创建** |

### Q2-Q3 待执行

| 方向 | 说明 | 优先级 |
|------|------|--------|
| `tree-sitter` 升级 | 监控 `tree-sitter-languages` 对 `>=0.22` 兼容 | 中 |
| 性能基准自动化 | `pytest-benchmark` 集成到 CI | 中 |
| 向量库评估 | 评估 `qdrant` / `lancedb` 替代 `chromadb` | 低 |

### Q4+ 长期方向

| 方向 | 说明 |
|------|------|
| 规则 DSL | 类 Semgrep YAML 声明式规则，降低社区贡献门槛 |
| WASM 部署 | Tree-sitter WASM + LSP in browser（Web IDE 支持） |
| Angular 前端 | Web Dashboard，后端 CORS 已预留 `localhost:4200` |
| 多租户 SaaS | 用户认证、项目隔离、结果存储（商业化路径） |

---

## 架构优化方向

### 1. 统一数据模型层 — **已完成**

`src/core/models.py` 定义了 `Finding`、`ScanResult`、`AuditResponse` 等 Pydantic 模型。
提供 `from_legacy_dict()` / `to_legacy_dict()` 实现渐进迁移。

### 2. 配置集中化 — **已完成**

`src/core/config.py` 中的 `AegisSettings` 通过 `pydantic-settings` 管理所有配置：
- AI provider keys (DeepSeek / OpenAI)
- 数据库路径
- 缓存与限流参数
- CORS 配置
- 日志级别

### 3. 清理双引擎 — **部分完成**

- `ast_analyzer.py`、`security_rules.py`、`rule_based_audit.py` 已标记 `@deprecated`
- `aegis_server.py` 仍在 import 旧引擎（向后兼容）
- **v1.4 目标**: 将 `/api/audit` 切换到 `rule_engine.py`
- **v1.5 目标**: 完全移除旧引擎代码

### 4. 跨文件分析集成到 LSP — **已完成**

`WorkspaceContext` 类在 LSP 初始化时后台构建 import graph：
- `INITIALIZE`: 读取工作区根路径，启动后台线程构建依赖图
- `didSave`: 合并跨文件 findings 到单文件诊断结果，并触发图的增量重建
- 用户配置传递: `initializationOptions` 传入 `severity_minimum`、`disabled_rules` 等

### 5. 插件配置能力增强 — **已完成**

`package.json` 新增配置项：

| 配置项 | 类型 | 说明 |
|--------|------|------|
| `aegisAI.severity.minimum` | enum | 最低显示严重度 |
| `aegisAI.excludePatterns` | array | 排除扫描的文件 glob |
| `aegisAI.disabledRules` | array | 禁用的规则 ID 列表 |
| `aegisAI.ai.enabled` | boolean | AI 修复开关 |
| `aegisAI.ai.provider` | enum | AI 提供商（deepseek/openai） |
| `aegisAI.scanOnSave` | boolean | 保存时自动扫描 |
| `aegisAI.scanOnChange` | boolean | 编辑时实时扫描 |

---

## CI/CD 改进 — **已完成**

### 新增 CI Jobs

```
quality:          Ruff lint + format check + mypy type check
extension:        VSCode 扩展编译检查 (npm ci && npm run compile)
security-scan:    测试 + coverage + 基准验收 + SARIF + HTML report
```

### 版本升级

| 组件 | v3/v4 → | 新版本 |
|------|---------|--------|
| `actions/checkout` | v3 | **v4** |
| `actions/setup-python` | v4 | **v5** |
| `actions/upload-artifact` | v3 | **v4** |
| `github/codeql-action/upload-sarif` | v2 | **v3** |
| `actions/github-script` | v6 | **v7** |

### 新增步骤

- `pytest --cov` + Codecov 覆盖率上报
- Ruff lint + format check
- mypy 类型检查（`src/core/` 强制 strict）
- VSCode 扩展编译检查

---

## 实施路线图

### 阶段 1 — 紧急修复（已完成）

- [x] 修复 `try:999` 语法错误
- [x] 创建 `pyproject.toml`
- [x] 创建 `src/core/` 模块
- [x] 替换 `requests` → `httpx`
- [x] 升级 GitHub Actions 版本

### 阶段 2 — 架构清理（已完成）

- [x] 旧引擎标记 deprecated
- [x] `aegis-backend` 移至 `_archived/`
- [x] 文档目录合并
- [x] VSCode 扩展配置扩展
- [x] 跨文件分析集成到 LSP
- [x] Docker 支持

### 阶段 3 — 渐进迁移（Q2 2026）

- [ ] 各模块 Finding dict → `Finding` Pydantic 模型
- [ ] `aegis_server.py` `/api/audit` 切换到 `rule_engine.py`
- [ ] 统一所有入口的日志初始化
- [ ] `scripts/` 目录重组
- [ ] 性能基准自动化（pytest-benchmark）

### 阶段 4 — 功能扩展（Q3-Q4 2026）

- [ ] Java 语言支持（tree-sitter-java）
- [ ] Go 语言基础规则
- [ ] 规则 DSL 评估
- [ ] VSCode Marketplace 正式发布（500+ installs）
- [ ] 演示 GIF + 社区运营

---

## 变更记录

| 日期 | 变更内容 |
|------|----------|
| 2026-03-05 | 初始文档创建，完成阶段 1-2 全部实施 |
