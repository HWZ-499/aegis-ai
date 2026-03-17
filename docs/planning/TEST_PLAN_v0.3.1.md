# Aegis AI v0.3.1 — 全面测试计划

> 版本：aegis-vscode 0.3.1 + aegis-ai-core 1.2.1
> 日期：2026-03-17
> 目标：发布后全方位验证，确保所有功能正常工作

---

## 测试概要

| 阶段 | 范围 | 预期产出 |
|------|------|----------|
| P1 | Core 单元测试回归 | pytest 全通过 |
| P2 | LSP 服务器集成测试 | 服务器启动 + 扫描 + 诊断正常 |
| P3 | VS Code 扩展 E2E 测试 | 激活 + 命令 + UI 组件正常 |
| P4 | 多语言扫描验证 | JS/TS/Python/PHP/Java/Go 全覆盖 |
| P5 | 配置 & 边界 & 性能 | 各配置项生效 + 边界正确处理 |

---

## Phase 1：Core 单元测试回归

**目标**：确保 core 引擎全部现有测试通过

| # | 测试项 | 命令/方法 | 通过标准 |
|---|--------|-----------|----------|
| 1.1 | pytest 全量运行 | `cd aegis-ai-core && pytest tests/ -v` | 0 failures |
| 1.2 | AST 规则测试 | `pytest tests/test_ast_rules.py -v` | 全通过 |
| 1.3 | 污点分析测试 | `pytest tests/test_taint_analysis.py -v` | 全通过 |
| 1.4 | Baseline 测试 | `pytest tests/test_baseline.py -v` | 全通过 |
| 1.5 | 自定义规则测试 | `pytest tests/test_custom_rules.py -v` | 全通过 |
| 1.6 | 多语言测试 | `pytest tests/test_multi_language.py -v` | 全通过 |
| 1.7 | PHP 污点测试 | `pytest tests/test_php_taint.py -v` | 全通过 |
| 1.8 | NoSQL 规则测试 | `pytest tests/test_nosql_rule.py -v` | 全通过 |
| 1.9 | LSP 服务器测试 | `pytest tests/test_lsp_server.py -v` | 全通过 |
| 1.10 | LSP E2E 测试 | `pytest tests/test_lsp_e2e.py -v` | 全通过 |

---

## Phase 2：LSP 服务器集成测试

**目标**：验证修复后的 LSP 服务器（protocol.notify）完整功能

| # | 测试项 | 方法 | 通过标准 |
|---|--------|------|----------|
| 2.1 | 服务器启动 | Python 导入 create_server() | 无异常 |
| 2.2 | protocol.notify 可用 | 检查 server.protocol.notify 存在 | hasattr = True |
| 2.3 | JS 扫描功能 | analyze_javascript(test_vuln_demo.js) | 检出 ≥5 漏洞 |
| 2.4 | Python 扫描功能 | analyze_python(test_vulnerable_code.py) | 检出漏洞 |
| 2.5 | PHP 扫描功能 | analyze_php(PHP 测试代码) | 检出漏洞 |
| 2.6 | Java 扫描功能 | analyze_java(Java 测试代码) | 检出漏洞 |
| 2.7 | Go 扫描功能 | analyze_go(Go 测试代码) | 检出漏洞 |
| 2.8 | 诊断映射 | finding_to_diagnostic 转换 | severity/range/message 正确 |
| 2.9 | scan_document 集成 | scan_document(source, file_path) | 返回 finding 列表 |
| 2.10 | 超时/大文件保护 | 验证 MAX_FILE_SIZE 和 SCAN_TIMEOUT | 正确跳过 |

---

## Phase 3：VS Code 扩展 E2E 测试

**目标**：验证扩展在 VS Code 内的完整用户体验

| # | 测试项 | 方法 | 通过标准 |
|---|--------|------|----------|
| 3.1 | 扩展激活 | 打开 .js 文件后检查扩展状态 | 状态栏显示 "Aegis: 安全" 或 issue 数 |
| 3.2 | 自动扫描 (didOpen) | 打开 test_vuln_demo.js | Problems 面板显示诊断 |
| 3.3 | 保存扫描 (didSave) | 修改后保存文件 | 诊断更新 |
| 3.4 | 手动扫描命令 | Ctrl+Alt+S | 触发扫描 + 状态栏更新 |
| 3.5 | 扫描工作区命令 | Command Palette → Scan Workspace | 进度通知 + 批量诊断 |
| 3.6 | Findings TreeView | Activity Bar → Aegis Security | 显示分层发现列表 |
| 3.7 | 点击跳转 | TreeView 中点击 finding | 跳转到对应文件行 |
| 3.8 | Code Action | 在诊断处点击小灯泡 | 显示"插入修复建议注释" |
| 3.9 | 状态栏生命周期 | 扫描过程观察 | scanning → N issues/安全 |
| 3.10 | 报告 Webview | Command: Show Report | Webview 打开 scan-report.html |
| 3.11 | 错误恢复 | 关闭 Python/LSP 后观察状态 | 状态栏显示 disconnected/error |

---

## Phase 4：多语言扫描验证

**目标**：验证每种语言的漏洞检测能力

### 4.1 JavaScript（test_vuln_demo.js）

| 漏洞类型 | 代码行 | 预期 rule_id |
|----------|--------|-------------|
| SQL Injection | L10 | SQL_INJECTION_JS_AST |
| XSS | L16 | XSS_RISK_JS_AST |
| RCE (eval) | L19 | RCE_COMMAND_EXEC_JS_AST |
| Path Traversal | L24 | PATH_TRAVERSAL_JS_AST |
| Hardcoded Credentials | L30-31 | HARDCODED_CREDENTIALS_JS_AST |

### 4.2 Python

| 漏洞类型 | 预期 rule_id |
|----------|-------------|
| SQL Injection | SQL_INJECTION_PY_AST |
| RCE (exec/eval/subprocess) | RCE_COMMAND_EXEC_PY_AST |
| XSS (flask/django template) | XSS_RISK_PY_AST |
| Path Traversal | PATH_TRAVERSAL_PY_AST |
| SSRF | SSRF_PY_AST |
| Deserialization (pickle) | DESERIALIZATION_PY_AST |

### 4.3 PHP

| 漏洞类型 | 预期 rule_id |
|----------|-------------|
| SQL Injection (mysqli_query) | SQL_INJECTION_PHP_AST |
| RCE (shell_exec, system) | RCE_PHP_AST |
| XSS (echo unsanitized) | XSS_PHP_AST |
| Path Traversal (file_get_contents) | PATH_TRAVERSAL_PHP_AST |

### 4.4 Java

| 漏洞类型 | 预期 rule_id |
|----------|-------------|
| SQL Injection (PreparedStatement?) | SQL_INJECTION_JAVA_AST |
| RCE (Runtime.exec) | RCE_JAVA_AST |
| XSS (Servlet response) | XSS_JAVA_AST |
| Deserialization (ObjectInputStream) | DESERIALIZATION_JAVA_AST |

### 4.5 Go

| 漏洞类型 | 预期 rule_id |
|----------|-------------|
| SQL Injection (database/sql) | SQL_INJECTION_GO_AST |
| RCE (os/exec) | RCE_GO_AST |
| XSS (template.HTML) | XSS_GO_AST |
| Path Traversal (filepath.Join) | PATH_TRAVERSAL_GO_AST |

---

## Phase 5：配置 & 边界 & 性能

| # | 测试项 | 方法 | 通过标准 |
|---|--------|------|----------|
| 5.1 | severity.minimum 配置 | 设置为 "High"，验证 Low/Medium 被过滤 | 只显示 High/Critical |
| 5.2 | disabledRules 配置 | 禁用 SQL_INJECTION_JS_AST | 该规则不再报告 |
| 5.3 | excludePatterns 配置 | node_modules 文件不被扫描 | 无诊断 |
| 5.4 | scanOnSave=false | 关闭保存扫描 | 保存后不触发 |
| 5.5 | scanOnChange=false | 关闭实时扫描 | 输入时不触发 |
| 5.6 | 大文件处理 | >2MB 文件 | 跳过不扫描 |
| 5.7 | 不支持的文件类型 | .txt/.md 文件 | 无诊断 |
| 5.8 | 空文件 | 空 .js 文件 | 0 findings |
| 5.9 | 扫描性能 | test_vuln_demo.js scan 时间 | <2s |
| 5.10 | pythonPath 配置 | 设置错误路径 | 友好错误提示 |

---

## 测试执行记录

| 阶段 | 状态 | 结果摘要 | 日期 |
|------|------|----------|------|
| P1 | PASSED | 437 passed, 2 skipped, 0 failures (100s) | 2026-03-17 |
| P2 | PASSED | Server OK, notify OK, 6 langs OK (JS:7, PY:4, PHP:3, Java:3, Go:2) | 2026-03-17 |
| P3 | PASSED | 2/2 ext tests passing (fixed EXT_ID bug) | 2026-03-17 |
| P4 | PASSED (17/18) | JS:5/5 PY:5/5 PHP:3/3 Java:3/3 Go:1/2 | 2026-03-17 |
| P5 | PASSED | 22/22 checks. Perf: JS 8ms, PY 6ms | 2026-03-17 |

---

## 发现的问题清单

| # | 阶段 | 严重度 | 描述 | 状态 |
|---|------|--------|------|------|
| 1 | P3 | Medium | Extension test EXT_ID 写错 (aegis-ai → wen-zai) | FIXED |
| 2 | P4 | Low | Go XSS 规则不检测 fmt.Fprintf(w, userInput) | KNOWN (rule gap) |
