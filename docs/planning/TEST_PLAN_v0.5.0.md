# Aegis AI v0.5.0 — 全面测试计划

> 版本：aegis-vscode 0.5.0 + aegis-ai-core 1.4.0
> 日期：2026-03-18
> 目标：验证 Phase 1 (O1+O2) + Phase 2 (O3+O4+O5) 全部优化功能的完整性和正确性

---

## 测试概要

| 阶段 | 范围 | 预期产出 |
|------|------|----------|
| **P1** | Core 单元测试回归 | pytest 全量 0 failures |
| **P2** | O1 — Inline Suppression UX | 抑制注释解析 + baseline 过滤正确 |
| **P3** | O2 — AI Fix Diff Preview | generate_fix LSP handler 可用 |
| **P4** | O3 — Dataflow Visualization | TaintPath.to_full_dict() 输出结构正确 |
| **P5** | O4 — SARIF/GHAS 报告 | SARIF 2.1.0 结构合法，含 rules/codeFlows |
| **P6** | O5 — 增量扫描 | IncrementalAnalyzer + DependencyTracker 功能正确 |
| **P7** | TypeScript 编译 | 0 errors (tsc --noEmit) |
| **P8** | LSP 集成 + End-to-End | LSP 服务器启动 + 诊断推送正确 |

---

## Phase 1：Core 单元测试回归 (P1)

**目标**：确保所有优化后 core 引擎原有测试不退化

| # | 测试项 | 命令 | 通过标准 |
|---|--------|------|----------|
| 1.1 | pytest 全量运行 | `pytest tests/ -v --tb=short` | 0 failures |
| 1.2 | AST 规则测试 | `pytest tests/test_ast_rules.py -v` | 全通过 |
| 1.3 | 污点分析测试 | `pytest tests/test_taint_analysis.py -v` | 全通过 |
| 1.4 | Phase2 污点测试 | `pytest tests/test_phase2_taint.py -v` | 全通过 |
| 1.5 | 多语言测试 | `pytest tests/test_multi_language.py -v` | 全通过 |
| 1.6 | 规则综合测试 | `pytest tests/rules/ -v` | 全通过 |
| 1.7 | 报告 XSS 防护测试 | `pytest tests/test_report_xss.py -v` | 全通过 |
| 1.8 | Core Features 测试 | `pytest tests/test_core_features.py -v` | 全通过 |

---

## Phase 2：O1 — Inline Suppression UX (P2)

**目标**：验证行内抑制注释和 baseline 抑制逻辑

| # | 测试项 | 命令 | 通过标准 |
|---|--------|------|----------|
| 2.1 | InlineSuppressor 单元测试 | `pytest tests/test_inline_suppressor.py -v` | 全通过 |
| 2.2 | Baseline 单元测试 | `pytest tests/test_baseline.py -v` | 全通过 |
| 2.3 | 通配符抑制 (# aegis-ignore) | 自动覆盖 | 全行所有规则被抑制 |
| 2.4 | 类型级抑制 (# aegis-ignore: RULE) | 自动覆盖 | 仅指定规则被抑制 |
| 2.5 | 前缀注释抑制（上一行） | 自动覆盖 | 下一行被抑制 |
| 2.6 | JS 风格注释 (// aegis-ignore) | 自动覆盖 | 支持 JS/TS/Java/Go/PHP |
| 2.7 | filter_findings 集成 | 自动覆盖 | 过滤后 findings 列表正确 |

---

## Phase 3：O2 — AI Fix Diff Preview (P3)

**目标**：验证 AI fix 生成接口和 LSP handler 注册

| # | 测试项 | 命令/方法 | 通过标准 |
|---|--------|-----------|----------|
| 3.1 | AI Provider 测试 | `pytest tests/test_ai_provider.py -v` | 全通过 |
| 3.2 | ai_analyzer 可导入 | `python -c "from src.scanner.ai_analyzer import AIAnalyzer; print('OK')"` | 无异常 |
| 3.3 | aegis/generateFix handler 注册 | LSP E2E 或 import 检查 | server.py 包含 handler |

---

## Phase 4：O3 — Dataflow Visualization (P4)

**目标**：验证 TaintPath.to_full_dict() 和 taint_enhancer 的完整字典输出

| # | 测试项 | 命令/方法 | 通过标准 |
|---|--------|-----------|----------|
| 4.1 | TaintPath.to_full_dict 结构 | 手动验证 | 包含 nodes, edges, pathLength, isSanitized, riskLevel, confidence |
| 4.2 | TaintNode 序列化 | to_full_dict 中 nodes | 每个 node 含 nodeType, name, filePath, line, column, codeSnippet |
| 4.3 | TaintEdge 序列化 | to_full_dict 中 edges | 每个 edge 含 edgeType, line, description |
| 4.4 | taint_enhancer full_path | `python -c "from src.scanner.taint_enhancer import ..."` | full_path 字段存在 |
| 4.5 | Phase2 Taint 测试 | `pytest tests/test_phase2_taint.py -v` | 全通过 |
| 4.6 | PHP Taint 测试 | `pytest tests/test_php_taint.py -v` | 全通过 |

---

## Phase 5：O4 — SARIF/GHAS 报告 (P5)

**目标**：验证 SARIF 2.1.0 格式合规，包含 rules 数组、CWE tags、codeFlows

| # | 测试项 | 命令/方法 | 通过标准 |
|---|--------|-----------|----------|
| 5.1 | generate_sarif 基本生成 | 手动调用验证 | 返回合法 JSON |
| 5.2 | SARIF schema 版本 | JSON 检查 | version == "2.1.0" |
| 5.3 | rules 数组 | JSON 检查 | 每个 rule 有 id + shortDescription |
| 5.4 | result.ruleId 关联 | JSON 检查 | ruleId 在 rules 中存在 |
| 5.5 | CWE tags & helpUri | JSON 检查 | properties.tags 包含 CWE-xxx + "security" |
| 5.6 | codeFlows (有 taint_analysis) | JSON 检查 | threadFlows.locations 非空 |
| 5.7 | %SRCROOT% uriBaseId | JSON 检查 | artifactLocation.uriBaseId == "%SRCROOT%" |
| 5.8 | aegis-scan.yml 模板 | 文件存在性 | templates/aegis-scan.yml 存在且可读 |

---

## Phase 6：O5 — 增量扫描 (P6)

**目标**：验证 IncrementalAnalyzer 函数级变更检测和 DependencyTracker 依赖追踪

| # | 测试项 | 命令/方法 | 通过标准 |
|---|--------|-----------|----------|
| 6.1 | IncrementalScanner 测试 | `pytest tests/test_incremental_scanner.py -v` | 全通过 |
| 6.2 | IncrementalAnalyzer 首次分析 | 手动验证 | get_changed_functions 返回 ([], True) 首次 |
| 6.3 | IncrementalAnalyzer 缓存命中 | 手动验证 | 相同代码 → ([], False) |
| 6.4 | IncrementalAnalyzer 函数变更 | 手动验证 | 修改函数 → 只返回变更函数名 |
| 6.5 | IncrementalAnalyzer >60% fallback | 手动验证 | 大量变更 → full_rescan=True |
| 6.6 | DependencyTracker JS import 解析 | 手动验证 | 正确识别 import/require 依赖 |
| 6.7 | DependencyTracker Python import 解析 | 手动验证 | 正确识别 from/import 依赖 |
| 6.8 | DependencyTracker get_affected_files | 手动验证 | 返回导入了变更文件的所有文件 |
| 6.9 | DependencyTracker export hash 变化 | 手动验证 | 导出签名变更返回 True |

---

## Phase 7：TypeScript 编译 (P7)

**目标**：确保 VS Code 扩展编译无报错

| # | 测试项 | 命令 | 通过标准 |
|---|--------|------|----------|
| 7.1 | tsc --noEmit | `cd aegis-vscode && npx tsc --noEmit` | 0 errors |

---

## Phase 8：LSP 集成 + End-to-End (P8)

**目标**：验证 LSP 服务器完整功能链

| # | 测试项 | 命令 | 通过标准 |
|---|--------|------|----------|
| 8.1 | LSP Server 单元测试 | `pytest tests/test_lsp_server.py -v` | 全通过 |
| 8.2 | LSP Integration 测试 | `pytest tests/test_lsp_integration.py -v` | 全通过 |
| 8.3 | LSP E2E 测试 | `pytest tests/test_lsp_e2e.py -v` | 全通过 |
| 8.4 | Server initialize 响应 | 自动覆盖 | capabilities 包含 textDocumentSync |
| 8.5 | didOpen → publishDiagnostics | 自动覆盖 | 漏洞代码产生诊断 |

---

## 验收标准

| 条件 | 要求 |
|------|------|
| P1 全量 pytest | 0 failures |
| P2 InlineSuppressor | 全通过 |
| P3 AI Provider | 全通过 |
| P4 Taint to_full_dict | 结构验证通过 |
| P5 SARIF 报告 | 7 项验证全通过 |
| P6 增量扫描 | 9 项验证全通过 |
| P7 TypeScript | 0 errors |
| P8 LSP 集成 | 全通过 |

**总体验收**：所有 Phase 全部 PASS 方可确认 v0.5.0 功能完整。

---

## 测试执行结果（2026-03-18）

| 阶段 | 结果 | 详情 |
|------|------|------|
| **P1** Core 全量 pytest | ✅ **437 passed**, 2 skipped | 0 failures, 59.98s |
| **P2** O1 Inline Suppression | ✅ **27 passed** | 16 InlineSuppressor + 11 Baseline |
| **P3** O2 AI Fix Diff Preview | ✅ **17 passed** | AI Provider 全通过 + aegis/generateFix handler 确认 |
| **P4** O3 Dataflow Visualization | ✅ **42 passed** + to_full_dict 验证通过 | nodes/edges/pathLength/isSanitized/riskLevel/confidence 结构正确 |
| **P5** O4 SARIF/GHAS | ✅ **7/7 验证通过** | SARIF 2.1.0 + rules + CWE tags + codeFlows + %SRCROOT% |
| **P6** O5 增量扫描 | ✅ **4 pytest + 8 manual 全通过** | IncrementalAnalyzer (首次/缓存/变更/fallback) + DependencyTracker (JS/PY import + affected + hash) |
| **P7** TypeScript | ✅ **0 errors** | tsc --noEmit 编译正常 |
| **P8** LSP 集成 | ✅ **54 passed** | LSP server + integration + E2E 全通过 |

### 总计

| 指标 | 数值 |
|------|------|
| pytest 自动测试 | **581 passed**, 2 skipped, 0 failures |
| 手动验证项 | **15/15** 通过 |
| TypeScript 编译 | 0 errors |

### 结论

**v0.5.0 全部功能验证通过** — O1 (Inline Suppression UX) + O2 (AI Fix Diff Preview) + O3 (Dataflow Visualization) + O4 (GHAS SARIF) + O5 (Incremental Scanning) 均工作正常，无退化。
