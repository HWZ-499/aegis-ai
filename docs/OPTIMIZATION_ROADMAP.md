# Aegis AI O1–O10 优化路线图

> 本文档是项目优化阶段、完成状态和验收标准的唯一事实源。
> 长期审查材料可作为优先级参考，但实际执行进度以本文档为准。

**最后同步日期**：2026-07-12
**当前阶段**：O10 已完成；下一阶段为 O9 生态与分发

## 当前执行优先级（2026-07-10 调整）

O7 的架构收口与 O10 的真实项目准确率验证必须并行推进，不能等到发布阶段才开始。
推荐执行顺序如下：

1. 收尾 O7，并把当前重构整理为可回滚、可验证的稳定检查点。
2. 立即并行启动 O10：冻结 NodeGoat、DVWA 与真实项目的 ground truth、扫描配置和可复跑基准；发布前以这套口径更新公开质量指标。
3. 推进 O8，优先让扫描失败、误报解释、降级信息与扫描进度在 IDE 中可见、可操作。
4. 仅在真实项目指标稳定、公开文档口径一致后推进 O9 的 Marketplace、PyPI 与宣传。

该调整不会改变 O1–O10 的阶段范围，只把“检测结果可信”从发布后的维护事项提升为发布前门槛。

## 强制文档同步规则

从 2026-06-20 起，任何优化任务都必须同时更新本文档：

1. 开始工作时，将目标阶段和任务标为“进行中”。
2. 代码、测试、CI 或行为发生变化时，同步更新对应阶段的完成项和验收证据。
3. 完成工作时，记录测试数量、基准数据、相关文件及仍未解决的问题。
4. 未更新本文档的优化不得视为完成，也不应提交或合并。
5. 若基准口径、测试数量或阶段定义发生变化，必须写明日期和原因。

## 阶段总览

| 阶段 | 目标 | 状态 |
|---|---|---|
| O1 | Baseline、行级抑制、忽略规则 | 已完成 |
| O2 | AI 修复生成、Diff Preview、修复应用 | 已完成 |
| O3 | 污点路径查询、可视化与 Finding 缓存 | 已完成 |
| O4 | 多格式报告、SARIF Code Flow、CI 上传与报告验收 | 已完成 |
| O5 | 增量扫描、跨文件分析、缓存与性能 | 已完成 |
| O6 | 检测准确率、FP/FN 与规则覆盖 | 已完成 |
| O7 | 架构治理、legacy 清理与类型安全 | 已完成 |
| O8 | IDE 错误可见性、交互体验与扩展测试 | 已完成 |
| O9 | PyPI、Marketplace、规则生态与社区 | 进行中 |
| O10 | 真实项目验收、稳定版本与长期维护 | 已完成 |

## O1：Baseline 与抑制

**状态：已完成**

- [x] `.aegis-baseline.json`
- [x] 行级 `aegis-ignore`
- [x] LSP Code Action 添加到 baseline
- [x] CLI baseline 读取与更新

## O2：AI 修复工作流

**状态：已完成**

- [x] AI 修复生成
- [x] 修复结果解析与校验
- [x] Diff Preview
- [x] 应用修复与失败处理

## O3：污点路径与 IDE 查询

**状态：已完成**

- [x] Finding 缓存
- [x] `aegis/getTaintPath`
- [x] Diagnostic 附带污点路径数据
- [x] 污点路径 Webview

## O4：报告、SARIF 与 CI

**状态：已完成**

### 已完成

- [x] JSON、HTML、Markdown、SARIF 2.1.0 输出
- [x] HTML 动态内容转义
- [x] SARIF rule descriptor、CWE、位置与严重级别
- [x] SARIF `codeFlows/threadFlows`
- [x] 扫描失败通过 JSON/SARIF 表达为 partial scan
- [x] GitHub Actions 上传 SARIF
- [x] GitHub Actions 上传 HTML 与 benchmark artifact
- [x] PR 扫描摘要评论

### 收尾验收

- [x] 为 SARIF Code Flow 增加结构化回归测试
- [x] 验证 SARIF URI、region、ruleId 和 threadFlow location 一致性
- [x] 增加四种报告格式的 CLI 端到端测试
- [x] CI 对生成的 SARIF 做 JSON/关键字段校验，禁止用空文件掩盖生成失败
- [x] 更新报告与 CI 验证文档
- [x] 完成 O4 全量测试后标记“已完成”

### O4 验收证据

- `tests/test_report_xss.py` 覆盖 SARIF rule descriptor、URI、region、partial scan 和 Code Flow。
- `tests/test_report_cli_e2e.py` 覆盖 JSON、HTML、Markdown、SARIF 四种 CLI 输出。
- `.github/workflows/security-scan.yml` 严格校验 SARIF 文件与关键结构，不再创建空报告兜底。
- `docs/VERIFICATION_GUIDE.md` 已增加 O4 本地复现步骤与检查清单。
- 2026-06-20 全量验证：`678 passed, 1 xfailed, 49 deselected`；
  Ruff、格式、类型检查、发布一致性检查通过。
- 对 `tests/unit_test_lab` 实际生成 SARIF：12 个 results、4 个 rules，
  所有 `result.ruleId` 均可映射到 rule descriptor。

## O5：增量、跨文件与性能

**状态：已完成**

### 已完成

- [x] 函数级增量分析与依赖追踪
- [x] 项目扫描缓存按规则版本失效
- [x] 同名同内容文件缓存隔离
- [x] 单轮规则哈希和文件哈希复用
- [x] 真实线程池并行扫描与确定性结果顺序
- [x] 并发扫描错误状态加锁
- [x] DSL 正则编译缓存
- [x] DSL YAML 解析缓存与项目级规则快照
- [x] Java、Go、PHP 单次 AST 解析
- [x] Tree-sitter Language 全局缓存与 Parser 线程隔离复用
- [x] 跨文件分析复用主扫描源码快照
- [x] 跨文件模块文件索引与解析缓存
- [x] 主扫描二进制读取、UTF-8 容错与通用换行保持

### 当前基准

同口径 100 文件混合语言扫描，Windows / Python 3.11：

| 模式 | 优化前 | 2026-06-20 当前值 |
|---|---:|---:|
| 顺序扫描 | 约 542 ms | 约 234 ms |
| 4 线程扫描 | 约 378 ms | 约 119 ms |
| 跨文件模块解析压力场景 | 约 225 ms | 约 18.7 ms |

当前验证基线：`684 passed, 1 xfailed, 49 deselected`。

### 剩余验收

- [x] 真实大型项目的时间与峰值内存基准
- [x] 并发缓存写入与中断恢复验证
- [x] LSP 增量扫描与 CLI 项目扫描一致性验证
- [x] 固化可重复的性能回归测试和阈值
- [x] 整理并提交 O5 稳定检查点（后续 O7/O10 检查点已完整承载并继续验证）

### O5 缓存可靠性验收证据

- 缓存使用“临时文件写完整后 `os.replace`”的原子替换流程。
- 32 个并发写入者不会留下损坏 JSON 或临时文件。
- 模拟替换中断时保留上一份有效缓存。
- `clear_cache()` 会清理崩溃遗留的 `.tmp` 文件。
- 实际扫描路径下，预计算缓存键后的原子写入约 92 ms / 100 文件。
- 2026-06-20 全量验证：`681 passed, 1 xfailed, 49 deselected`。

### O5 性能回归门禁

- 默认测试使用结构性预算，避免机器速度差异造成误报：
  - 200 次重复模块解析最多允许 10 次候选文件查询；
  - 项目级 DSL 规则预加载后，200 次规则集合构造不得重新扫描规则目录。
- 原有规则哈希、文件哈希、Parser 复用和跨文件源码快照测试继续作为性能不变量。
- CI 的 pytest-benchmark 输出到 `reports/performance-benchmark.json`，
  并作为 `performance-benchmark` artifact 保留 90 天，用于趋势比较。

### O5 真实项目基准

2026-06-20，Windows / Python 3.11，扫描 `aegis-ai-core/src`：

| 模式 | 文件 | Finding | 错误 | 时间 | 峰值内存 |
|---|---:|---:|---:|---:|---:|
| 顺序 | 118 | 43 | 0 | 15.652 s | 13.33 MiB |
| 4 线程 | 118 | 43 | 0 | 13.949 s | 15.22 MiB |

两种模式的文件数、finding 数和错误数一致。另有 8 个单文件
pytest-benchmark 场景成功生成 JSON 基准。

### O5 LSP / CLI 一致性

- 新增 `tests/test_lsp_cli_consistency.py`。
- 用未改函数中的旧 finding 和改动函数中新 finding 验证：
  LSP 函数级增量合并、LSP 全量扫描、CLI 单文件扫描的
  `(type, rule_id, line, severity)` 完全一致。

## O6：检测准确率

**状态：已完成**

- [x] 建立按语言、漏洞类型和规则统计的 TP/TN/FP/FN 矩阵
- [x] 补 PHP AST-only 的 RCE 与 XSS 缺口
- [x] 扩充反序列化、开放重定向、SSRF 等验收基准
- [x] 强化跨函数与跨文件污点传播（Python/JS 一跳参数 → Sink）
- [x] 扩展返回值摘要、重导出与多跳调用链传播
- [x] 为 Recall、Precision、F1 设置不可下降门禁

### O6 当前质量基线

2026-06-21，统一扫描 `tests/rules` 的 207 个受控样本：

| 语言 | TP | TN | FP | FN | Recall | Precision |
|---|---:|---:|---:|---:|---:|---:|
| Go | 17 | 14 | 0 | 0 | 100% | 100% |
| Java | 22 | 16 | 0 | 0 | 100% | 100% |
| JavaScript | 19 | 18 | 0 | 0 | 100% | 100% |
| PHP | 31 | 26 | 0 | 0 | 100% | 100% |
| Python | 26 | 18 | 0 | 0 | 100% | 100% |
| **总计** | **115** | **92** | **0** | **0** | **100%** | **100%** |

### O6 已完成

- `BenchmarkResult` 统一记录总体、漏洞类型、语言和“语言 × 漏洞类型”四个维度。
- `run_rule_sample_benchmark()` 使用 CLI/LSP 相同的生产分析入口，不再维护独立扫描口径。
- 恢复 Python SQLi 样本 `tp_python_cursor_execute_format.py` 的指标统计，不再静默跳过。
- 新增严格受控样本门禁：总体和每种语言均要求 Recall、Precision、F1 为 100%，FPR 为 0%。
- 基准脚本同时生成 `benchmark_report_*.json` 与 `quality_matrix_*.json`，CI 保存 90 天。
- 2026-06-22 全量验证：`737 passed, 1 xfailed, 50 deselected`；
  O6 acceptance `30 passed`，CI 类型门禁、Ruff、格式与 VS Code TypeScript 检查通过。

### O6 PHP AST-only 收敛

- PHP RCE/XSS 取消 Regex 补充，统一由 Tree-sitter AST 规则产出。
- 公共 API、LSP、项目扫描使用相同 `analyze_php()` 入口与规则 ID。
- AST 遍历不再依赖污点图成功构建；污点图失败时仍检测直接 Source→Sink。
- RCE 新增反引号命令、`call_user_func()` 动态调用和 shell sanitizer 覆盖。
- XSS 新增 `print`、短 echo 标签、`die/exit`，并统一处理嵌套 HTML sanitizer。
- 移除 RCE/XSS 近邻行去重，保留不同控制流分支中的独立 sink。
- DVWA 169 个 PHP 文件复测：RCE 9、XSS 7，`PHP-Regex` 来源为 0。

### O6 反序列化、开放重定向与 SSRF 扩展

- SSRF 从 Python/JavaScript 扩展到 PHP、Java、Go，五种主语言均注册统一规则。
- PHP 覆盖 `curl_init`、`curl_setopt(CURLOPT_URL)`、`file_get_contents` 等 URL sink。
- Java 覆盖 `RestTemplate`、`WebClient`、`HttpClient.send` 和 URL connection API。
- Go 覆盖 `http.Get/Head/Post/PostForm/NewRequest` 与 HTTP client 方法。
- 新增 PHP、Java、Go 的 LSP / 公共 API / 项目扫描一致性测试。
- JavaScript 反序列化新增 `js-yaml.load` TP/TN；Python 开放重定向新增
  `HttpResponseRedirect` TP/TN。
- 三类规则当前均有按语言的 TP/TN 统计，受控样本仍为 0 FP、0 FN。

### O6 跨文件参数污点传播

- `CrossFileAnalyzer` 复用生产 `analyze_python()` / `analyze_javascript()`，
  通过参数级合成 Source 生成导出函数的“参数 → Sink”摘要，不维护独立 Sink 清单。
- 摘要会扣除原文件本身已存在的 finding，避免把与参数无关的漏洞错误归因到调用端。
- 调用端使用统一 `DataFlowTracker` 追踪直接用户输入、变量赋值传播和 sanitizer。
- Python 支持 `import` / `from ... import`；JavaScript/TypeScript 支持 ESM、
  CommonJS 解构、默认导入/导出及 `.js/.jsx/.mjs/.cjs/.ts/.tsx` 解析。
- 修复带扩展名的相对模块导入解析，并保持原 `get_module_info()` 公共结构兼容。
- `ProjectScanner(use_cross_file=True)`、CLI `--cross-file` 和 LSP
  `experimental_cross_file` 复用同一 findings；默认项目扫描行为保持不变。
- 跨文件 finding 以被调函数 Sink 为主位置，以调用端 Source 为
  `related_locations`，并附带两段式 `taint_path`。
- 参数 → Sink 契约通过固定点迭代跨包装函数传播，不限制静态调用链层数。
- 返回值摘要区分函数内部 Source 与参数派生返回值，并在调用端赋值时继续传播污点。
- Python 导入别名、ESM 直接/别名/星号重导出及 CommonJS 属性重导出均解析到原始导出。
- 新增 10 个项目级回归，覆盖 Python、ESM、具名 CommonJS、默认 CommonJS、
  多跳包装、Python/ESM/CommonJS 重导出、Python/JavaScript 返回值、
  安全常量、ProjectScanner、CLI 与 LSP。
- 当前边界：仅解析可静态确定的模块与函数调用；运行时动态分派、反射调用和条件导出
  留待真实项目 ground-truth 阶段评估。

> 该 100% 指标仅表示受控回归样本全部通过；真实项目准确率仍以
> DVWA、NodeGoat 和后续 ground-truth 评估为准。

## O7：架构治理

**状态：已完成**

- [x] 移除剩余生产可达的 legacy regex 路径
- [x] 移除 CLI / ProjectScanner 可达的 legacy 扫描引擎
- [x] 移除 PHP 生产入口的 legacy regex 补充层
- [x] 统一生产分析入口与语言识别
- [x] 统一项目扫描会话与缓存生命周期边界
- [x] 收紧 mypy（全仓 `src/` 已纳入发布阻断门禁）
- [x] 清理静默异常与宽泛异常捕获（仅保留 5 个显式边界）
- [x] 清理五语言分析器的静默解析/污点/遍历异常
- [x] 拆分大型模块

### O7 第一批：统一分析入口与类型边界

- 新增 `src/analysis/languages.py`，集中维护语言类型、别名和文件扩展名映射。
- 新增 `rule_engine.analyze_source()` 作为唯一生产语言分派入口；原
  `analyze_python()` / `analyze_javascript()` 等函数继续作为兼容 API。
- ProjectScanner、LSP、worker daemon、benchmark、并行扫描器和跨文件摘要
  已迁移到统一入口，不再各自维护语言 `if/elif` 分派。
- 新增架构回归门禁，禁止上述生产调用方重新直接调用语言专用入口。
- `cross_file_analyzer.py` 修复剩余 mypy 问题并从 legacy 报告提升到 CI 类型门禁。
- 当前 CI 类型组 28 个文件、legacy 可见性组 11 个文件均为 0 mypy 错误。
- 2026-06-22 全量验证：`747 passed, 1 xfailed, 50 deselected`；
  O6 acceptance `30 passed`，Ruff、格式、发布一致性与 VS Code TypeScript 检查通过。

### O7 第二批：扫描会话与缓存生命周期

- `ProjectScanner.scan_session()` 统一管理全量与增量扫描的单轮状态。
- 每轮开始统一重置结果、统计、失败文件和跨文件统计，并预加载一次 DSL 规则快照。
- 任意成功或异常退出都会释放 DSL 定义和源码快照，避免临时状态跨轮泄漏。
- 磁盘 `ScanCache`、规则版本哈希、Tree-sitter Language 和线程 Parser 缓存明确保持跨轮复用。
- 顶层扫描会话通过独立锁串行化；文件级并行扫描仍按原线程池执行。
- 新增异常路径回归，验证跨文件失败时临时状态释放，同时持久缓存仍可命中。
- 性能结构门禁继续覆盖规则哈希、文件哈希、模块解析和 DSL 规则加载复用。
- 2026-06-22 全量验证：`749 passed, 1 xfailed, 50 deselected`；
  O6 acceptance `30 passed`，两个 mypy 分组、Ruff、格式与 VS Code TypeScript 检查通过。

### O7 第三批：移除 legacy 生产扫描引擎

- 删除 ProjectScanner 中旧 `ast_analyzer/multi_language_ast + scan_code_locally`
  的运行时分支和相关生产导入。
- `--engine` 暂保留为命令兼容参数，但只接受 `new`；`legacy` 会明确返回参数错误。
- 程序化构造 `ProjectScanner(engine="legacy")` 会立即抛出 `ValueError`，不再静默降级。
- `analyze_code_ast()`、`scan_code_locally()` 继续作为显式兼容/测试 API，
  不再能通过项目扫描主路径进入生产结果。
- PHP 尚未迁移完成的受限补充检查和 C/C++ 基础支持不属于本次删除范围，
  后续按漏洞类型逐项 AST 化后再移除。
- 新增 CLI、ProjectScanner 和源码架构门禁，防止 legacy 分支重新回流。

### O7 第四批：PHP 生产入口 AST-only

- 将 DVWA 认证查询中“两个用户输入字段 → mysql 弱转义 → 带引号 SELECT 插值”
  的 4 个 SQLi 缺口迁移到 `PhpSQLInjectionAstRule`。
- 迁移规则限定真实用户输入来源、两个独立弱转义字段和 `SELECT` 查询；
  单变量 INSERT 等场景不扩大告警范围。
- 删除 `analyze_php()` 对 `scan_code_locally()` 的调用和对应 PHP 正则去重/数字 guard 代码。
- 受控 PHP 样本、DVWA 169 文件以及全部真实目标 183 个 PHP 文件中，
  AST-only 与迁移前生产 finding 集合一致，`PHP-Regex` 独有 finding 为 0。
- DVWA ground truth 保持 TP 22、FP 29、FN 2、TN 3；
  Recall 91.7%、Precision 43.1%、F1 0.587，未发生质量回退。
- 保留 `scan_code_locally()` 兼容 API 和 C/C++ 基础支持；它们不再进入 PHP 生产入口。
- 2026-06-22 全量验证：`756 passed, 1 xfailed, 50 deselected`；
  O6 acceptance `30 passed`，性能结构门禁 `8 passed`，两个 mypy 分组、
  Ruff、格式与 VS Code TypeScript 检查通过。

### O7 第五批：分析器降级可观测性

- 新增统一 `log_analysis_degradation()`，固定语言、阶段、文件、异常类型和消息字段。
- Python、JavaScript/TypeScript、PHP、Java、Go 的 parse、taint、traverse
  可恢复失败不再静默；正常降级行为和 finding 输出保持不变。
- JavaScript 将原本混合的 parse/traverse 捕获拆开，日志可准确定位失败阶段。
- 新增 14 个异常路径回归，覆盖四个 Tree-sitter 分析器三阶段降级、
  Python SyntaxError，以及 `after_file` 在降级后继续执行。
- 增加源码架构门禁，禁止五语言分析器异常处理重新使用静默 `pass`。
- CI mypy 从单独 PHP 分析器扩展到整个 `src/analysis/analyzers/`，
  当前 CI 类型组 34 个文件、legacy 可见性组 11 个文件均为 0 错误。
- 2026-06-22 全量验证：`770 passed, 1 xfailed, 50 deselected`；
  O6 acceptance `30 passed`，性能结构门禁 `8 passed`，Ruff、格式与
  VS Code TypeScript 检查通过。

### O7 第六批：共享运行时与文件元数据可观测性

- Tree-sitter 线程 Parser 初始化失败新增结构化 debug 日志，不改变线程隔离与复用。
- IncrementalAnalyzer 的 Parser 初始化和源码解析失败不再静默返回。
- 新增共享 `get_file_size()`，ProjectScanner 文件发现和 LSP 大文件检查统一使用。
- 文件元数据不可读时记录组件、路径和异常，仍保持原有继续扫描行为。
- 新增 Parser 初始化、增量解析和文件元数据异常回归。
- `tree_sitter_runtime.py` 与 `core/file_metadata.py` 纳入 CI mypy，
  当前 CI 类型组 36 个文件、legacy 可见性组 11 个文件均为 0 错误。
- 2026-06-22 全量验证：`774 passed, 1 xfailed, 50 deselected`；
  O6 acceptance `30 passed`，性能结构门禁 `8 passed`，Ruff、格式与
  VS Code TypeScript 检查通过。

### O7 第七批：规则入口数据化与类型边界

- `get_default_rules_for_language()` 改为 `_DEFAULT_RULE_FACTORIES` 数据表，
  统一规则顺序、DSL 加载和 alias 规范化，减少五语言重复分支。
- 新增 `RuleDefinitionMap` 与 `RuleFactory` 类型别名，保留项目级 DSL
  预加载快照传递，并通过 CI mypy 验证规则工厂签名。
- `analyze_source()` 不再绕回 `analyze_python()` / `analyze_javascript()`
  等语言兼容 helper；标准化语言后直接进入 `_analyze_with()`。
- C/C++ 轻量兼容路径与 PHP AST 近邻去重后处理保持原行为。
- 新增架构门禁，防止统一生产入口重新委托到语言专用兼容 API。
- 2026-06-24 验证：`775 passed, 1 xfailed, 50 deselected`；
  O6 acceptance `30 passed`；CI mypy 36 个文件、legacy 可见性组 11 个文件
  均为 0 错误；Ruff 针对变更文件通过。

### O7 第八批：LSP 静默降级日志

- `_coerce_payload()` 在自定义 pygls payload 对象的 `items()` / `vars()`
  转换失败时记录 debug 级结构化日志，不再静默吞掉异常。
- `aegis.addToBaseline` 写入 baseline 后刷新 diagnostics 失败时记录
  `baseline_refresh_degraded`，仍保持 baseline 已写入且命令成功返回。
- 新增 2 个 LSP 回归测试，覆盖 payload 转换降级和未初始化 workspace
  造成的 baseline 刷新降级路径。
- 2026-06-24 验证：`777 passed, 1 xfailed, 50 deselected`；
  O6 acceptance `30 passed`；CI mypy 36 个文件、legacy 可见性组 11 个文件
  均为 0 错误；Ruff 针对变更文件通过。

### O7 第九批：Finding 模型坐标归一化

- `Finding.from_legacy_dict()` 新增共享坐标归一化 helper，
  将 legacy `related_locations` 中的空值、非法字符串、对象和负数统一收敛为 0。
- 移除 related location 坐标转换里的静默 `pass`；坏坐标不再导致整条
  related location 被丢弃，尽量保留污点来源和跨文件关联信息。
- 新增模型回归测试，覆盖非 dict 条目忽略、非法字符串和负数坐标归零。
- 2026-06-24 验证：`778 passed, 1 xfailed, 50 deselected`；
  O6 acceptance `30 passed`；CI mypy 36 个文件、legacy 可见性组 11 个文件
  均为 0 错误；Ruff 针对变更文件通过。

### O7 第十批：Benchmark 行号输入归一化

- `evaluate_project_against_ground_truth()` 的 ground-truth 行号解析提升为
  `_expected_ground_truth_lines()` 模块级 helper，去掉嵌套函数中的静默
  `pass`。
- `line_candidates` 和 `line` 统一只接受正整数行号；非法字符串、布尔值、
  非数字对象和非正数会被明确忽略，并对候选行去重保序。
- 新增 benchmark 回归测试，覆盖坏行号、重复行号和字符串行号的归一化。
- 2026-06-24 验证：`779 passed, 1 xfailed, 50 deselected`；
  O6 acceptance `30 passed`；CI mypy 36 个文件、legacy 可见性组 11 个文件
  均为 0 错误；Ruff 针对变更文件通过。

### O7 第十一批：主扫描链 mypy 门禁收口

- CI 类型组由逐个列举 scanner/core 文件改为覆盖整个 `src/scanner/`、
  `src/core/` 和 `src/worker_daemon.py`，避免模块间类型关系被
  `--follow-imports=skip` 隐藏。
- 整目录检查发现 `ProjectScanner.supported_extensions` 到
  `PerformanceOptimizer` 的真实泛型不变性问题；性能优化器只读参数改用
  `Mapping[str, str]`，允许共享的 `AnalysisLanguage` 映射安全传入。
- worker daemon 与 benchmark 的语言归一化边界显式返回
  `AnalysisLanguage | None`，并为跨模块返回值增加明确类型收敛。
- 已提升到 CI 的 scanner/core 文件从 `legacy-report` 去重；新增门禁测试，
  防止重新退回容易漏检的逐文件清单。
- 2026-06-29 验证：`779 passed, 1 xfailed, 50 deselected`；
  O6 acceptance `30 passed`；CI mypy 50 个文件、legacy 可见性组 5 个文件
  均为 0 错误；Ruff 全量 lint 与 VS Code TypeScript 检查通过。

### O7 第十二批：全仓 mypy 发布门禁

- CI mypy 目标从主扫描链扩大为整个 `src/`，当前覆盖 124 个 Python 源文件。
- 删除非阻断的 `legacy-report` 类型债务组及对应 CI artifact；所有源码类型错误
  现在都会直接阻断发布门禁，不再保留绕过路径。
- 新增门禁回归，固定 `src/` 全覆盖并禁止重新引入非阻断 legacy 类型组。
- 2026-07-08 复验：`780 passed, 1 xfailed, 50 deselected`；
  CI mypy 124 个源码文件 0 错误，Ruff lint 通过。

### O7 第十三批：弃用审计桥接层统一入口

- `rule_based_audit.audit_code_with_rules_only()` 从旧 AST + legacy regex 双扫描
  迁移到唯一生产入口 `analyze_source()`，主项目不再通过该桥接层调用 regex 引擎。
- 保留 1.4 兼容返回字段：`ast_count` 映射为统一规则数量、`regex_count` 固定为 0，
  同时新增语义明确的 `rule_count`；无扩展名输入继续按历史行为作为 Python 分析。
- 报告文案同步为“统一规则引擎”，新增防止 legacy 调用回流和无扩展名兼容回归。
- 2026-07-08 验证：定向回归 `23 passed`；全量
  `782 passed, 1 xfailed, 50 deselected`；O6 acceptance `30 passed`；
  Ruff lint、189 文件格式门禁与全仓 mypy 124 个源码文件均通过。

### O7 第十四批：C/C++ 生产分析路径解耦

- 新增独立 `analyzers/c_cpp_analyzer.py`，集中维护 C/C++ 的基础规则、
  上下文检查、误报过滤、去重和严重级别，不再从生产入口初始化旧多语言分析器。
- `analyze_c_cpp()` 直接调用维护中的 C/C++ 模块，删除旧 AST + regex 结果合并层；
  deprecated `security_rules` 兼容入口也改为复用新模块的上下文增强流程。
- 保持缓冲区溢出、格式化字符串、RCE、路径遍历、内存/释放、cin 和线程生命周期
  检测矩阵，并新增注释/字符串伪调用不告警的回归。
- 本机 500 次混合 C++ 样本微基准：新入口约 `0.066 s`，原双组件路径约
  `0.163 s`，约 `2.48x`；定向回归 `99 passed, 1 xfailed`。
- 2026-07-08 验证：全量 `795 passed, 1 xfailed, 50 deselected`；
  O6 acceptance `30 passed`；Ruff lint、191 文件格式门禁与全仓 mypy
  125 个源码文件均通过。

### O7 第十五批：移除最后一个生产 legacy regex 规则

- 删除 `SQLInjectionRegexRule`、`sql_injection/regex_rule.py` 及其包级公开导出；Python 默认规则
  工厂不再注册行级 legacy regex，统一使用 AST / taint 与声明式 DSL 路径。
- Python analyzer demo 改用 `PythonSQLInjectionAstRule`；新增架构门禁，要求六种生产语言的默认
  非 DSL 规则中不存在 `SQL_INJECTION_REGEX` 或 `regex_rule` 实现，并要求已删除模块不能回流。
- `%` 格式化 SQLi 的生产回归仍由 `SQL_INJECTION_PY_AST` 在原 sink 行检出。
- 对受控测试、核心源码、Flask 2.3.2、Django 3.2 做同源码差分：legacy 规则独有 26 条 finding，
  均来自测试/文档字符串或 Django 内部受控 SQL 标识符；其中 Django 独有 15 条，没有新增真实 TP。
- 删除后 Django 3.2 可追溯 ground truth 复跑为 SQL_INJECTION FP 7；项目总体仍为 TP 0、FP 136、
  FN 1、TN 7，剩余 PATH_TRAVERSAL FN 与其它类别 FP 保留给 O10 治理，不在 O7 静默处理。
- 全量验证：`809 passed, 1 xfailed, 50 deselected`；acceptance `30 passed`；
  规则/XSS 定向 `265 passed`；Ruff 通过，全仓 mypy 124 个源码文件 0 errors。
- 复验时修复 JavaScript XSS member call helper 的 `Node | None` 类型边界，不改变检测行为。
- 显式兼容测试 API `scan_code_locally()` 仍与生产入口隔离，最终废弃由 O10 兼容性清理统一处理；
  宽泛异常边界在第十六批收口。

### O7 第十六批：宽泛异常边界白名单

- 移除 `AIAnalyzer._call_ai_analysis()` 的兜底 `except Exception`；prompt 构造等内部编程错误不再
  伪装成 `provider_unavailable`，只有已分类的 gateway、解析、I/O 和数据错误转为结构化失败。
- corrupt baseline 的 UI 通知捕获从任意异常收窄为 `OSError / RuntimeError`，baseline 文件保护与
  用户提示行为保持不变。
- 全仓仅保留 5 个必要宽泛边界：CLI 顶层、worker request 顶层、LSP `scan_document()` 适配器、
  OpenAI-compatible SDK 适配器和第三方 provider fallback。后两者必须兼容可选 SDK / 插件的未知
  异常类型，并会立即分类或降级到下一个 provider。
- 新增 AST 架构门禁，精确锁定允许的文件与函数，并禁止全仓新增 bare `except`、
  `except BaseException` 或第 6 个 `except Exception`。
- 新增 AIAnalyzer 编程错误可见性回归；边界相关定向 `125 passed`。
- 2026-07-11 全量验证：`811 passed, 1 xfailed, 50 deselected`；Ruff 通过；
  全仓 mypy 124 个源码文件 0 errors。
- O7 仅余大型模块拆分；异常可观测性与宽泛捕获清理完成。

### O7 第十七批：AI 分析与本地修复职责拆分

- 将确定性的 C/C++ local replacement 常量、解析和 builder 从 `scanner/ai_analyzer.py` 迁到
  独立 `scanner/local_fix.py`；新模块不依赖 AI provider、gateway 或 `AIAnalyzer`。
- `AIAnalysisResult` 与公共 `build_local_fix_analysis()` 继续保留在原模块，LSP、扩展和既有调用方
  无需迁移；内部只通过 `_build_local_cpp_fix_replacement()` 单向调用本地修复模块。
- `ai_analyzer.py` 从 1536 行降至 1067 行；`local_fix.py` 为 474 行，职责限定为本地 C/C++ 修复。
- 新增架构门禁：AI orchestration 模块不得超过 1150 行、不得重新内联 local builder，
  `local_fix.py` 只能依赖 `re/dataclasses/typing` 标准库。
- 本地修复、AI provider 与 LSP 定向 `110 passed`；2026-07-11 全量
  `812 passed, 1 xfailed, 50 deselected`；Ruff 通过；全仓 mypy 扩展为 125 个源码文件 0 errors。
- `cross_file_analyzer.py`、`taint_analyzer.py` 保持单一分析引擎职责；`source_sink_registry.py`
  主要承载声明式规则数据；deprecated `security_rules.py` 留给 O10 兼容 API 清理。避免仅为减少行数
  引入跨模块共享可变状态或循环依赖。
- O7 所有验收项完成；后续架构变化继续由统一入口、类型、异常边界和模块体量门禁保护。

## O8：IDE 产品体验

**状态：已完成**

- [x] 扫描失败状态明确可见
- [x] 完善 Findings/Baseline 视图
- [x] AI 修复失败提示与重试
- [x] VS Code 端到端测试
- [x] 大型工作区启动与后台扫描优化

### O8 第一批：扫描失败状态可见且不误报“安全”

- LSP 失败后会清空旧 diagnostics，扩展端新增按 URI 保存的 `ScanFailureState`，防止随后
  的 diagnostics 事件将失败文件错误显示为 `Safe`。
- 状态栏现在显示 `Aegis: Scan failed`，tooltip 含规范化后的具体失败原因，点击仍可打开
  Aegis 输出日志。
- Findings 视图会显示最近一次当前文件扫描失败的原因；同一文件的下一次扫描开始或成功结束后
  才清除该状态，其他文件的失败不会污染当前文件。
- 新增 3 个 `scanFailureState` 回归，覆盖多行/缺失错误、按文件隔离，以及重新扫描后恢复。
- 2026-07-10 验证：`npm run check` 通过；`npm test` 通过（41 passing）。

### O8 第二批：AI 修复失败提示与重试

- 扩展端保留后端结构化失败语义：配置缺失会提供“打开 AI 设置”和“查看日志”，服务不可用、
  LSP 请求失败及未知服务错误会提供“重试”和“查看日志”。
- LSP 传输异常不再被误报为“AI 没有返回安全替换”，而是显示原始失败原因并允许重试。
- 重试复用原 finding 的 URI、规则、行范围与消息，不依赖重试时的当前编辑器或光标位置。
- `no_applicable_fix` 仍只显示信息，不提供无意义的重试入口。
- 新增 2 个 `aiFixResult` 回归；2026-07-11 验证：`npm run check` 通过，`npm test`
  通过（43 passing）。

### O8 第三批：Findings 严重度与状态一致性

- Findings 按严重度、行号和消息稳定排序；规则分组与文件分组同样严重度优先，避免高风险项被
  诊断到达顺序埋在列表后方。
- 规则和 finding 显示 Critical / High、Medium、Low、Info 安全语义标签与图标，文件节点显示
  finding 数量。
- 状态栏 fallback 现在统计所有 Aegis diagnostics；修复 Low / Info finding 在切换编辑器后被
  错误显示为 `Safe` 的问题。
- Findings provider 会在扩展释放时注销 diagnostics/editor 监听器，避免重复激活后的监听泄漏。
- 新增 3 个 `findingsTreeProvider` 回归；2026-07-11 验证：`npm run check` 通过，`npm test`
  通过（46 passing）。

### O8 第四批：Baseline 多工作区与坏条目可见性

- 单根工作区保持原有文件 → 规则 → 条目层级；多根工作区增加工作区根节点，分别展示每个
  `.aegis-baseline.json` 的 finding 数量和状态。
- Baseline 条目携带所属工作区根目录；移除 suppression 和随后复扫均使用该根目录，不再默认
  操作第一个 workspace folder。
- 监听 workspace folder 增删并即时刷新 Baseline roots，无需重载扩展。
- 格式合法但混有坏条目的 baseline 不再静默丢弃：视图显示无效条目数量和修复/重建提示，
  同时保留所有有效条目。
- Baseline 文件、规则节点显示 finding 数量；文件和规则顺序保持确定性。
- 新增 2 个 `baselineTreeProvider` 回归；2026-07-11 验证：`npm run check` 通过，`npm test`
  通过（48 passing）。Findings/Baseline 视图收尾完成。

### O8 第五批：后台工作区扫描与端到端完成语义

- `aegis/requestScanWorkspace` 由 pygls 工作线程执行，逐文件扫描不再占用 LSP 事件线程；编辑器
  请求可以在大型工作区扫描期间继续处理。
- 后端用非阻塞锁拒绝重叠 workspace scans，扩展端同样禁止第二次触发覆盖第一次的进度 Promise。
- 每轮扫描携带 scan ID；前端忽略上一轮迟到的进度，并按实际完成比例增量更新，不再因重复或
  跳号通知累计超过 100%。
- 工作区扫描改用 LSP request：流式通知负责进度，request response 负责最终完成。即使末条通知
  在初始化边界丢失，进度 UI 也不会永久悬挂。
- 手动文件/工作区扫描会等待 LSP 完成连接后再发请求，修复扩展已激活但通知 handler 尚未就绪的
  启动竞态。
- 新增 4 个进度状态机回归、1 个 pygls 后台 handler 回归，以及 1 个真实扩展宿主端到端测试。
  2026-07-11 验证：`npm run check` 通过，`npm test` 通过（53 passing）；
  `tests/test_lsp_server.py` 71 passed；Ruff lint/format 通过。
- VS Code 端到端测试项完成；大型工作区启动路径在第六批以 watcher 审计和结构门禁收尾。

### O8 第六批：大型工作区启动收尾

- 移除 LanguageClient 的 `**/*.{js,…}` 全工作区递归 watcher。后端没有注册
  `workspace/didChangeWatchedFiles`，原 watcher 只产生大型仓库启动和文件变更开销，没有功能消费方。
- 打开、修改与保存同步继续由完整的 10 语言 document selector 和 LanguageClient 文档同步负责；
  baseline 继续使用独立的窄范围 `**/.aegis-baseline.json` watcher。
- 客户端选项从大型 `extension.ts` 拆分为独立模块，新增结构门禁：10 种语言必须完整，初始化参数
  必须透传，递归源码 `synchronize.fileEvents` 必须保持为空。
- 与第五批的 LSP 后台 workspace scan、重入保护和 request 完成语义合并验收后，大型工作区不再
  在启动时注册无效源码树 watcher，手动全仓扫描也不再阻塞 LSP 事件线程。
- 2026-07-11 验证：`npm run check` 通过，完整扩展宿主 `npm test` 通过（54 passing）；
  打开/保存扫描、C++、remediation comment 和 workspace scan E2E 均通过。O8 全部完成。

## O9：生态与分发

**状态：进行中（O10 已完成）**

- [ ] PyPI 稳定发布
- [ ] VS Code Marketplace 稳定发布
- [x] DSL 规则编写与测试文档
- [x] 社区规则模板
- [x] 安全披露与贡献流程

### O9 第一批：社区规则与贡献入口

- 新增 `docs/technical/DSL_RULE_AUTHORING.md`，覆盖规则生成、schema、元变量约束、文件过滤、
  嵌入式 TP/TN、退出码、项目自动加载、DSL 能力边界和内置规则贡献流程；明确 DSL 是行级模式
  补充，复杂多行/跨函数 Source→Sink 应使用 AST/taint 规则。
- 新增可直接复制的 `templates/rules/community-rule.yaml`，包含不安全 `yaml.load` 的一个 TP 与两个
  TN；真实执行 `aegis rules test` 为 3/3 通过，并由 pytest 门禁持续验证。
- `aegis rules init` 规范化 `py/js/ts` 别名，并按规则类型校验可生成的语言组合；不再为 PHP XSS
  之类未实现的组合生成 Python 语义骨架，而是明确提示使用 `--type custom`。DSL schema 同时拒绝
  未支持语言、非标准 severity、空 patterns 和损坏正则，避免规则静默不加载或产生非法 finding。
- 新增根级 `CONTRIBUTING.md`、`SECURITY.md` 和 PR checklist，定义开发环境、规则 TP/TN 要求、
  全量检查、兼容性说明与私密安全披露流程；Issue 配置修复为当前 `HWZ-499/aegis-ai` 仓库和真实
  roadmap 路径，并增加 Security Policy 入口。
- 新增社区就绪结构门禁，锁定 README/文档索引、DSL 可执行契约、安全披露提示和 Issue 仓库链接。
  验证：核心 `835 passed, 50 deselected`，Ruff 通过，mypy 119 个源码文件 0 errors，发行一致性检查
  通过。PyPI 与 Marketplace 尚未执行外部发布，继续保留为 O9 后续任务。

## O10：稳定版

**状态：已完成**

- [x] DVWA、NodeGoat 干净版本可复跑基线
- [x] 其它真实项目按同一 provenance 口径复跑
- [x] 固化性能、准确率和内存指标
- [x] 升级与兼容性测试
- [x] 清理废弃接口
- [x] 稳定版本与维护策略

### O10 第一批：真实项目指标可追溯

- `scripts/benchmark/evaluate_project.py` 现在将引擎、扫描器提交、靶场提交、ground-truth
  路径和 SHA-256 写入 JSON 与 Markdown；非 Git 靶场会明确标记 revision unavailable。
- Ground truth 现在可用 `in_scope: false` 标记未承诺漏洞类别、第三方依赖漏洞或语义不匹配
  CVE。默认报告保留这些条目的原因但不把它们伪装成产品漏报；`--include-out-of-scope` 可复核
  全量原始口径。
- 每条标注还会校验当前靶场文件、行号与可选 `expected_pattern`；失效项会进入
  `invalid_entries`，默认不计入指标，并可由 `--include-invalid-ground-truth` 复核。Express
  4.18.1 的 OPEN_REDIRECT 标注已确认与当前靶场行号漂移，不作为规则漏报处理。
- 2026-07-10 基于 scanner `8c35f5f`、DVWA `33e364c`、ground-truth `ca7b1f6e…` 重跑：
  TP 23、FP 29、FN 0、TN 4，Recall 100.0%、Precision 44.2%、F1 0.61。PHP heredoc 内
  `document.location` → `document.write` 的 DOM XSS 已补齐；API 常量 `shell_exec` 标注已经源码
  核验并转为 RCE 负样本，不将其伪装成规则漏报。
- 同一 scanner 下 NodeGoat `c5cb68a`、ground-truth `dd5a5259…` 重跑：TP 12、FP 2、FN 0、
  TN 0，Recall 100.0%、Precision 85.7%、F1 0.92。JS/TS sink 只按真实 callee 识别，避免回调
  内的常量 `res.redirect` 被外层认证调用误匹配。
- README 已移除不同日期、不同扫描器版本混排的历史项目指标；只公开这一份可复跑基线。
- 规则强化优先级：P0 是已确认真实漏报（本轮已完成 NodeGoat HTTP 回调 XSS、DVWA heredoc DOM
  XSS）；P1 是 NodeGoat 剩余 NoSQL session 值与测试凭据发现的逐条归因和 TN fixture，禁止用
  路径级静默压低误报；P2 是为 Express、Flask、body-parser、Django 等其它靶场建立经文件/行号/模式
  校验的 ground truth，只有确认真实 FN 后才扩展规则。
- 下一步：按该优先级补真实 TN/TP 并重跑其它目标；Express 的失效 OPEN_REDIRECT 标注与 Flask
  的范围外硬编码凭据条目继续保留在 provenance 报告中，不误归因为扫描器漏报。

### O10 第二批：干净基线门禁与逐 finding 审计

- provenance 不再只记录 `HEAD`：报告同时记录 scanner/target dirty 状态；dirty 时对 tracked diff 与
  meaningful untracked 文件路径/内容生成 SHA-256。扫描器自产的 `.aegis-cache` 不算目标源码改动，
  真实 tracked 删除或其它 untracked 源码仍会使目标变脏。目标目录也不再意外借用父仓库 revision。
- 新增 `--require-clean`。正式基线只有在扫描器与目标均为可识别的干净 Git 工作区时才会产出，
  否则在扫描前以退出码 2 拒绝；当前 O7/O8/O10 尚未提交，因此本批复跑只写入临时候选目录，
  不覆盖正式 reports。
- 报告新增 Python/平台/处理器、扫描耗时、RSS 起止/增量和独立评估器进程生命周期峰值；每个
  TP/FP/FN/TN 也写入可审计明细，未匹配 finding 不再只计数而不展示。
- 支持 `--target-repository-root`：当评估对象是 mono-repo 子目录时，扫描范围保持在子目录，revision
  与 dirty 状态由显式仓库根提供。Java 反序列化 pilot 因此从错误的“扫描整个 security lab、只用
  2 条 Java 标注”修正为只扫描 `java-deserialization-demo`。
- 核验并纠正 ground truth：CVE-2022-24434 属于 dicer，CVE-2014-6394 属于 send，均不能把
  body-parser 1.20.0 源码当作 TP；Flask 2.3.2 已修复 CVE-2023-30861，该漏洞实际是缓存代理条件下
  缺少 `Vary: Cookie`，不是未设置 `SECRET_KEY`；Django CVE-2021-31542 按官方口径修正为 Low、
  3.2.1 修复并定位到实际 storage 代码。
- dirty-scanner 候选快照（仅用于治理，不可发布为稳定门槛）：DVWA 23/29/0/4、NodeGoat
  12/2/0/0、Go pilot 3/0/0/2、Java deserialization pilot 1/0/0/1；Django 为 0/136/1/7，
  Flask 为 0/10/0/1。body-parser 两条旧标注均转为范围外，Express 仍是 1 条范围外、1 条失效，
  两者目前没有可用于产品准确率的范围内正样本。
- 本机并行候选性能观测：DVWA 2.679 s / 55.320 MiB peak RSS，NodeGoat 0.246 s / 52.641 MiB，
  Django 38.811 s / 153.570 MiB，Flask 1.362 s / 70.324 MiB，Go 0.070 s / 48.207 MiB，
  Java 子项目 0.060 s / 47.930 MiB。正式性能阈值须在干净检查点上串行多轮采样后再固化。
- 回归验证：核心 `822 passed, 1 xfailed, 50 deselected`，Ruff 通过，mypy 125 个源码文件
  0 errors；VS Code TypeScript check 通过、扩展测试 54 passing。
- 废弃接口盘点确认 `security_rules.py` 已退出生产分析入口，但仍是 v1.4 兼容导出及 deprecated PHP
  类的依赖，不能在未声明 breaking change 时直接删除。生产扫描缓存版本哈希已停止读取该 100KB
  legacy 模块，只由当前 `analysis/rules/` 与自定义 DSL 规则变化触发失效；完整移除安排在稳定版兼容
  迁移与版本策略明确后执行。

### O10 第三批：clean-worktree 正式基线

- 在检查点 `d51bd8b` 上串行执行八个目标的 `--require-clean` 复跑，scanner 与 target 均为干净、
  可识别的 Git revision，所有 JSON 报告的 `provenance.reproducible` 均为 `true`。
- 正式准确率结果：DVWA 23/29/0/4，NodeGoat 12/2/0/0，Go pilot 3/0/0/2，Java
  deserialization pilot 1/0/0/1，Django 0/136/1/7，Flask 0/10/0/1。body-parser 无范围内
  标注；Express 的一条范围外、一条失效标注继续单列，不把 0 分解释为产品 Recall。
- 单轮串行观测：DVWA 2.566 s / 58.508 MiB peak RSS，NodeGoat 0.232 s / 53.020 MiB，
  Django 39.491 s / 141.875 MiB，Flask 1.194 s / 69.578 MiB，Go 0.066 s / 49.309 MiB，
  Java 子项目 0.067 s / 48.797 MiB。正式报告已归档到 `aegis-ai-core/scripts/reports/`。
- Java 使用父仓库的干净本地 clone，扫描范围仅为 `java-deserialization-demo`；没有修改原靶场中
  用户已有的 tracked `.class` 删除。
- 在同一 `d51bd8b` clean worktree 上完成每目标 3 轮串行采样，准确率计数三轮完全一致；
  `scripts/data/o10_stable_thresholds.json` 固化 target revision、ground-truth SHA-256、最低 TP/TN、
  最高 FP/FN、耗时与峰值 RSS 预算。耗时预算取至少 1 秒或观测最大值的 1.5 倍，RSS 预算取至少
  64 MiB 或观测最大值的 1.25 倍。
- 评估器新增 `--thresholds`：自动要求 clean provenance，目标或 ground truth 漂移、质量计数回退、
  耗时或内存超预算时将 violations 写入 JSON/Markdown 并以退出码 3 失败。提交 `a41f754` 上八目标
  实跑全部 gate passed；Django 39.763 秒 / 143.238 MiB，低于 61 秒 / 180 MiB 预算。

### O10 第四批：运行时与发行包兼容性

- 新鲜 Python 3.13 环境验证确认 `tree-sitter-languages` 尚无可安装发行版；项目原来的
  `requires-python >=3.10` 会错误承诺 3.13 支持。核心、README、扩展配置与启动探测统一收口为
  Python 3.10–3.12，3.13 在创建 managed venv 前返回明确错误。
- Security Scan CI 新增 Python 3.10/3.11/3.12 全量测试矩阵，以及 Node 20/22/24 扩展类型检查矩阵；
  weekly real-world workflow 改用 `pip install -e ".[dev]"`，不再依赖不完整的 requirements 手工补包。
- `requirements.txt` 补齐核心 `pydantic-settings` 与 `pyyaml`；release consistency gate 现在同时校验
  Python 下限和上限是否有文档，防止未来再次把支持范围写宽。
- wheel 在隔离环境成功构建、安装与启动 CLI，METADATA 为 `Requires-Python: <3.13,>=3.10`；
  `project.license` 迁移到 SPDX 字符串并移除废弃 classifier，构建不再产生 setuptools license
  deprecation。删除仓库中陈旧的 1.3.0 `egg-info/PKG-INFO` 并统一忽略生成元数据。
- 验证：Python 3.11 核心 `823 passed, 1 xfailed, 50 deselected`；Python 3.13 安装按预期在元数据
  检查阶段拒绝；VS Code TypeScript check 通过、扩展测试 55 passing；四份 workflow YAML 可解析。

### O10 第五批：v1.5 废弃接口移除

- 核心版本进入 `1.5.0.dev0`，兑现自 1.2 起声明的 v1.5 移除窗口；正式 `1.5.0` 留给下一批稳定
  版本与维护策略验收，避免以 1.4.0 版本号构建已经移除 1.4 兼容 API 的发行包。
- 删除 Python-only `ast_analyzer.py`、通用 `security_rules.py`、旧报告桥 `rule_based_audit.py` 以及
  依赖旧 `PhpTaintGraph` 的 `rules/php/`；`rule_engine` 与 `rules` 命名空间不再导出旧函数、特征库
  常量或 `Php*Rule` 类。
- `multi_language_ast.py` 从近 900 行独立解析/正则实现缩为统一 `analyze_source()` 的薄兼容适配器；
  不支持的语言不再进入跨语言通用正则兜底。CLI、LSP、ProjectScanner 与兼容调用方现在共享同一
  分派和 finding 口径。
- 删除无生产调用方、仍配置旧正则签名的 `scanner.rule_config`；自定义规则统一使用
  `.aegis/rules` YAML DSL、`aegis rules init/test` 与 `--rules-dir`。
- 新增删除状态、导出表与适配器依赖门禁，并发布 `V1_5_MIGRATION.md` 迁移映射；旧 AST/regex
  双引擎测试改为统一入口、finding schema 与未知语言边界测试。
- wheel 复验发现本地陈旧 `build/lib` 可让 setuptools 把已删除源码重新打包；新增
  `scripts/check_distribution.py`，PyPI workflow 在 `twine check` 前同时检查 wheel/sdist，发现任一
  已退役模块即拒绝发布。
- 验证：核心 `818 passed, 50 deselected`；Ruff 通过；mypy 119 个保留源码文件 0 errors；干净目录
  wheel 为 `aegis_ai_core-1.5.0.dev0` 且发行内容门禁通过；bundled backend 重建后 TypeScript check
  通过、扩展测试 55 passing。

### O10 第六批：稳定版本与维护策略

- Core 元数据从 `1.5.0.dev0` 冻结为稳定 `1.5.0`，classifier 更新为 Production/Stable；新增 Core
  与 VS Code 独立 changelog，扩展 README 原先指向的缺失 changelog 已补齐。PyPI/Marketplace 的
  实际发布仍属于 O9，本批只准备可发布的稳定源码与制品口径。
- 新增 `docs/MAINTENANCE.md`：Core 与扩展分别遵循 Semantic Versioning；最新 Core minor 获得正常
  修复、上一 minor 提供 90 天关键/安全修复窗口；明确 Python/Node 支持矩阵、兼容与弃用约束、
  质量门禁、阈值变更规则和发行节奏。
- 修复发布 tag 冲突：PyPI 不再与扩展共同监听 `v*`。Core 只监听 `core-v*`，扩展只监听
  `vscode-v*`；`check_release_tag.py` 要求 tag 与 `pyproject.toml` / `package.json` 的稳定 `X.Y.Z`
  完全一致，交叉组件 tag、版本漂移和 prerelease 元数据都会失败。
- 发行一致性门禁新增 changelog 版本与维护政策检查，并移除 Python 3.11-only `tomllib` 依赖，
  保持脚本在支持的 Python 3.10–3.12 范围内仅使用标准库。当前机器未安装 Python 3.10，本地以
  3.11 验证，3.10/3.12 继续由 CI matrix 执行。
- VSIX 实包审计发现扩展根 `.pytest_cache` 会被默认打包；`.vscodeignore` 现统一排除 pytest/mypy/
  Ruff 缓存，发行内容门禁扩展到 VSIX，并在 artifact 上传前执行。复验 VSIX 从 143 个文件降至
  139 个文件（约 520 KiB），包含 changelog 与 Core 1.5.0，不含缓存或已退役 backend 模块。
- 验证：核心 `823 passed, 50 deselected`，Ruff 通过，mypy 119 个源码文件 0 errors；Core 与扩展
  精确 tag 门禁通过；干净构建生成 `aegis_ai_core-1.5.0-py3-none-any.whl`，Version 1.5.0、
  Production/Stable、`Requires-Python <3.13,>=3.10` 且内容门禁通过；bundled backend 携带 Core
  1.5.0，TypeScript check 通过，扩展宿主 55 passing。O10 全部完成，下一阶段进入 O9。

## 更新记录

| 日期 | 更新 |
|---|---|
| 2026-07-12 | O9 第一批：发布 DSL 规则创作/测试指南、可执行社区规则模板、贡献指南、安全策略与 PR 门禁；修复旧 Issue 链接，强化规则模板语言组合和 DSL schema 校验；核心 835 tests 通过，O9 进入进行中。 |
| 2026-07-12 | O10 第六批并完成阶段：Core 冻结为稳定 1.5.0，发布维护政策与双组件 changelog；拆分 `core-v*` / `vscode-v*` 发布 tag 并增加精确版本门禁，修复 release checker 的 Python 3.10 兼容性及 VSIX 缓存污染；稳定 wheel、核心 823 tests 与扩展 55 tests 全部通过。 |
| 2026-07-12 | O10 第五批：核心进入 `1.5.0.dev0`，移除已过弃用窗口的旧 AST/regex/PHP/报告接口与孤立正则配置器，多语言兼容层统一委托 `analyze_source()`，补迁移文档和防回流门禁；废弃接口验收完成。 |
| 2026-07-12 | O10 第四批：Python 支持范围收口为 3.10–3.12，新增 Python/Node CI 矩阵、3.13 启动前拒绝、wheel 隔离安装和发行元数据验证；升级与兼容性验收完成。 |
| 2026-07-12 | O10 第三批：创建 `d51bd8b` 稳定检查点，八个真实目标通过 clean provenance 复跑；3 轮串行采样固化质量/耗时/RSS 预算，`a41f754` 上八目标机器门禁全通过，前三项 O10 验收完成。 |
| 2026-07-11 | O10 第二批：provenance 增加 dirty/diff 指纹与 `--require-clean`，报告加入耗时、RSS、运行环境和逐 finding 审计；纠正 body-parser/Flask/Django 的错误 CVE 标注及 Java mono-repo 扫描范围，完成八目标 dirty-scanner 候选复跑。 |
| 2026-07-11 | O7 第十七批并完成阶段：C/C++ local fix 从 AI orchestration 拆出为零 provider 依赖模块，主模块 1536→1067 行并增加依赖/体量门禁；全量 812 passed、mypy 125 文件清零。 |
| 2026-07-11 | O7 第十六批：内部宽泛捕获收窄，全仓仅保留 CLI/daemon/LSP/SDK/plugin 5 个显式边界并用 AST 门禁锁定；全量 811 passed、mypy 清零。 |
| 2026-07-11 | O7 第十五批：删除最后一个生产可达的 `SQLInjectionRegexRule`，Python SQLi 统一到 AST/taint/DSL；差分移除 26 条独有误报候选，Django SQLi FP 复跑为 7；全量 809 passed、acceptance 30 passed、mypy 清零。 |
| 2026-07-11 | O8 大型工作区启动收尾并完成阶段：移除无消费方的递归源码 watcher，固化 10 语言 document selector 与零递归 watcher 门禁；扩展测试 54 passing。 |
| 2026-07-11 | O8 后台扫描与 E2E：workspace scan 移出 LSP 事件线程，增加重入保护、scan ID、request 完成兜底和连接就绪等待；扩展 53 passing、LSP 71 passed。 |
| 2026-07-11 | O8 Baseline 视图收尾：支持多根工作区隔离、动态 roots、坏条目警告与层级数量；移除/复扫使用条目所属根目录；扩展测试 48 passing。 |
| 2026-07-11 | O8 Findings 视图增强：严重度优先稳定排序、层级数量与安全语义标签；状态栏统计 Low/Info finding，不再错误显示 Safe；扩展测试 46 passing。 |
| 2026-07-11 | O8 AI 修复失败体验完成：配置错误可直达设置，服务/传输错误可复用原 finding 重试并查看日志；扩展测试 43 passing。 |
| 2026-07-10 | 规则强化：JS/TS sink 改为按真实 callee 匹配，消除回调中常量跳转的 NodeGoat 误报；PHP heredoc 增加 `document.location` → `document.write` DOM XSS 检测；核验并修正 DVWA 常量命令的 RCE 标注。重跑后 DVWA 为 23/29/0/4（F1 0.61），NodeGoat 为 12/2/0/0（F1 0.92）。 |
| 2026-07-10 | 评估器增加文件、行号与可选代码模式的 ground-truth 有效性校验；Express 4.18.1 的开放重定向标注确认与当前靶场漂移，单列为 invalid 而非规则漏报。 |
| 2026-07-10 | 修正 Git 全局代理端口至 SakuraCat 监听的 7897，拉取并复跑 NodeGoat；修复 HTTP 回调响应体直接写入 `res.write` 的 XSS 漏报，新增正/负样本并更新可复跑质量基线。 |
| 2026-07-10 | O10 ground-truth 增加显式范围语义：外部依赖、未承诺类别和规则语义不匹配项在报告中可审计地排除，保留 `--include-out-of-scope` 全量复核入口；Express/Flask 复跑建立下一轮真实误报/漏报治理起点。 |
| 2026-07-10 | 启动 O10：项目评估报告新增 scanner/target revision 与 ground-truth SHA-256；在固定 DVWA 输入上重跑并更新公开指标，O7 与 O10 按既定优先级并行。 |
| 2026-06-20 | 建立 O1–O10 统一路线图；写入强制文档同步规则；同步 O1–O5 当前状态、O4 收尾清单和 O5 基准。 |
| 2026-06-20 | O4 收尾实现：SARIF Code Flow 结构化测试、路径/位置规范化、四格式 CLI E2E、CI 严格 SARIF 校验和验证指南已完成，等待全量测试。 |
| 2026-06-20 | O4 全量验收通过并标记完成：678 passed；真实 SARIF 输出与 ruleId 映射校验通过。开始 O5 并发缓存写入与中断恢复。 |
| 2026-06-20 | O5 原子缓存写入完成：并发写入、中断恢复、临时文件清理通过；全量 681 passed。开始性能回归门禁。 |
| 2026-06-20 | O5 性能回归门禁完成：新增结构性操作预算，并在 CI 保存 pytest-benchmark JSON 趋势 artifact。 |
| 2026-06-20 | O5 真实项目基准完成：118 文件，顺序/4 线程结果一致，记录时间与峰值内存；全量 683 passed。 |
| 2026-06-20 | O5 LSP/CLI 一致性验证完成：函数级增量合并结果与 LSP 全量、CLI 单文件结果一致。 |
| 2026-06-21 | O5 全量稳定验收通过：684 passed，Ruff、格式、CI 类型门禁与 VS Code TypeScript 检查通过；稳定检查点待提交。 |
| 2026-06-21 | 启动 O6：统一 186 个规则样本的 TP/TN/FP/FN 统计，新增语言×漏洞类型矩阵和严格不可下降门禁；当前 104 TP、82 TN、0 FP、0 FN。 |
| 2026-06-21 | PHP RCE/XSS 收敛到 AST-only：补反引号、动态调用、print/短 echo/die 等覆盖；质量矩阵扩展为 195 样本、109 TP、86 TN、0 FP、0 FN。 |
| 2026-06-21 | SSRF 扩展为五语言统一覆盖，并补反序列化/开放重定向边界样本；质量矩阵扩展为 207 样本、115 TP、92 TN、0 FP、0 FN。 |
| 2026-06-21 | 完成 Python/JavaScript 一跳跨文件参数 → Sink 传播：统一函数摘要、ESM/CommonJS/默认导出、CLI/LSP/项目扫描入口；全量 732 passed，下一步为返回值与多跳传播。 |
| 2026-06-22 | 完成返回值摘要、Python/ESM/CommonJS 重导出和固定点多跳调用链传播；跨文件项目级回归增至 10 个，全量 737 passed，O6 验收完成并进入 O7。 |
| 2026-06-22 | O7 第一批完成：统一语言识别与 `analyze_source()` 生产入口，迁移六类调用方并增加架构门禁；cross-file 提升到 CI mypy，两个类型组均清零；全量 747 passed。 |
| 2026-06-22 | O7 第二批完成：统一全量/增量扫描会话，异常路径释放 DSL/源码快照，同时保留磁盘缓存与 Parser 跨轮复用；新增生命周期回归与性能不变量验证，全量 749 passed。 |
| 2026-06-22 | O7 第三批完成：移除 CLI/ProjectScanner 可达的 legacy AST+Regex 引擎，保留 `--engine new` 命令兼容并明确拒绝 legacy；增加不可回流门禁。 |
| 2026-06-22 | O7 第四批完成：迁移 DVWA 剩余 4 个 PHP SQLi regex 缺口并删除 PHP 生产补充层；183 个真实目标 PHP 文件 AST-only 集合一致，DVWA 指标不变，全量 756 passed。 |
| 2026-06-22 | O7 第五批完成：统一五语言分析器 parse/taint/traverse 降级日志，移除静默异常并将整个 analyzers 目录纳入 CI mypy，全量 770 passed。 |
| 2026-06-22 | O7 第六批完成：Tree-sitter/增量 Parser 与 ProjectScanner/LSP 文件元数据降级可观测，CI mypy 扩展到 36 个文件，全量 774 passed。 |
| 2026-06-24 | O7 第七批完成：规则注册表数据化、`analyze_source()` 直接进入统一执行器，并新增防止回退到语言兼容 helper 的架构门禁；全量 775 passed。 |
| 2026-06-24 | O7 第八批完成：LSP payload 转换与 baseline 刷新失败不再静默，新增 debug 降级日志和 2 个回归测试；全量 777 passed。 |
| 2026-06-24 | O7 第九批完成：Finding legacy related location 坐标统一归一化，移除静默跳过坏坐标导致的关联信息丢失；全量 778 passed。 |
| 2026-06-24 | O7 第十批完成：benchmark ground-truth 行号解析模块化，非法候选值显式忽略并去重保序；全量 779 passed。 |
| 2026-06-29 | O7 第十一批完成：CI mypy 扩展为整个 scanner/core 与 worker daemon，修复语言映射到性能优化器的泛型边界；CI 类型组增至 50 文件，全量 779 passed。 |
| 2026-07-08 | O7 第十二批完成复验：mypy 发布门禁扩大到全仓 `src/` 共 124 个源码文件，删除非阻断 legacy 类型报告逃生口；全量 780 passed。 |
| 2026-07-08 | O7 第十三批完成：弃用审计桥接层迁移到统一 `analyze_source()`，移除其 legacy regex 运行路径并保留返回兼容性；全量 782 passed。 |
| 2026-07-08 | O7 第十四批完成：C/C++ 生产入口脱离旧多语言与正则引擎，独立基础规则保持检测矩阵并将微基准提升约 2.48 倍；全量 795 passed。 |
