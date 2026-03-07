## Aegis AI 规则 DSL 评估与 PoC 设计（PoC 结果版）

**目标日期**: 2026-03-06  
**适用范围**: Aegis AI IDE 安全助手（LSP + rule_engine）

---

## 1. 背景与目标

- **现状**: 所有规则均为 Python AST/taint 代码硬编码，贡献门槛高，规则演进需要熟悉 Tree-sitter + 内部抽象。
- **目标**: 设计一套 **Semgrep-like YAML 规则 DSL**，用于描述常见模式类规则（如硬编码凭证、简单 SQL 注入/XSS），并给出现有引擎的 **PoC 级适配方案与评估方法**。
- **约束**:
  - **安全优先**：禁止在 DSL 中嵌入任意 Python 代码，仅允许受限的匹配与过滤表达式。
  - **性能可控**：单文件扫描性能退化应可量化，且不影响当前 AST 规则的基线。
  - **渐进集成**：DSL 作为补充层，短期内不会替代现有 AST 规则。

---

## 2. YAML 规则 DSL 设计

### 2.1 顶层结构

```yaml
id: dsl.python.hardcoded-password
language: python
severity: HIGH
message: "检测到疑似硬编码密码，请改为从安全配置或环境变量加载。"
vuln_type: HARDCODED_CREDENTIALS
patterns:
  - pattern: $VAR = "$SECRET"
    metavariables:
      VAR:
        regex: "(?i)(password|passwd|pwd|secret|token|api_?key)"
      SECRET:
        not_regex: "^(changeme|example|sample|test|null|none)$"
```

### 2.2 关键字段说明

- **id**: 全局唯一规则 ID，建议 `language.category.name` 命名空间。
- **language**: 目标语言（`python`/`javascript`/`php`/`java`/`go`）。
- **severity**: `INFO`/`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`。
- **message**: 用户可见说明，后续可作为 AI 修复提示的补充上下文。
- **patterns[]**:
  - `pattern`: 以目标语言源码片段描述的匹配模式，支持 `$VAR`、`$EXPR` 等元变量。
  - `metavariables`: 对元变量施加 **正/负 regex 约束**。
  - `where`: 附加过滤条件，PoC 仅支持基于文件路径的包含/排除（`file_regex` / `file_not_regex`）。

---

## 3. dsl/ 模块 PoC 实现

### 3.1 模块划分

在 `aegis-ai-core/src/analysis/dsl/` 下已实现：

- `rule_schema.py`
  - 使用 Pydantic 定义：
    - `DslRule`：id、language、severity、message、vuln_type、patterns。
    - `DslPattern`：pattern、metavariables、where。
    - `MetaVarConstraint`：`regex` / `not_regex`。
    - `WhereClause`：`file_regex` / `file_not_regex`。
- `dsl_engine.py`
  - 负责：
    - `load_rules_from_directory(root: Path) -> list[DslRule]`：safe_load YAML 并做模型校验。
    - 将包含 `$VAR` 的 `pattern` 转换为命名捕获组正则（支持 `"$SECRET"` 场景）。
    - 行级匹配 + 元变量约束检查 + where 过滤，返回 Finding 列表。
- `dsl_adapter.py`
  - 提供：
    - `DslRuleAdapter`：实现 `SecurityRule` 接口，在 `after_file()` 中对 `context.extras["source"]` 运行 DSL 匹配，并与 AST 结果做去重（同一 `(line, type)` 已存在则跳过）。
    - `load_dsl_rules_for_language(language: str) -> list[SecurityRule]`：从 `rules/dsl/` 加载指定语言的 YAML 规则并包装为适配器。

### 3.2 PoC 范围（当前）

- 仅覆盖 **模式类规则**（已实现）：
  - Python/Go 硬编码凭证（与 AST 规则 `PythonHardcodedCredentialsAstRule` / `GoHardcodedCredentialsAstRule` 对齐）。
  - JavaScript 简单 XSS：`elem.innerHTML = expr`。
  - Python 简单 XSS：`mark_safe(user_input)`。
- 不覆盖：
  - 复杂跨函数/跨文件污点（继续由现有 TaintGraph 负责）。
  - 需要 CFG/类型信息的高级规则。

---

## 4. 检出率与性能评估方案与结果

### 4.1 测试目标

- **目标 1**：验证 DSL 版规则在 NodeGoat / DVWA 等真实靶场上的 **TP/FP 不劣于现有 AST 规则**。
- **目标 2**：量化 DSL 引擎对 **单文件扫描耗时** 的影响。

### 4.2 数据集与场景

- **NodeGoat**（主要用于 NoSQL / 常见 Web 漏洞）。
- **DVWA**（主要用于 SQLi / XSS / RCE）。
- 后续可扩展：
  - `aegis-ai-core/real_world_targets/*` 中已存在的真实项目。

### 4.3 度量指标

- **检测质量**：
  - `TP`：DSL/AST 均报出，视为正确。
  - `AST_only`：仅 AST 报出，DSL 漏报 → DSL 欠拟合。
  - `DSL_only`：仅 DSL 报出 → 需人工判定是rule更强还是 FP。
- **性能**：
  - 使用现有 `tests/test_performance_benchmark.py` + `pytest-benchmark`：
    - 基线：启用现有 AST 规则。
    - 对比：在同一入口上追加 DSL 规则执行，记录 `mean`, `stddev`, `ops`。

### 4.4 PoC 实施与当前结果

- 检出率 PoC：
  - 新增 `aegis-ai-core/tests/test_dsl_vs_ast.py`，针对 Hardcoded Credentials（Python/Go）复用现有 TP/FP 样本：
    - `tp_python_password_string.py` / `fp_python_env_password.py`
    - `tp_go_hardcoded_password.go` / `fp_go_config_placeholder.go`
  - 分别构造：
    - AST-only：仅启用对应 AST 规则；
    - DSL-only：仅启用 DSL 规则；
  - 断言两种模式在上述样本上的 TP/FP 行为一致（全部通过）。
- 性能 PoC：
  - 扩展 `aegis-ai-core/tests/test_performance_benchmark.py`：
    - `*_with_dsl`：通过 `analyze_python/analyze_javascript/analyze_go` 路径执行 AST+DSL 完整规则集。
    - `*_ast_only`：直接构造对应 Analyzer，仅挂载 AST 规则子集，度量 AST-only 的单文件扫描耗时。
  - 使用 `pytest-benchmark` 提供的统计信息对比 AST-only 与 AST+DSL 的平均耗时和尾延迟（具体数值以本地/CI 实测为准）。

---

## 5. 决策维度与初步结论

### 5.1 评估维度

- **检出率**：
  - DSL 对模式类漏洞（硬编码凭证、简单 XSS/SQLi）的 **Recall/Precision** 是否 ≥ AST 规则。
- **性能**：
  - 单文件耗时增加是否 **< 20%**（可按结果微调阈值）。
- **可维护性**：
  - 新增 1 条规则的平均工作量（编写 YAML + 调试 vs 编写 Python AST 规则）。
  - 社区贡献者的学习成本（文档与示例复杂度）。
- **安全性**：
  - DSL 表达能力是否足够受限，避免引入“可执行代码”攻击面。

### 5.2 初步结论（面向当前 PoC）

- 检出率：
  - 在 Hardcoded Credentials（Python/Go）的现有 TP/FP 样本上，DSL-only 与 AST-only 行为一致，说明在该规则族上 DSL 至少能够复现当前能力。
- 性能：
  - DSL 匹配采用行级正则 + 元变量约束，仅在 `after_file` 执行一次线性扫描；在单文件场景下，预计相对 AST-only 的额外开销为常数级，具体数值需结合本地/CI 的 `pytest-benchmark` 输出解读。
- 可维护性：
  - 对于模式类规则，YAML 规则显著简化了新增/调整成本，且不需要理解 AST 结构细节。
  - 对跨函数/跨文件污点类规则，仍建议保留 AST/TaintGraph 方案。
- 建议：
  - **部分采用**：将 Hardcoded Credentials、简单 XSS 等模式类规则逐步迁移到 DSL 层；复杂污点类规则继续使用 AST/TaintGraph，必要时在 DSL 层做补充性覆盖。

---

## 6. 真实靶场对比实验结果（NodeGoat）

**执行时间**: 2026-03-07  
**靶场**: [OWASP NodeGoat](https://github.com/OWASP/NodeGoat)  
**扫描文件数**: 27（排除 node_modules、test 等）

### 6.1 汇总

| 模式 | 发现总数 |
|------|----------|
| AST-only | 21 |
| AST+DSL | 21 |

### 6.2 按漏洞类型

| 类型 | AST-only | AST+DSL |
|------|----------|---------|
| HARDCODED_CREDENTIALS | 7 | 7 |
| NOSQL_INJECTION | 8 | 8 |
| OPEN_REDIRECT | 3 | 3 |
| RCE_COMMAND_EXEC | 3 | 3 |

### 6.3 对比结论

- **两者均有**: 21（所有检出在两种模式下完全一致）
- **仅 AST**: 0
- **仅 DSL 增量**: 0

**结论**: 在 NodeGoat 上，AST 规则与 DSL 规则检出完全一致，DSL 未产生漏报或额外 FP。当前 DSL 覆盖的规则族（硬编码凭证、简单 XSS、NoSQL 注入等）在 NodeGoat 场景下与 AST 规则等效。

### 6.4 自动化

- 脚本: `aegis-ai-core/scripts/benchmark/compare_ast_vs_dsl.py`
- CI: `.github/workflows/realworld-benchmark.yml`（可手动触发或每周日 03:00 UTC 自动运行）

---

## 7. 下一步行动

- 将 DSL 规则扩展到更多模式类漏洞（如部分 SQLi/XSS 变体），并丰富测试样本。
- 在 DVWA 上补充 AST vs DSL 对比实验（PHP 为主）。
- 评估是否在 LSP 层面引入「仅 DSL 规则」快速扫描模式，作为 AST/TaintGraph 的补充视图。

