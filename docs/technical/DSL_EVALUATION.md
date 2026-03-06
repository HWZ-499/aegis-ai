## Aegis AI 规则 DSL 评估与 PoC 设计（草案）

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

## 2. YAML 规则 DSL 初稿

### 2.1 顶层结构

```yaml
id: python.hardcoded-password
language: python
severity: HIGH
message: "检测到疑似硬编码密码，请改为从安全配置或环境变量加载。"

rules:
  - pattern: |
      $VAR = "$SECRET"
    metavariables:
      VAR:
        regex: "(?i)(password|passwd|pwd|secret|token|api_?key)"
      SECRET:
        # 明确排除占位符、空值等
        not_regex: "^(changeme|example|sample|test|null|none)$"
    where:
      - not:
          file:
            regex: "(?i)test|fixture"
```

### 2.2 关键字段说明

- **id**: 全局唯一规则 ID，建议 `language.category.name` 命名空间。
- **language**: 目标语言（`python`/`javascript`/`php`/`java`/`go`）。
- **severity**: `INFO`/`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`。
- **message**: 用户可见说明，后续可作为 AI 修复提示的补充上下文。
- **rules[]**:
  - `pattern`: 以目标语言源码片段描述的匹配模式，支持 `$VAR`、`$EXPR` 等元变量。
  - `metavariables`: 对元变量施加 **正/负 regex 约束**。
  - `where`: 附加过滤条件，PoC 仅支持：
    - `file.regex`: 基于文件路径的包含/排除。
    - `not`/`any`/`all` 组合。

---

## 3. dsl/ 模块 PoC 设计

### 3.1 模块划分

在 `aegis-ai-core/src/analysis/dsl/` 下新增：

- `rule_schema.py`
  - 使用 **Pydantic** 定义 YAML 规则模型：
    - `DslRule`：单条规则（id、language、severity、message、patterns）。
    - `DslPattern`：包含 `pattern`、`metavariables`、`where`。
    - `MetaVariableConstraint`：`regex` / `not_regex`。
- `dsl_engine.py`
  - 负责：
    - 从 YAML 文件/目录加载并校验 `DslRule`。
    - 将 `pattern` 转换为 Tree-sitter 查询或简化文本模式（PoC 阶段可先用 **行级正则+简单 AST 上下文**）。
    - 执行匹配并生成统一的 `Finding` dict。
- `dsl_adapter.py`
  - 提供：
    - `make_dsl_rule_wrappers(rules: list[DslRule]) -> list[SecurityRule]`
      - 将 DSL 规则包装为实现 `SecurityRule` 接口的轻量适配器。
    - （可选）`load_default_dsl_rules(language: str)`：加载 `rules/dsl/<language>/*.yaml`。

### 3.2 PoC 范围（建议）

- 仅覆盖 **模式类规则**：
  - Python/Go 硬编码凭证（与现有 AST 规则对齐）。
  - JavaScript/Python 简单 XSS 模式（如 `innerHTML = userInput` / `mark_safe(user_input)`）。
- **不覆盖**：
  - 复杂跨函数/跨文件污点（仍由现有 TaintGraph 负责）。
  - 需要 CFG/类型信息的高级规则。

---

## 4. 检出率与性能评估方案

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

### 4.4 实施步骤（PoC）

1. 在 `scripts/benchmark/` 下新增一个 PoC 脚本（后续实现时按此方案）：
   - 对 NodeGoat / DVWA 的固定文件集跑两轮：
     - 仅 AST 规则。
     - AST + DSL 规则。
   - 输出 JSON 报告：
     - `{"file": "...", "ast_findings": N1, "dsl_findings": N2, "overlap": N3, "benchmark": {...}}`
2. 使用 `pytest-benchmark` 记录多轮运行结果，比较 **99 分位耗时** 与 **平均耗时**。

---

## 5. 决策维度与结论模板

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

### 5.2 决策文档结构（本文件后续演进为正式结论）

后续在完成 PoC 与 benchmark 之后，将本文件补充为正式决策文档，结构建议：

1. **背景与目标**（本节已有）
2. **DSL 设计与实现概览**（基于第 2-3 节）
3. **实验设置**：
   - 数据集、评估脚本、规则列表。
4. **结果对比**：
   - 检出率表格（AST vs DSL）。
   - 性能基准对比（基于 pytest-benchmark）。
5. **优劣分析**：
   - 典型成功/失败样例。
6. **最终建议**：
   - **全面采用**：将模式类规则迁移至 DSL，AST 规则仅保留复杂场景。
   - **部分采用**：仅对硬编码凭证、部分 XSS/SQLi 使用 DSL。
   - **不采用**：保持当前 AST 方案，仅作为设计实验归档。

---

## 6. 下一步行动（供后续实现使用）

- 在 `src/analysis/dsl/` 下按本设计创建 `rule_schema.py` / `dsl_engine.py` / `dsl_adapter.py` 骨架，并配套最小 PoC 规则。
- 在 `docs/technical/` 下维护 DSL 规则示例与贡献指南。
- 等 PoC 与 benchmark 完成后，将本文件从“草案”更新为正式的 `DSL_EVALUATION` 决策文档。

