# 添加新语言支持（标准化 Checklist）

本文档描述在 Aegis-AI 中接入一门新语言（如 Java、Go）的完整步骤，确保不遗漏任何环节。

## 前置条件

- 已有语言（Python、JavaScript/TypeScript、PHP）的规则与污点分析可作为参考。
- 新语言需在 `tree-sitter-languages` 或自建 Tree-sitter 语法中提供解析器。

---

## Checklist（按顺序执行）

### 1. 污点分析器：节点类型映射

**文件**: `aegis-ai-core/src/analysis/taint/taint_analyzer.py`

- 在 `TaintAnalyzer.__init__` 中为 `language="<lang>"` 加载对应 Tree-sitter 语言（`get_language("<lang>")`）。
- 在 `_collect_assignments` 中增加新语言的赋值节点类型（如 `assignment_expression`、`variable_declaration` 等），并实现 `_process_<lang>_assignment`，将变量名与右值注册到 `_variables` 与 `self.graph`。
- 在 `_identify_sources_and_sinks` 中增加新语言的调用/成员节点类型（如 `call_expression`、`function_call_expression`、`member_expression` 等），确保 `_check_call_expression` / `_check_member_expression` 能命中。
- 若参数为变量，在 `_check_single_argument` 中支持该语言的标识符节点类型（如 `identifier`、`variable_name`），以便从 `_variables` 查找污点。

---

### 2. Source/Sink 注册表

**文件**: `aegis-ai-core/src/analysis/taint/source_sink_registry.py`

- 新增 `_load_<lang>_sources()`：注册该语言的用户输入源（如 HTTP 请求参数、环境变量、标准输入等）。
- 新增 `_load_<lang>_sinks()`：按 `VulnCategory` 注册危险 API（SQL 执行、命令执行、文件操作、反序列化、XSS 输出、开放重定向等）。
- 新增 `_load_<lang>_sanitizers()` 或在 `_load_sanitizers()` 中扩展：注册净化函数（如 HTML 转义、参数化查询、路径规范化、Shell 转义等）。
- 在 `load_defaults()` 中依次调用上述三个方法。

---

### 3. 语言专用分析器

**文件**: `aegis-ai-core/src/analysis/analyzers/<lang>_analyzer.py`

- 实现 `<Lang>Analyzer` 类，接收 `rules: Iterable[SecurityRule]`。
- 在 `analyze(code, file_path)` 中：
  - 构建 `AnalysisContext(file_path, language="<lang>")`，将源码放入 `context.extras["source"]`。
  - 使用 Tree-sitter 解析得到 AST，调用 `TaintAnalyzer(language="<lang>").analyze_tree(root, file_path, code)` 填充 `context.taint_graph`。
  - 调用各规则的 `before_file(context)`，遍历 AST 调用 `rule.visit(node, context)`，再调用 `after_file(context)`。
  - 返回 `context.findings`。

---

### 4. 规则实现

**目录**: `aegis-ai-core/src/analysis/rules/<vuln_type>/`

- 为每种漏洞类型（如 SQL_INJECTION、RCE_COMMAND_EXEC、XSS_RISK、PATH_TRAVERSAL、DESERIALIZATION、HARDCODED_CREDENTIALS、OPEN_REDIRECT）新增 `<lang>_ast_rule.py`（或复用现有规则并扩展 `languages`）。
- 规则继承 `SecurityRule`，实现 `visit(node, context)`，在命中时调用 `context.add_finding(...)`。
- 利用 `context.taint_graph` / `context.is_var_tainted()` / `context.is_var_sanitized()` 做污点与净化感知。

---

### 5. 规则引擎：默认规则与分支

**文件**: `aegis-ai-core/src/analysis/rule_engine.py`

- 在 `get_default_rules_for_language(language)` 中增加 `if language == "<lang>": return [ ... ]`，返回该语言的所有规则实例。
- 新增便捷函数 `analyze_<lang>(code, file_path) -> List[Dict]`，内部实例化 `<Lang>Analyzer(get_default_rules_for_language("<lang>"))` 并调用 `analyzer.analyze(code, path)`，异常时返回 `[]`。

---

### 6. 项目扫描器：扩展名与分发

**文件**: `aegis-ai-core/src/scanner/project_scanner.py`

- 在 `_full_support` 或 `_partial_support` 中增加新语言的扩展名（如 `'.java': 'java'`）。
- 在 `scan_file` / 单文件分析分支中，根据扩展名调用 `analyze_<lang>(code, file_path)`。

---

### 7. 修复建议模板

**文件**: `aegis-ai-core/src/scanner/rag_enhancer.py`

- 在 `BUILTIN_REMEDIATION` 中，为各漏洞类型补充 `framework_suggested_code`，键为该语言/框架标识（如 `"spring"`、`"gin"`），值为安全代码片段字符串，供 LSP 悬停与 Code Action 使用。

---

### 8. 测试样本

**目录**: `aegis-ai-core/tests/rules/<vuln_type>/true_positive/` 与 `false_positive/`

- 每种漏洞类型至少提供 1 个正样本（TP）与 1 个负样本（FP），文件名建议 `tp_<lang>_<场景>.<ext>` / `fp_<lang>_<场景>.<ext>`。

---

### 9. 规则测试入口

**文件**: `aegis-ai-core/tests/rules/test_all_rules.py`

- 在扩展名集合中增加新语言（如 `JAVA_EXTENSIONS = {".java"}`）。
- 在 `_analyze(code, path)` 中根据扩展名调用 `analyze_<lang>(code, path)`。
- 在 `_collect_cases` 中纳入新语言的样本目录，并确保 `VULN_TYPE_MAP` 或等价逻辑能正确映射样本文件到期望的漏洞类型与 TP/FP 期望。

---

### 10. 接口约定摘要

- **SecurityRule**（`src/analysis/base/security_rule.py`）：实现 `supports(language)`、`visit(node, context)`；可选 `before_file(context)`、`after_file(context)`；`languages` 属性为适用语言集合。
- **AnalysisContext**（`src/analysis/base/analysis_context.py`）：提供 `file_path`、`language`、`findings`、`taint_graph`、`dataflow_tracker`、`extras`；规则通过 `add_finding()` 追加结果，通过 `is_var_tainted()` / `is_var_sanitized()` 查询污点与净化状态。

完成以上 10 步后，新语言即可在项目扫描与 LSP 中生效，并与现有污点分析、修复建议体系一致。
