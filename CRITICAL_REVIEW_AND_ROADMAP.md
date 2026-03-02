# Aegis AI 锐评与优化路线图

> 视角：安全公司面试官 / 安全产品经理
> 态度：客观、刻薄、不留情面
> 目的：让项目从"能看"变成"能打"

---

## 第一部分：锐评

### 一句话总结

**这是一个架构野心远超实际检测深度的 SAST 原型。骨架像模像样，但肌肉是纸糊的。**

---

### 1. 最大的问题：检测逻辑是"穿着 AST 外衣的字符串匹配"

你声称是"AST 分析引擎"，但实际上 **60%+ 的安全决策仍然是字符串子串匹配**。

**典型案例——NoSQL 注入规则的"用户输入判断"：**

```python
keywords = ["input", "user", "request", "param", "arg", "query", "form", "req", "body"]
return any(k in text_lower for k in keywords)
```

这意味着：
- `formattedData` 命中 `form` → 误报
- `bodyParser` 命中 `body` → 误报
- `require(...)` 命中 `req` → 误报
- `argumentList` 命中 `arg` → 误报

**一个真正用过你工具的开发者，会在第三个误报后关掉它。**

---

### 2. 污点分析：有骨架，没血肉

你建了 `TaintGraph`、`TaintNode`、`TaintEdge`、BFS 路径查找——**数据结构本身没问题**。问题是实际的传播逻辑几乎为零。

**你的污点传播只能处理这一种模式：**
```javascript
const x = req.body;  // Source
sink(x);             // Sink
```

**以下真实世界中无处不在的模式，全部漏检：**

| 模式 | 示例 | 能检测？ |
|------|------|---------|
| 解构赋值 | `const { name } = req.body` | ❌ |
| 模板字符串 | `` `SELECT * FROM ${input}` `` | ❌ |
| 字符串拼接 | `"SELECT * FROM " + input` | ❌ |
| 函数返回值 | `const data = getInput()` | ❌ |
| 回调参数 | `app.get('/path', (req, res) => {...})` | ❌ |
| 展开运算符 | `const data = { ...req.body }` | ❌ |
| 条件表达式 | `const x = isAdmin ? req.body : defaults` | ❌ |
| 异步操作 | `const data = await getBody(req)` | ❌ |
| 类方法 | `this.query = req.body` | ❌ |
| Express 中间件链 | `req.user = decoded` | ❌ |

更严重的是，你有 **两套互不相通的污点系统**：
- `DataFlowTracker`（用于规则层）
- `TaintAnalyzer` + `TaintGraph`（独立系统）

它们各自有各自的缺陷，互不共享状态。这是典型的"堆功能不整合"。

---

### 3. "多语言支持"是纸上谈兵

`supported_extensions` 列了 **15+ 种语言**，包括 Rust、Swift、Kotlin、C#。但实际上：

| 语言 | 实际分析能力 |
|------|------------|
| Python | 有真正的 AST 分析（但深度有限） |
| JavaScript/TypeScript | 有 Tree-sitter AST（但安全判断靠字符串） |
| Java/Go/PHP/Ruby/... | **全部退化为 Python 正则规则** |

用 Python 正则去扫 Rust 代码？这不是多语言支持，这是掩耳盗铃。面试官只要追问一句"你的 Java 规则具体检测了什么"，就会穿帮。

---

### 4. 跨文件分析：只建了依赖图，没用起来

`CrossFileAnalyzer` 能解析 `require()` 和 `import`，能构建依赖图，能统计导入导出数量。然后呢？

**依赖图构建之后，没有任何消费方真正使用它来传播污点。**

CLI 里 `--cross-file` 做的事情是：扫描 → 打印统计 → 写入 `stats`。没有一行代码把跨文件信息注入到漏洞检测逻辑中。这是一个"有输入没输出"的功能。

---

### 5. 测试套件：自欺欺人

```python
if stats['sources'] > 0 and stats['sinks'] > 0:
    print("\n✅ 测试 2 通过")
    return True
else:
    print("\n⚠️ 测试 2 部分通过")
    return True  # ← 两个分支都返回 True，这个测试永远不会失败
```

- **没有用 pytest / unittest**，全是手写 `print` + emoji
- **没有反向测试**（验证安全代码不被误报）
- **没有基准测试**（没用 OWASP Benchmark / Juliet Test Suite）
- **测试代码不会失败**——这不是测试，是自我安慰

---

### 6. 报告生成器有 XSS 漏洞

```python
<p>{finding.get('details', 'No details')}</p>
```

Finding 的 `details` 字段直接注入 HTML，没有转义。如果扫描目标的代码中包含 `<script>alert(1)</script>`，你的安全扫描器的报告本身就有 XSS。

**安全工具自身有安全漏洞——这在面试中是致命的。**

---

### 7. Sanitizer 匹配同样粗糙

```python
pattern=r"(escapeHtml|escape|sanitize|encode)"
```

`encodeURIComponent`（不防 XSS）会被当作 HTML 净化器。`escape_velocity`（物理变量）会被当作安全函数。只要变量名里有 `escape`，你就认为它是安全的——这会导致大量漏报。

---

### 8. 面试官会怎么评价

**如果只看 README / 架构图 / CLI 参数列表：**
> "嗯，Source/Sink 模型、污点分析、跨文件依赖图、RAG 知识库、AI 验证——概念很全面，像是读过论文的。"

**如果花 15 分钟看代码：**
> "AST 规则里的安全判断 90% 是 `if keyword in string`；污点分析只能处理 `x = source; sink(x)`；跨文件分析建了图但没人用；测试永远返回 True；报告生成器本身有 XSS。这个项目的功能清单和实际深度之间有巨大的鸿沟。"

**最终评价：**
> "这是一个有潜力的学习项目，展现了对 SAST 理论的理解。但作为'拿得出手'的项目，目前最大的风险是：架构搭得越大，检测逻辑越浅，反而越容易被追问穿帮。宁可砍掉 80% 的功能，把剩下的 20% 做到真正能用。"

---

## 第二部分：优化路线图

### 核心原则：**深度 > 广度**

砍掉纸上谈兵的功能，把 1-2 个方向做到真正有说服力。

---

### 阶段一（紧急）：补上致命短板

> 目标：让现有功能经得起 15 分钟的代码审查

**落实情况（已做）：**
- **1.1 报告 XSS**：`report_generator.py` 中已统一使用 `_esc()` 对 `details`/`content`/`type` 等动态内容做 HTML 转义，报告输出无未转义注入。
- **1.2 用户输入判断**：NoSQL/SQL 等规则已改用 `is_user_input_node`（AST 结构化匹配）与 `dataflow_tracker.is_var_tainted`，不再用「关键词子串」判断，避免 bodyParser/formattedData 等误报。
- **1.3 测试**：已有 `test_acceptance_benchmark.py`、`test_rules_positive_negative.py` 等 pytest 用例，含 TP/TN 与反向测试；可继续补充更多 TN 用例。

#### 1.1 修复报告 XSS（1 小时）— 已落实

```python
import html
# 所有动态内容必须转义
details = html.escape(finding.get('details', ''))
```

**这是底线问题，安全工具不能有安全漏洞。**

#### 1.2 重写"用户输入判断"逻辑（2-3 小时）

**当前（字符串匹配）：**
```python
keywords = ["input", "user", "request", "param", "arg", "query"]
return any(k in text_lower for k in keywords)
```

**应该改为（AST 语义判断）：**
```python
def is_user_controlled(self, node, context):
    """真正基于 AST 的用户输入判断"""
    text = self._get_node_text(node)
    
    # 1. 直接匹配已知 Source（精确匹配，不是子串）
    if context.dataflow_tracker.is_user_input_expr(text):
        return True
    
    # 2. 查询污点追踪器
    if context.dataflow_tracker.is_tainted(text):
        return True
    
    # 3. 检查 AST 父节点是否是 Source
    # 例如 req.body.xxx 的 xxx 是通过 member_expression 访问的
    parent = node.parent
    if parent and parent.type == "member_expression":
        obj_text = self._get_node_text(parent)
        if context.dataflow_tracker.is_user_input_expr(obj_text):
            return True
    
    return False  # 不确定就不报
```

#### 1.3 写真正的测试（3-4 小时）

使用 **pytest**，包含：

```python
# test_nosql_rule.py
import pytest

class TestNoSQLRule:
    """NoSQL 注入规则测试"""
    
    # --- 应该检测到的 ---
    def test_direct_req_body(self):
        """db.users.findOne(req.body) 应该报"""
        assert len(scan("db.users.findOne(req.body)")) >= 1
    
    def test_variable_from_req(self):
        """const x = req.body; db.find(x) 应该报"""
        assert len(scan("const x = req.body;\ndb.find(x)")) >= 1
    
    # --- 不应该检测到的（反向测试）---
    def test_safe_hardcoded(self):
        """db.find({name: 'admin'}) 不应该报"""
        assert len(scan("db.find({name: 'admin'})")) == 0
    
    def test_safe_sanitized(self):
        """db.find({id: parseInt(req.body.id)}) 不应该报"""
        assert len(scan("db.find({id: parseInt(req.body.id)})")) == 0
    
    def test_non_db_find(self):
        """[1,2,3].find(x => x > 1) 不应该报"""
        assert len(scan("[1,2,3].find(x => x > 1)")) == 0
    
    def test_variable_named_body(self):
        """const bodyParser = ...; 不应该因为名字含 body 而报"""
        assert len(scan("const bodyParser = require('body-parser')")) == 0
```

**关键：必须有反向测试。** 面试官会问"你怎么保证不误报"，而不只是"你能检测什么"。

#### 1.4 砍掉虚假的"多语言支持"（30 分钟）— 已落实

- **project_scanner.py**：拆分为 `_full_support`（Python、JavaScript、TypeScript，AST+规则）与 `_partial_support`（Java、PHP、Go、C/C++，仅正则）；`supported_extensions` 为两者并集。Rust、Swift、Kotlin、C# 等无规则语言已不列入。
- **CLI 输出**：`scan_project(verbose=True)` 时分别打印「完整支持（AST+规则）」与「基础支持（仅正则）」扩展名；未支持文件的跳过原因中也会区分完整/基础支持列表。
- **API**：`ProjectScanner.get_support_level(ext)` 返回 `'full'` / `'partial'` / `None`，供文档与报告使用。
- **Scanner README**：已更新为诚实标注表（完整支持 vs 基础支持）及 1.4 说明。

---

### 阶段二（核心）：把污点分析做实

> 目标：让 Source → Sink 追踪能覆盖真实世界 60% 的代码模式

**落实情况（已做）：**
- **2.1 统一两套污点系统**：已打通。JS/TS 分析流程中**先**运行 `TaintAnalyzer.analyze_tree(root, file_path, code)` 构建污点图，再设置 `context.taint_graph`；规则通过 `context.is_var_tainted` / `context.has_tracked_var` / `context.get_taint_source` / `context.is_var_sanitized` 查询时**优先委托 taint_graph**，无图时回退到 DataFlowTracker。TaintGraph 已提供规则层查询 API（`is_var_tainted`、`has_tracked_var`、`get_taint_source_info`、`mark_sanitized`）；TaintAnalyzer 已支持 `analyze_tree`、Express 路由 req 标记、解构赋值、Sanitizer 感知。默认 JS 规则已移除 DataFlowCollector，污点图由 TaintAnalyzer 独家构建；DataFlowCollector 仍可在测试或特殊场景中单独使用。
- **2.2 补全关键传播模式**：DataFlowTracker 已支持直接赋值、解构赋值、字符串拼接/模板字符串、Express 路由回调（`mark_as_source(req)`）；JavaScriptDataFlowCollector 已实现路由回调识别、解构收集、赋值收集，并**已加入默认 JS 规则且置于首位**，扫描时先收集污点再执行检测规则。
- **2.3 Sanitizer 感知**：DataFlowTracker 已支持 `_detect_sanitizer_call`、`track_sanitization`、`is_var_sanitized`；NoSQL 规则在变量参数路径已使用 `is_var_sanitized` 跳过；SQL 模板字符串、XSS response.send 路径已增加「所有插值/标识符均已被净化则不报」逻辑。

#### 2.1 统一两套污点系统（重要）— 已落实（JS/TS）

**JS/TS 分析路径**：`JavaScriptAnalyzer` 在设置 `context.taint_graph` 后显式设置 `context.dataflow_tracker = None`，规则层仅通过 `taint_graph` 查询污点，不再回退到 DataFlowTracker。Python 仍可使用 DataFlowTracker（无 TaintAnalyzer 时）。

统一后的调用流程：
```
1. JavaScriptAnalyzer.analyze() 被调用
2. 先运行 TaintAnalyzer.analyze_code() 构建污点图
3. 再运行各条 SecurityRule，规则内部通过 context.taint_graph 查询
4. 规则不再自己判断"是否是用户输入"，而是查图
```

#### 2.2 补全关键传播模式

按优先级排列：

| 优先级 | 模式 | 说明 |
|--------|------|------|
| P0 | Express 路由回调 | `app.get('/x', (req, res) => {...})` 中 `req` 是 Source |
| P0 | 解构赋值 | `const { name } = req.body` |
| P0 | 模板字符串 | `` `SELECT ${x}` `` |
| P1 | 字符串拼接 | `"SELECT " + x` |
| P1 | 函数参数 | `function f(data) { sink(data) }; f(req.body)` |
| P2 | 展开运算符 | `{ ...req.body }` |
| P2 | 条件表达式 | `x ? req.body : safe` |

**P0 中的 Express 路由回调是最关键的。** 不支持这个，Node.js 项目的检测率会低得离谱。因为几乎所有用户输入都是通过 `(req, res) =>` 回调进来的。

实现思路：
```python
def _process_route_handler(self, node):
    """
    识别 Express 路由处理函数。
    
    app.get('/path', (req, res) => { ... })
    app.post('/path', handler)
    router.use(middleware)
    """
    # 找到回调函数的参数列表
    # 第一个参数标记为 Source（它就是 req）
    # 这样回调体内所有 req.body / req.query 的使用都能追踪到
```

#### 2.3 加入 Sanitizer 感知

在规则层面，检测到 Sink 后，回溯路径上是否经过 Sanitizer：

```python
def _is_sanitized(self, taint_path):
    """检查污点路径是否经过净化"""
    for node in taint_path.path_nodes:
        if self.registry.is_sanitizer(node.name, self.language):
            return True
    return False
```

如果经过了 `parseInt()` / `escapeHtml()`，则降低严重等级或不报告。

---

### 阶段三（差异化）：把 IDE 插件做出来

> 这才是真正的亮点——大多数 SAST 工具没有做好实时 IDE 集成

**落实情况（已做）：**
- **LSP Server**：`aegis-ai-core/src/lsp/`（pygls），监听 textDocument/didOpen、didSave，返回 Diagnostics；支持 `python -m src.lsp` 启动。
- **VSCode 扩展**：`aegis-vscode/`，通过 vscode-languageclient 连接 LSP，在编辑器中实时展示安全诊断。
- **测试**：`test_lsp_server.py`、`test_lsp_e2e.py` 覆盖 Diagnostic 转换与端到端通信。后续可迭代：增量分析、Code Action 一键修复、数据流路径展示。

#### 3.1 LSP（Language Server Protocol）方案

不做 VSCode 插件、不做 JetBrains 插件——做 **LSP Server**。一个 Server 适配所有编辑器。

```
架构：
  Aegis LSP Server (Python)
    ├── 监听文件变更事件
    ├── 增量分析（只分析改动文件 + 受影响的依赖）
    ├── 返回 Diagnostics（行内警告 + 严重等级）
    └── 支持 Code Action（一键修复建议）

客户端：
  VSCode Extension（通过 LSP 协议通信）
  Cursor Extension（同上）
  JetBrains（通过 LSP 适配器）
```

技术选型：
- Python 端用 `pygls`（Python Language Server 框架）
- 前端用 `vscode-languageclient`

#### 3.2 实时诊断效果

用户写代码时看到：

```
⚠️ [Aegis] Line 15: NoSQL 注入风险 (High)
   用户输入 `req.body` 未经验证直接传入 `db.users.findOne()`
   路径: req.body → userId → findOne()
   修复: 对输入进行类型检查 `String(req.body.userId)`
```

这比事后生成 HTML 报告有价值 100 倍。

#### 3.3 为什么这是差异化优势

| 工具 | 实时 IDE 检测 | 数据流路径显示 | 一键修复 |
|------|-------------|--------------|---------|
| Semgrep | ✅（VSCode 插件） | ❌ | ❌ |
| SonarLint | ✅（JetBrains/VSCode） | 部分 | ❌ |
| CodeQL | ❌（仅 CI/CD） | ✅ | ❌ |
| Snyk | ✅（VSCode 插件） | ❌ | ✅（部分） |
| **Aegis AI** | **✅ + AI 修复** | **✅** | **✅** |

你的独特卖点：**实时检测 + 数据流可视化 + AI 生成修复代码**。这三个组合在一起，目前没有开源工具做到。

---

### 阶段四（锦上添花）：用真实基准说话

**落实情况（已做 / 进行中）：**
- **自建基准**：`benchmark.py` + `benchmark_cases.py`，`run_benchmark()` 使用与生产一致的 `analyze_javascript`，按类型聚合 TP/TN/FP/FN；`format_report_md()` 产出路线图 4.2 格式（按类型 Recall、误报率 FPR、F1）；`run_and_save_report()` 写入 `reports/benchmark_report_*.md` 与 `.json`；回归脚本 `run_regression_scan.py` 先跑自建基准再可选扫 NodeGoat/Juice Shop。
- **真实项目评估**：需提供 ground-truth（预期漏洞列表）才能算 Recall/Precision/F1；已增加「真实项目基准评估」脚本与 ground-truth 格式，见下文 4.3。

#### 4.1 引入标准基准测试

- **OWASP Benchmark**：2740 个测试用例（Java），业界标准
- **Juliet Test Suite**：NIST 标准漏洞测试集
- **NodeGoat / DVWA / Juice Shop**：你已经在用，继续
- **自建 Benchmark**：为 JS/TS 构建一个覆盖常见模式的测试集

#### 4.2 生成标准评估报告

```
Aegis AI SAST 评估报告

目标: NodeGoat v1.0
日期: 2026-02-08

检测率 (Recall):
  - SQL 注入: 8/10 (80%)
  - NoSQL 注入: 6/8 (75%)
  - XSS: 5/12 (42%)
  - RCE: 4/5 (80%)
  总计: 23/35 (65.7%)

误报率 (FPR):
  - 总发现: 30
  - 真阳性: 23
  - 误报: 7
  误报率: 23.3%

F1 Score: 0.71
```

**这种量化数据在面试中比任何架构图都有说服力。**

#### 4.3 真实项目基准评估（已做）

- **Ground-truth 格式**：JSON 数组，每项 `{"file": "路径或 glob", "line": 行号, "type": "漏洞类型"}`；`file` 可为后缀（如 `login.js`）或 glob（如 `*route*`）。
- **脚本**：`scripts/evaluate_project.py --project-dir <路径> --ground-truth <JSON>`，对项目扫描后与 ground-truth 对比，输出 TP/FP/FN 及与 4.2 同格式的 Markdown/JSON 报告（Recall、Precision、F1）。
- **示例**：`scripts/ground_truth_example.json`；针对 NodeGoat/Juice Shop 可维护专用 ground-truth 文件后运行上述脚本得到量化指标。

---

### 阶段五（长远）：RAG + AI 真正落地

当前的 RAG 和 AI 模块是"有了"但"没用好"。

#### 5.1 RAG 不该只查知识库

当前 RAG 做的事：扫到漏洞 → 查 ChromaDB → 返回相似 CVE。

**应该做的事：**
```
扫到漏洞 → 查知识库 → 结合当前代码上下文 →
生成：
  1. 这个漏洞在你的代码中具体怎么被利用（PoC）
  2. 类似漏洞在真实世界造成了什么后果（CVE 案例）
  3. 针对你这段代码的精确修复方案（不是通用建议）
```

#### 5.2 AI 应该参与检测，不只是验证

当前 AI 是"后置验证"——先扫描，再用 AI 判断真假。

**更有价值的方向：**
```
1. AI 辅助规则生成：给 AI 一段新框架的代码，让它自动识别 Source/Sink
2. AI 辅助误报判断：不是判断"是不是漏洞"，而是"这个 Sink 的参数是否可控"
3. AI 生成攻击 PoC：对于每个发现，生成具体的攻击载荷
```

---

## 第三部分：优先级排序

| 优先级 | 任务 | 预计时间 | 价值 |
|--------|------|---------|------|
| 🔴 P0 | 修复报告 XSS | 1h | 底线 |
| 🔴 P0 | 重写用户输入判断逻辑 | 3h | 降低 90% 误报 |
| 🔴 P0 | 写 pytest 测试（含反向测试） | 4h | 面试必答 |
| 🔴 P0 | 砍掉虚假多语言声明 | 0.5h | 诚实 > 虚胖 |
| 🟠 P1 | 统一两套污点系统 | 4h | 架构整洁 |
| 🟠 P1 | Express 路由回调识别 | 4h | 检测率翻倍 |
| 🟠 P1 | 解构赋值 / 模板字符串追踪 | 3h | 覆盖常见模式 |
| 🟠 P1 | Sanitizer 集成到规则层 | 2h | 降低误报 |
| 🟡 P2 | LSP Server 原型 | 8h | **差异化杀手锏** |
| 🟡 P2 | 标准基准测试 + 量化报告 | 4h | 面试加分 |
| 🟢 P3 | RAG 生成精确修复方案 | 6h | 锦上添花 |
| 🟢 P3 | AI 辅助检测 | 8h | 远期方向 |

---

## 第四部分：面试话术建议

### 不要说：
> ~~"我们支持 15 种语言"~~
> ~~"我们有完整的污点分析"~~
> ~~"我们的 AI 能自动验证漏洞"~~

### 应该说：
> "这是一个针对 JavaScript/Python 的 SAST 工具，核心是基于 Tree-sitter 的 AST 分析引擎，配合 Source-Sink-Sanitizer 模型做污点追踪。目前在 NodeGoat 基准上检测率约 65%，误报率约 25%。我们正在做 LSP 集成，目标是实现写代码时的实时安全检测。"

**承认局限，展示深度，比吹嘘广度有说服力一万倍。**

### 面试官可能追问的问题，提前准备好：

1. "你的污点分析能追踪几层？" → 诚实说当前能力，然后说正在做什么改进
2. "和 Semgrep 比有什么优势？" → LSP 实时检测 + AI 修复 + RAG 知识库
3. "误报率怎么控制的？" → Sanitizer 感知 + 反向测试验证
4. "在真实项目上跑过吗？" → NodeGoat / Juice Shop 的量化数据
5. "你最大的技术挑战是什么？" → Express 回调模式的污点传播 / 跨文件数据流
