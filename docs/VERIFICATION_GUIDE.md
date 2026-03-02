# Aegis AI 产品验证指南

本文说明如何从**自动化测试**、**命令行扫描**、**报告内容**、**LSP/IDE** 和**可选 PoC** 等维度验证当前产品行为，确保 TDD 落地功能可被复现与回归。

---

## 一、自动化测试（推荐先跑）

在 **aegis-ai-core** 目录下执行。用于验证规则引擎、LSP 转换、Finding 结构等核心逻辑。

### 1. 核心测试（不依赖 ChromaDB / 外部服务）

```powershell
cd c:\Users\HT341\aegis-ai\aegis-ai-core

# LSP、NoSQL、AST 规则、Finding 转换与 version 校验
python -m pytest tests/test_lsp_server.py tests/test_nosql_rule.py tests/test_ast_rules.py -v

# 污点分析、数据流、NoSQL 数据流
python -m pytest tests/test_phase2_taint.py tests/test_nosql_dataflow.py -v

# 多语言规则、核心能力
python -m pytest tests/test_multi_language.py tests/test_core_features.py -v
```

若部分测试依赖 `sentence_transformers` 等可选库，可排除对应文件再跑，例如：

```powershell
python -m pytest tests/ -v --ignore=tests/test_embedding_models.py
```

**建议**：每次改规则或 LSP/context 后跑一遍上述集合，确认无回归。

---

## 二、命令行扫描验证

用真实或故意含漏洞的项目做一次完整扫描，检查报告里是否有预期漏洞类型与**关联位置**展示。

### 1. 扫描当前仓库（aegis-ai-core 自身）

```powershell
cd c:\Users\HT341\aegis-ai\aegis-ai-core

# 默认 HTML，输出到 reports/ 目录
python -m src.scanner.cli . --engine new -o reports/self-scan.html -v

# 仅 JSON（便于检查 finding 结构：line / start_line / related_locations）
python -m src.scanner.cli . --engine new --format json -o reports/self-scan.json -v
```

打开 `reports/self-scan.html`，确认：

- 有 **Critical/High/Medium** 等严重级别；
- 若存在污点类漏洞（如 NoSQL/SQL 污点），报告中是否有 **「关联位置」** 列表（TDD 7.1）。

### 2. 使用故意漏洞项目（推荐）

| 项目 | 说明 | 克隆与扫描示例 |
|------|------|----------------|
| **NodeGoat** | OWASP 故意漏洞，NoSQL/XSS 等 | `git clone --depth 1 https://github.com/OWASP/NodeGoat.git` 后 `python -m src.scanner.cli C:\NodeGoat --engine new -o reports/nodegoat-report.html -v` |
| **vulnerable-nodejs-express-mysql** | 小型 Express+MySQL 故意漏洞 | 克隆后 `python -m src.scanner.cli <路径> --engine new -o reports/vuln-express-report.html -v` |
| **Juice Shop** | OWASP 旗舰故意漏洞，体量大 | 克隆后 `python -m src.scanner.cli <路径> --engine new -o reports/juice-shop-report.html -v` |

详细路径与更多目标见：**aegis-ai-core/docs/TEST_TARGETS.md**。

### 3. 报告内容检查清单

- **HTML 报告**  
  - 摘要：总文件数、扫描文件数、问题数、耗时。  
  - 每个 finding：**第 X 行**、类型、详情；若该 finding 有 **related_locations**，应出现 **「关联位置」** 列表（如「第 X 行: SOURCE: req.body.xxx」）。  
  - 所有动态内容应正确转义（无 XSS 风险）。

- **JSON 报告**  
  - `results` 下每个 finding 可包含：`line`、`start_line`、`start_character`、`end_line`、`end_character`、`related_locations`（数组，每项含 `file_path`、`start_line`、`message` 等）。

---

## 三、真实目标验证（第三步）

**这一步就是：用「故意漏洞项目」（例如 NodeGoat）扫一遍，打开生成的 HTML 报告，确认能扫出预期类型的漏洞。**

### 要做什么

1. **扫 NodeGoat（或你已克隆的其它故意漏洞项目）**
   - 在 **aegis-ai-core** 目录下执行（命令见上文 **二、2. 使用故意漏洞项目**）：
   ```powershell
   cd c:\Users\HT341\aegis-ai\aegis-ai-core
   python -m src.scanner.cli C:\NodeGoat --engine new -o reports/nodegoat-report.html -v
   ```
   - 若 NodeGoat 不在 `C:\NodeGoat`，把路径改成你的实际路径。

2. **打开报告**
   - 用浏览器打开 `aegis-ai-core\reports\nodegoat-report.html`。

3. **检查报告里是否有这些内容**
   - **扫描摘要**：总文件数、有问题文件数、总问题数、耗时。
   - **严重程度统计**：至少能看到 **Critical**、**High**（以及可能有 Medium/Low）。
   - **详细发现**：按文件列出问题；对 NodeGoat 预期能看到例如：
     - **NOSQL_INJECTION**（High）
     - **RCE_COMMAND_EXEC**（Critical，如 eval/child_process）
     - **HARDCODED_CREDENTIALS**（High）
     - 每条有 **第 X 行**、类型、详情说明。

满足以上即算**第三步验证通过**。更多报告检查项见 **二、3. 报告内容检查清单**。

---

## 四、RAG 增强与超时行为（TDD 10.2）

- **无 ChromaDB**：扫描仍可完成，RAG 增强被跳过，报告使用内置修复建议；**不应**出现因 RAG 导致的崩溃或阻塞。
- **有 ChromaDB**：若知识库路径正确，报告中可看到「相关 CVE」「修复建议」等；若检索超时（默认 5 秒）或异常，应**仅跳过 CVE 增强**，**不丢弃**已有 findings。
- **验证方式**：  
  - 使用 `--engine new` 扫描并生成 **增强版 HTML**（若 CLI 支持 `--enhanced` 或默认带 RAG），观察是否有 CVE/建议；  
  - 或写一小段脚本：对同一批 findings 先不连 DB、再连 DB 或模拟慢查询，确认 `enhance_findings` 在异常/超时时返回原始 findings。

---

### 四.五、检测质量（基准 + 误报/漏报治理）

常态化跑 **Recall / Precision / F1**，用于规则/污点改动后的回归与误报/漏报治理。

- **单命令跑基准并写报告**（在 aegis-ai-core 下）：
  ```powershell
  python scripts/run_benchmark_report.py
  ```
  输出：`reports/benchmark_report_YYYY-MM-DD.md`、`.json`，控制台打印 Recall/Precision/F1。
- **验收阈值**：`python -m pytest tests/test_acceptance_benchmark.py` 要求 Recall ≥ 70%、FPR ≤ 20%、F1 ≥ 0.75；规则改动后应保持通过。
- **详细说明**（指标含义、新增用例、治理流程）：见 **aegis-ai-core/docs/DETECTION_QUALITY.md**。

---

## 五、LSP 与 IDE 集成验证（第四步，详细步骤）

这一步是在 **Cursor 或 VS Code 里** 看到「写代码时实时出安全诊断」：有漏洞的那一行会有波浪线，点进去还能看到「关联位置」（污点来源等）。

### 方式 A：用项目自带的 Aegis 扩展（推荐）

项目里有一个 **aegis-vscode** 扩展，会启动 Aegis 的 LSP，并在编辑 JS/TS/Python 时显示诊断。

#### 步骤 1：用「正确的工作区」打开

- 在 Cursor/VS Code 里用 **「文件 → 打开文件夹」** 打开的是 **整个 aegis-ai 文件夹**（即包含 aegis-ai-core、aegis-vscode 的那一层），**不要**只打开 aegis-ai-core。  
- 这样扩展才能自动找到 `aegis-ai-core` 作为 LSP 的工作目录。

#### 步骤 2：安装并编译扩展

- 在侧边栏点 **「扩展」**（或 `Ctrl+Shift+X`），点 **「从 VSIX 安装…」** 若你已有打包好的 vsix；  
- **或者** 直接以「开发模式」加载本地扩展：  
  - 按 `F5` 或 **运行 → 启动调试**；  
  - 在 launch 里选 **「启动扩展（打开 aegis-ai 工作区）」**（会打开一个新窗口，工作区为 aegis-ai）。  
- 若用源码跑，先在 **aegis-vscode** 目录执行一次 `npm install` 和 `npm run compile`，再 F5 启动扩展。

#### 步骤 3：配置 LSP 工作目录（若诊断不出现）

- 在新窗口里：**文件 → 首选项 → 设置**（或 `Ctrl+,`），搜索 **`aegis`**。  
- 找到 **Aegis AI Security Scanner** 相关配置：  
  - **`aegisAI.serverCwd`**：填 **aegis-ai-core 的绝对路径**，例如：  
    `C:\Users\HT341\aegis-ai\aegis-ai-core`  
  - **`aegisAI.pythonPath`**：若你平时用 `python` 就能跑，可保持默认 `python`；若是 `py` 或完整路径，改成对应值。  
- 保存设置后，可 **重新加载窗口**（命令面板里搜「Reload Window」）让扩展用新配置启动 LSP。

#### 步骤 4：打开一份「故意含漏洞」的文件

- 在左侧 **把 NodeGoat 加进工作区**：**文件 → 将文件夹添加到工作区**，选你克隆的 NodeGoat 目录（例如 `C:\NodeGoat`）。  
- 在 NodeGoat 里打开一个会被 Aegis 报问题的 JS 文件，例如：  
  - **NoSQL 注入**：`routes/users.js` 或 `routes/allocations.js` 里含有 `req.body` / `req.query` 直接进 `find`、`findOne`、`update` 等调用的文件。  
- **保存文件**（`Ctrl+S`）或**直接编辑**：LSP 会在「打开时」「保存时」以及**编辑时（输入停止约 0.4 秒后，M2 防抖）**更新诊断。

#### 步骤 5：看诊断和「关联位置」

- **诊断（波浪线）**：有漏洞的那一行（或一段代码）下面会出现**红色/黄色波浪线**，鼠标悬停会看到 Aegis 的提示（类型、严重程度、说明）。  
- **关联位置（Related Information）**：若该漏洞带污点来源，在诊断的详情里会有一条 **「Related Information」** 或 **「相关位置」**，点进去会跳到**污点来源那一行**（例如 `SOURCE: req.body.xxx`）。  
- 若没有波浪线：按下面 **「无波浪线排查」** 逐项检查。

---

#### 打开 NodeGoat 的 JS 没有波浪线？按下面排查

**1. 工作区必须是「先打开 aegis-ai」，再添加 NodeGoat**  
- 若你当前是 **只打开了 NodeGoat**（文件 → 打开文件夹 → 选 NodeGoat），扩展会去找 `NodeGoat\aegis-ai-core`，找不到就不会启动 LSP，自然没有波浪线。  
- **正确做法**：  
  - **文件 → 打开文件夹** → 选 **aegis-ai**（和 aegis-ai-core、aegis-vscode 同一层）；  
  - 再 **文件 → 将文件夹添加到工作区** → 选 **NodeGoat**。  
- 这样第一个工作区根是 aegis-ai，扩展才能自动用 `aegis-ai\aegis-ai-core` 启动 LSP。

**2. 或直接配死 serverCwd（只开 NodeGoat 时也有效）**  
- **文件 → 首选项 → 设置**，搜索 **aegis**；  
- 找到 **Aegis AI Security Scanner: Server Cwd**，填：  
  `C:\Users\HT341\aegis-ai\aegis-ai-core`  
  （按你本机实际路径改）。  
- 保存后 **重新加载窗口**（命令面板输入 `Reload Window` 执行）。

**3. 看输出面板**  
- **查看 → 输出**（或 `Ctrl+Shift+U`），在输出里选 **「Aegis AI Security Scanner」**。  
- 若看到 **「无法启动：未找到有效的 aegis-ai-core 目录」** → 按上面 1 或 2 改工作区/配置。  
- 若看到 **「LSP Server 已连接」** 但依然无波浪线，再看是否有 **「LSP Server 启动失败」** 或 Python 报错。

**4. 看状态栏**  
- 窗口右下角应有 **「Aegis: 已连接」**；若是 **「Aegis: 未连接」**，说明 LSP 没起来，按 1～3 处理。

**5. 确认当前文件是 JS**  
- 右下角语言模式要为 **JavaScript**（或 TypeScript），否则不会走 Aegis 的 documentSelector。

**6. 试一下保存**  
- 打开 NodeGoat 里含漏洞的 JS（如 `app\routes\contributions.js`），按 **Ctrl+S** 保存一次，看是否在保存后出现波浪线。

#### 步骤 6：文档 version 校验（TDD 7.3，可选）

- 打开同一份含漏洞的文件，等诊断出现后，**故意改一行代码但不要保存**（例如加个空格再删掉），再触发一次分析（有的实现是 didChange 自动触发）。  
- **预期**：若实现正确，应**丢弃**基于旧 version 的结果，可能暂时不显示该文件的诊断或只显示空结果，避免「改了代码仍显示旧诊断」。

---

### 方式 B：不装扩展，只确认 LSP 能跑

若暂时不装扩展，只想确认 LSP 进程能启动、不崩溃：

```powershell
cd c:\Users\HT341\aegis-ai\aegis-ai-core
python -m src.lsp
```

- 运行后终端会「卡住」、没有新输出，这是正常的：LSP 在用 stdio 等 IDE 发协议消息。  
- 用 `Ctrl+C` 结束即可。能正常启动、不报错即说明 LSP 可执行。

### 方式 C：自动跑「第四步」协议层验证（无需打开 IDE）

不打开 Cursor/VS Code 也能验证「LSP 收到 didOpen 后能否正确发布诊断」：

```powershell
cd c:\Users\HT341\aegis-ai\aegis-ai-core
python -m pytest tests/test_lsp_e2e.py -v
```

- 测试会**启动真实 LSP 子进程**，模拟客户端发送 `initialize` 和 `textDocument/didOpen`（含漏洞的 JS/Python 代码），并断言能收到 `textDocument/publishDiagnostics` 且诊断内容正确（如含 RCE 的 JS 会出 RCE 诊断、安全代码为空诊断）。
- **6 个用例全部通过**即说明第四步的「协议与扫描链路」在本地是通的；剩下只有在 IDE 里接扩展、看波浪线与「关联位置」需要您本机手动做一次。

---

## 六、可选验证：RAG / 守护进程 / PoC（详细步骤）

这三项不是每次必做，但若要做，可按下面一步步来。

### 6.1 RAG 增强与超时（TDD 10.2）

**目的**：确认没有 ChromaDB 时扫描照常完成；有 ChromaDB 时报告里可有 CVE/建议；超时或异常时只跳过 RAG、不丢 findings。

- **无 RAG 时**：你前面跑的 `python -m src.scanner.cli . --engine new -o reports/self-scan.html` 就是在「无 ChromaDB」或未配置 DB 路径下跑的，只要生成了 HTML 且没有因 RAG 报错，即算通过。  
- **有 RAG 时**：若项目里已配置了 ChromaDB 路径（例如 CLI 或配置里指定了 `db_path`），再扫一次同一项目，打开报告看是否多出「相关 CVE」「修复建议」等区块。  
- **超时/异常**：代码里已对 RAG 检索做了超时（默认 5 秒）和 try/except；若 DB 很慢或不可用，应只跳过 CVE 增强，**不**丢弃已有 findings，报告里仍能看到所有漏洞条目。

不需要你手动「制造超时」；只要在没 DB 或 DB 异常时扫一遍，结果仍然完整即可。

---

### 6.2 守护进程（Worker Daemon，TDD 9.1.1）

**目的**：确认单进程 TCP 服务能收请求、返回 findings，并在达到请求数或内存上限后优雅退出。

#### 步骤 1：启动守护进程

```powershell
cd c:\Users\HT341\aegis-ai\aegis-ai-core
python -m src.worker_daemon --port 8765 --max-requests 5 --max-memory-mb 512
```

- 终端会打印类似：`Worker daemon listening on 127.0.0.1:8765 ...`（端口可能是 8765 或系统分配的）。  
- **不要关这个终端**，保持进程运行。

#### 步骤 2：用脚本或 PowerShell 发一条请求

新建一个临时脚本或直接用 PowerShell 发 HTTP 不行（当前守护进程是**裸 TCP**，不是 HTTP）。用 Python 发最简单，例如在**另一个终端**执行：

```powershell
cd c:\Users\HT341\aegis-ai\aegis-ai-core
python -c "
import socket, json
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 8765))
req = {'file_path': 'test.js', 'content': 'const x = require(\"mongodb\"); x.collection(\"u\").findOne(req.body);', 'language': 'javascript'}
s.send((json.dumps(req) + '\n').encode())
data = s.recv(8192).decode()
print(data)
s.close()
"
```

- **预期**：打印出一行 JSON，里面有 `"findings"` 数组，且至少有一条 NoSQL 相关 finding（因为 `req.body` 进了 `findOne`）。

#### 步骤 3：验证优雅退出

- 再次运行上面那段 `python -c "..."` 共 **5 次**（因为 `--max-requests 5`）。  
- 第 5 次之后，**守护进程所在终端**应自动打印类似「Reached max_requests=5, exiting...」并退出，而不是崩溃。  
- 若把 `--max-requests` 改大，可多请求几次再观察。

---

### 6.3 PoC 脚本（TDD 12.3）

**目的**：体会「内联后行号错位」和「多进程冷启动延迟」，为架构选型（常驻进程 vs 每次 spawn）提供依据。

#### PoC 1：内联与坐标地狱

```powershell
cd c:\Users\HT341\aegis-ai\aegis-ai-core
python scripts/poc1_inline_coordinate_hell.py
```

- **看什么**：脚本会演示「内联两个函数后」，漏洞在 AST 里对应的行号与真实源码行号的对应关系；结论是：需要维护「虚拟节点 → (CallSite, DefinitionSite)」映射，否则 IDE 里定位会乱。  
- 不需要改任何配置，跑完看终端输出即可。

#### PoC 2：多进程启动延迟

```powershell
cd c:\Users\HT341\aegis-ai\aegis-ai-core
python scripts/poc2_multiprocessing_latency.py
```

- **看什么**：会打印「每次 spawn 子进程」的耗时（例如几十到一百多毫秒）和「常驻进程一次请求」的耗时（可低至个位数毫秒）。  
- 用于理解：若 IDE 每次分析都起新进程，延迟会明显；所以 TDD 选「单守护进程 + IPC」。

更多说明见：**aegis-ai-core/scripts/README_POC.md**。

---

## 七、基准与回归（可选）

- **基准报告**（Recall/Precision/F1 等）：  
  `python scripts/run_benchmark_report.py --project-dir <NodeGoat 或 Juice Shop 等路径>`  
  用于对比规则与引擎变更前后的检测率与误报。

- **回归扫描**：  
  `python scripts/run_regression_scan.py`（若脚本存在且配置了目标目录）  
  用于定期回归，确保已知漏洞仍被检出。

---

## 八、建议验证顺序（快速通关）

| 步骤 | 做什么 | 在文档中的位置 |
|------|--------|----------------|
| **第一步** | 跑自动化测试（pytest） | **一、自动化测试** |
| **第二步** | 扫当前项目，生成 self-scan.html | **二、命令行扫描验证** → 1. 扫描当前仓库 |
| **第三步** | 扫 NodeGoat（或其它故意漏洞项目），打开 nodegoat-report.html 检查 | **三、真实目标验证（第三步）** |
| **第四步** | 在 IDE 里接 LSP，看实时诊断与关联位置 | **五、LSP 与 IDE 集成验证** |

按以上顺序即可在本地完整验证当前产品行为并与 TDD 对齐。
