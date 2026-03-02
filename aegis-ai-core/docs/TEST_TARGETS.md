# Aegis AI 实测目标项目

用于在真实/故意含漏洞项目上验证 Aegis SAST 的检测能力。建议先克隆到本地固定目录，再运行扫描与基准报告。

**若已用过 NodeGoat**，可换用 **OWASP Juice Shop** 或 **vulnerable-nodejs-express-mysql** 作为另一实测目标（见下文克隆与扫描命令）。

---

## 业内 SAST 基准与「大项目」选择

- **专门测 SAST 的业内基准**：**[OWASP Benchmark](https://owasp.org/www-project-benchmark/)**（<https://github.com/OWASP-Benchmark/BenchmarkJava>）  
  - **语言**：Java（当前主力），约 **2,740 个可运行用例**，覆盖 SQL 注入、XSS、命令注入、路径遍历、弱随机等 11 类，每个用例对应 CWE、有标准期望结果，用于评估 SAST/DAST 的准确率与速度。  
  - **与 Aegis 的关系**：Aegis 当前主攻 **JS/TS/Python**，不能直接跑 Java Benchmark；若后续支持 Java，可用它做业内对标。

- **Node/JavaScript**：目前 **没有** 官方的 OWASP Benchmark 版本。业内常用「故意漏洞」大项目做实测的是 **OWASP Juice Shop**（见下文）——体量大、OWASP 旗舰、多挑战，适合作为「不想用小型 demo 时」的 Node/JS 实测目标。

- **Python**：OWASP Benchmark 的 Python 版（v0.1）计划 2026 年初发布，届时可用于 Python 规则对标。

---

## 一、推荐项目（JavaScript/Node.js）

Aegis 对 JS/TS 支持最完整（AST + 污点），优先用以下项目实测。

### 1. NodeGoat（OWASP）

- **说明**：故意包含 OWASP Top 10 的 Node.js 应用，含 NoSQL 注入、XSS、反序列化等。
- **仓库**：<https://github.com/OWASP/NodeGoat>
- **克隆**：
  ```bash
  git clone --depth 1 https://github.com/OWASP/NodeGoat.git
  ```
- **建议路径**：`C:\NodeGoat` 或 `~/NodeGoat`

### 2. OWASP Juice Shop（**推荐：业内常用「大项目」**）

- **说明**：OWASP 旗舰故意漏洞项目，现代前端（Angular）+ Node 后端，覆盖 OWASP Top 10 及多种真实漏洞，体量远大于小型 Express 示例，业内常用来测 SAST/安全培训/CTF。
- **仓库**：<https://github.com/juice-shop/juice-shop>
- **克隆**：
  ```bash
  git clone --depth 1 https://github.com/juice-shop/juice-shop.git
  ```
- **说明**：代码量较大，扫描时间会稍长；适合「觉得小项目不够、想用业内常用大项目」时使用。

### 3. vulnerable-nodejs-express-mysql（小型 Express 示例）

- **说明**：故意含漏洞的 Node.js + Express + MySQL 登录示例，体积小、适合快速扫描对比。
- **仓库**：<https://github.com/stypr/vulnerable-nodejs-express-mysql>
- **克隆**：
  ```bash
  git clone --depth 1 https://github.com/stypr/vulnerable-nodejs-express-mysql.git
  ```
- **建议路径**：`C:\AegisTestTargets\vulnerable-nodejs-express-mysql`（与克隆脚本一致）。

### 4. 其他小型 Node/Express 示例

- 任意包含 `req.body` / `req.query`、`eval`、`innerHTML`、数据库调用的 Express 项目均可作为补充目标。

---

## 二、Python 项目

Aegis 支持 Python AST 规则（RCE、SQLi、XSS、路径遍历、硬编码凭证等），可用以下类型项目测试：

- 任意 **Flask / Django / FastAPI** 项目，尤其含：
  - `os.system` / `subprocess` / `eval`
  - 拼接 SQL、模板中未转义用户输入
  - `open(user_input)` 等文件操作
- 若需「故意漏洞」示例，可搜索 GitHub：`flask vulnerable`、`django sqli demo` 等。

---

## 三、用 Aegis 扫描上述项目

在 **aegis-ai-core** 目录下执行。

### 1. 扫描并生成 HTML 报告

```bash
# NodeGoat
python -m src.scanner.cli C:\NodeGoat --engine new -o reports/nodegoat-report.html -v

# Juice Shop（换用此项目时常用）
python -m src.scanner.cli C:\AegisTestTargets\juice-shop --engine new -o reports/juice-shop-report.html -v

# vulnerable-nodejs-express-mysql（小型，换用此项目时）
python -m src.scanner.cli C:\AegisTestTargets\vulnerable-nodejs-express-mysql --engine new -o reports/vuln-express-report.html -v

# 任意项目路径
python -m src.scanner.cli /path/to/your/project --engine new -o reports/project-report.html -v
```

### 2. 扫描并看按类型统计（配合基准报告脚本）

```bash
python scripts/run_benchmark_report.py --project-dir C:\NodeGoat
# 换用 Juice Shop 时：
python scripts/run_benchmark_report.py --project-dir C:\AegisTestTargets\juice-shop
# 换用小型 Express 示例时：
python scripts/run_benchmark_report.py --project-dir C:\AegisTestTargets\vulnerable-nodejs-express-mysql
```

会先跑自建基准并生成 `reports/benchmark_report_YYYY-MM-DD.md`，再对 `--project-dir` 做一次扫描并打印各漏洞类型的发现数量。

### 3. 仅跑自建基准（不扫真实项目）

```bash
python -m src.scanner.benchmark
# 或
python scripts/run_benchmark_report.py
```

报告输出在 `reports/benchmark_report_YYYY-MM-DD.md` 与 `.json`。

---

## 四、一键克隆脚本（可选）

可将以下内容保存为 `scripts/clone_test_targets.ps1`（Windows）或 `.sh`（Mac/Linux），在**仓库外**的目录执行，把目标克隆到固定位置后再用上面命令扫描。

**Windows PowerShell 示例**（保存为 `scripts/clone_test_targets.ps1`）：

```powershell
# 在希望存放项目的目录执行，例如 C:\ 或 D:\
$Base = "C:\AegisTestTargets"
New-Item -ItemType Directory -Force -Path $Base | Out-Null
Set-Location $Base

if (-not (Test-Path "NodeGoat")) {
    git clone --depth 1 https://github.com/OWASP/NodeGoat.git
    Write-Host "NodeGoat 已克隆到 $Base\NodeGoat"
}
if (-not (Test-Path "juice-shop")) {
    git clone --depth 1 https://github.com/juice-shop/juice-shop.git
    Write-Host "Juice Shop 已克隆到 $Base\juice-shop"
}
Write-Host "完成。扫描示例: python -m src.scanner.cli $Base\NodeGoat --engine new -o reports/nodegoat.html -v"
```

克隆完成后，在 aegis-ai-core 下执行：

```bash
python -m src.scanner.cli C:\AegisTestTargets\NodeGoat --engine new -o reports/nodegoat-report.html -v
python -m src.scanner.cli C:\AegisTestTargets\juice-shop --engine new -o reports/juice-shop-report.html -v
```

---

## 五、如何解读结果

- **自建基准报告**（`benchmark_report_*.md`）：看 Recall / Precision / F1，评估规则与污点是否稳定。
- **项目扫描报告**（HTML）：看各文件、各类型的发现数量与位置，用于查漏与误报排查。
- **`--project-dir` 控制台统计**：快速看「某项目各漏洞类型各有多少条」，便于和预期或人工审计对比。

建议流程：先跑通自建基准 → 再扫 NodeGoat / Juice Shop → 根据报告调规则或补充用例。

---

## 六、回归扫描（降低误报方案）

按《降低误报改进方案》回归：跑自建基准确认 Recall/Precision/F1 不下降，再对 NodeGoat、Juice Shop 全量扫一次，对比改进前后发现数。

```bash
# 仅跑基准
python scripts/run_regression_scan.py

# 指定 NodeGoat / Juice Shop 路径（或设环境变量 NODEGOAT_PATH、JUICESHOP_PATH）
python scripts/run_regression_scan.py --nodegoat C:\NodeGoat --juice-shop C:\juice-shop

# 扫描时禁用缓存
python scripts/run_regression_scan.py --nodegoat C:\NodeGoat --no-cache
```

输出：`reports/benchmark_report_YYYY-MM-DD.md`、`reports/regression_summary_YYYY-MM-DD.md`，以及可选的 `nodegoat-report_*.html`、`juice-shop-report_*.html`。用 `regression_summary_*.md` 对比各项目按类型统计，便于评估改进前后误报/漏报。

---

## 七、阶段四：真实项目基准评估（Recall/Precision/F1）

对 NodeGoat、Juice Shop 等真实项目做**量化评估**需提供 **ground-truth**（预期漏洞列表），再与扫描结果对比得到 TP/FP/FN 和 Recall、Precision、F1。

### 1. Ground-truth 格式

JSON 数组，每项包含：

- `file`：文件路径或后缀或 glob（如 `login.js`、`*route*`）
- `line`：预期漏洞行号（可选，用于更精确匹配）
- `type`：漏洞类型（如 `NOSQL_INJECTION`、`SQL_INJECTION`、`XSS_RISK`）

示例见 `scripts/ground_truth_example.json`。针对 NodeGoat/Juice Shop 可维护专用 JSON（如 `scripts/ground_truth_nodegoat.json`）。

### 2. 运行评估

在 **aegis-ai-core** 目录下：

```bash
python scripts/evaluate_project.py --project-dir C:\NodeGoat --ground-truth scripts/ground_truth_example.json
python scripts/evaluate_project.py --project-dir C:\NodeGoat --ground-truth scripts/ground_truth_nodegoat.json --output-dir reports --target-name NodeGoat
```

输出：`reports/evaluate_<目标名>_YYYY-MM-DD.md` 与 `.json`，格式与自建基准报告一致（按类型 Recall、误报率、F1）。
