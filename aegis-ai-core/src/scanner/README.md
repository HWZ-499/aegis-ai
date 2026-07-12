# 🔍 Scanner 模块 - 漏扫工具

## 📋 概述

Scanner 模块是 Aegis AI 的漏扫工具核心，提供批量扫描、报告生成和命令行工具功能。

---

## 🏗️ 模块结构

```
scanner/
├── __init__.py              # 模块初始化
├── project_scanner.py       # 项目扫描器（批量扫描）
├── report_generator.py      # 报告生成器（多种格式）
└── cli.py                   # 命令行工具
```

---

## 🚀 快速开始

### 1. 命令行使用（推荐）

```bash
# 扫描当前目录，输出 JSON 格式
cd aegis-ai-core
python -m src.scanner.cli . --format json

# 扫描指定目录，输出 HTML 报告
python -m src.scanner.cli /path/to/project --format html --output report.html

# 扫描并输出 SARIF 格式（用于 GitHub）
python -m src.scanner.cli . --format sarif --output results.sarif

# 显示详细信息
python -m src.scanner.cli . --format json --verbose
```

### 2. Python 模块使用

```python
from src.scanner.project_scanner import ProjectScanner
from src.scanner.report_generator import ReportGenerator

# 创建扫描器
scanner = ProjectScanner("/path/to/project")

# 执行扫描
results = scanner.scan_project(verbose=True)
stats = scanner.get_stats()

# 生成报告
generator = ReportGenerator("My Project")
json_report = generator.generate_json(results, stats)
html_report = generator.generate_html(results, stats)
```

---

## 📊 功能特性

### 0. 能力边界（诚实标注）

| 支持级别 | 语言 | 分析能力 | 说明 |
|----------|------|----------|------|
| **完整支持** | Python、JavaScript / TypeScript、Java、PHP、Go | AST + 污点 + 规则 | 统一规则引擎与语言专用规则 |
| **基础支持** | C/C++（.c, .cpp, .cc, .cxx, .h, .hpp 等） | 轻量上下文规则 | 缓冲区、格式化字符串、线程/锁与指针风险等基础检测 |

Rust、Swift、Kotlin、C# 等无规则语言不列入支持列表；CLI 使用 `-v` 时会分别显示完整支持与基础支持扩展名。**深度优先于广度。**

### 1. 批量扫描

- ✅ 自动扫描整个项目目录
- ✅ 完整 AST/污点安全检测：Python、JavaScript/TypeScript、Java、PHP、Go
- ⚠️ C/C++ 基础上下文规则
- ✅ 智能忽略（.git、node_modules、__pycache__ 等）
- ✅ 进度显示和统计信息
- ✅ **扫描范围与发现摘要**：仅扫描支持扩展名的代码文件（.js/.ts/.py 等）；其他文件（如 .html、.sql、.json）不纳入安全扫描。使用 `-v` 或查看 HTML 报告中的「扫描范围」可看到已扫描文件列表及未纳入扫描的文件与原因（例如「扩展名 .html 不在支持列表」），便于核对「为何只扫到少量文件」。

### 2. 报告格式

支持 4 种报告格式：

- **JSON**: 机器可读，适合 CI/CD 集成
- **HTML**: 可视化报告，适合查看
- **Markdown**: 文档格式，适合文档化
- **SARIF**: 标准格式，GitHub 支持

### 3. 检测能力

复用 Phase 1 的核心检测能力：

- ✅ 统一 AST/污点/DSL 静态分析（10+ 种漏洞类型）
- ✅ 单一生产分派入口，CLI、LSP 与项目扫描口径一致
- ✅ 严重程度分类（Critical/High/Medium/Low）

---

## 📖 API 文档

### ProjectScanner

#### 初始化

```python
scanner = ProjectScanner(
    project_path: str,
    ignore_patterns: Optional[List[str]] = None
)
```

**参数**:
- `project_path`: 项目根目录路径
- `ignore_patterns`: 要忽略的目录/文件模式列表（可选）

#### 扫描项目

```python
results = scanner.scan_project(verbose: bool = False) -> Dict[str, List[Dict]]
```

**返回**: 扫描结果字典，key 为文件路径，value 为问题列表

#### 获取统计信息

```python
stats = scanner.get_stats() -> Dict
```

**返回**: 统计信息字典，包含文件数、问题数、严重程度统计等

---

### ReportGenerator

#### 初始化

```python
generator = ReportGenerator(project_name: str = "Unknown Project")
```

#### 生成报告

```python
# JSON 格式
json_report = generator.generate_json(results, stats) -> str

# HTML 格式
html_report = generator.generate_html(results, stats) -> str

# Markdown 格式
markdown_report = generator.generate_markdown(results, stats) -> str

# SARIF 格式
sarif_report = generator.generate_sarif(results, stats) -> str
```

---

## 🎯 使用示例

### 示例 1: 基本扫描

```bash
# 扫描当前目录
python -m src.scanner.cli .

# 输出 JSON 到文件
python -m src.scanner.cli . --format json --output results.json
```

### 示例 2: HTML 报告

```bash
# 生成 HTML 报告
python -m src.scanner.cli /path/to/project --format html --output report.html

# 在浏览器中打开
start report.html  # Windows
open report.html   # macOS
xdg-open report.html  # Linux
```

### 示例 3: CI/CD 集成

```bash
# GitHub Actions 中使用
python -m src.scanner.cli . --format sarif --output results.sarif

# 检查退出码（有问题时返回非零）
if [ $? -ne 0 ]; then
    echo "发现安全问题！"
    exit 1
fi
```

### 示例 4: Python 脚本

```python
from src.scanner import ProjectScanner, ReportGenerator

# 扫描项目
scanner = ProjectScanner("/path/to/project")
results = scanner.scan_project(verbose=True)
stats = scanner.get_stats()

# 生成报告
generator = ReportGenerator("My Project")
report = generator.generate_html(results, stats)

# 保存报告
with open("report.html", "w", encoding="utf-8") as f:
    f.write(report)

# 检查是否有问题
if stats['total_issues'] > 0:
    print(f"⚠️ 发现 {stats['total_issues']} 个安全问题")
else:
    print("✅ 未发现安全问题")
```

---

## ⚙️ 配置选项

### 忽略模式

默认忽略的目录/文件：
- `.git`
- `__pycache__`
- `node_modules`
- `.venv`, `venv`
- `.pytest_cache`
- `.mypy_cache`
- `dist`, `build`
- `.idea`, `.vscode`

自定义忽略：

```bash
python -m src.scanner.cli . --ignore custom_dir test_files
```

### 支持的语言

**完整支持（AST+规则）：**
- `.py` / `.pyw` — Python
- `.js` / `.jsx` / `.mjs` / `.cjs` — JavaScript
- `.ts` / `.tsx` — TypeScript
- `.java` — Java
- `.php` / `.phtml` / `.php5` — PHP
- `.go` — Go

**基础支持（轻量上下文规则）：**
- `.c` / `.cpp` / `.cc` / `.cxx` / `.h` / `.hpp` — C/C++

---

## 📊 输出格式说明

### JSON 格式

```json
{
  "project_name": "My Project",
  "scan_time": "2026-02-03T10:00:00",
  "summary": {
    "total_files": 100,
    "scanned_files": 100,
    "files_with_issues": 5,
    "total_issues": 10,
    "scan_time_seconds": 2.5
  },
  "severity_stats": {
    "Critical": 2,
    "High": 3,
    "Medium": 4,
    "Low": 1
  },
  "results": {
    "file.py": [
      {
        "line": 10,
        "type": "SQL Injection Risk",
        "severity": "High",
        "details": "发现 SQL 字符串拼接",
        "file": "file.py",
        "file_path": "/path/to/file.py"
      }
    ]
  }
}
```

### HTML 格式

生成美观的 HTML 报告，包含：
- 扫描摘要表格
- 严重程度统计
- 详细问题列表（按文件分组）
- 代码高亮显示

### SARIF 格式

符合 SARIF 2.1.0 标准，可以直接上传到 GitHub：
- GitHub Security 标签页显示
- Pull Request 中显示问题
- 与 GitHub Actions 集成

---

## 🔧 故障排查

### 问题 1: 导入错误

**错误**: `ModuleNotFoundError: No module named 'src'`

**解决**: 确保从 `aegis-ai-core` 目录运行：

```bash
cd aegis-ai-core
python -m src.scanner.cli .
```

### 问题 2: 扫描速度慢

**原因**: 项目文件太多

**解决**: 
- 使用 `--ignore` 忽略不需要的目录
- 只扫描特定目录

### 问题 3: 报告文件太大

**原因**: 项目很大，问题很多

**解决**:
- 使用 JSON 格式（更紧凑）
- 过滤低严重程度的问题（未来功能）

---

## 🎯 下一步

### Phase 1.5 功能状态

- [x] 增量扫描（只扫描修改的文件）
- [x] YAML DSL 自定义规则（`.aegis/rules`）
- [x] 误报管理与 baseline
- [ ] 历史对比（对比两次扫描结果）

### Phase 2: IDE 插件

- [x] LSP Server（实时检测）
- [x] VS Code Extension
- [x] 集成到开发流程

---

## 📚 相关文档

- `PHASE1_ENHANCEMENT_PLAN.md` - Phase 1.5 增强计划
- `SCANNER_COMPARISON.md` - 漏扫工具对比分析
- `ADAPTATION_ANALYSIS.md` - 适配性分析

---

**Scanner 模块创建完成！** 🎉
