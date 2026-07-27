# Aegis AI Security Scanner

**Find and fix SQL injection, XSS, RCE, and 7+ more vulnerability types as you code.**

Real-time SAST scanning for VS Code / Cursor using Tree-sitter AST, taint analysis, validated rules, and optional AI-driven patches.

Supports: **JavaScript / TypeScript / Python / PHP / Java / Go / C/C++ basic scanning**

> **v0.6.7** — Stable package version. [See what changed →](CHANGELOG.md)

---

## 能力矩阵

| 状态 | 当前能力 |
|------|----------|
| **已支持** | 实时单文件诊断、Problems / 树视图、baseline 视图、AI 精准修复、示例修复、注释建议 |
| **实验性** | 一跳跨文件参数 → Sink 污点传播、suppressed findings 侧栏展示、custom / Ollama provider 工作流 |
| **规划中** | 跨文件返回值/重导出/多跳传播、更完整的多 IDE 打包与 smoke E2E |

## Installation

### Step 1: Install Extension
VS Code Marketplace: search **"Aegis AI Security Scanner"** or ID `wen-zai.aegis-ai-security`

### Step 2: Install Python 3.10–3.12
Aegis includes its Python backend in the VS Code extension package, but it still needs a local Python interpreter to run that backend.

Requirements:

- VS Code **1.91 or later**, or a compatible Cursor release.
- Python **3.10, 3.11, or 3.12**. Python 3.13 is not yet supported because the pinned Tree-sitter runtime has no compatible `tree-sitter-languages` distribution.
- `python --version` or `python3 --version` works in your terminal
- Internet access on first run so Aegis can install its backend dependencies into a VS Code-managed virtual environment

PowerShell check:

```powershell
python --version
```

Expected:

```text
Python 3.10.x, 3.11.x, or 3.12.x
```

On first activation, Aegis automatically:

- creates a private Python environment under VS Code extension storage
- installs the bundled `aegis-ai-core` backend into that environment
- starts the local LSP scanner from that managed environment

You do **not** need to clone the GitHub repository for normal Marketplace usage.

Advanced/development override only:

```json
{ "aegisAI.serverCwd": "/path/to/aegis-ai-core" }
```

### Step 3: Enable AI Fixes (Optional)
AI fixes are powered by the Python engine process. Configure env vars, then reload VS Code/Cursor.

PowerShell examples:

```powershell
$env:AI_PROVIDER = "deepseek"
$env:DEEPSEEK_API_KEY = "your_key"

# or OpenAI
$env:AI_PROVIDER = "openai"
$env:OPENAI_API_KEY = "your_key"

# or local Ollama
$env:AI_PROVIDER = "ollama"
$env:OLLAMA_BASE_URL = "http://localhost:11434/v1"
$env:OLLAMA_MODEL = "llama3"

# or custom endpoint
$env:AI_PROVIDER = "custom"
$env:AI_BASE_URL = "https://your-gateway.example.com/v1"
$env:AI_API_KEY = "your_key"
```

If you prefer settings UI, set `Aegis › Ai: Provider`; API keys still come from env vars.

**That's it.** Open any `.js`, `.ts`, `.py`, `.php`, `.java`, or `.go` file → save → diagnostics appear.

### Where The Fix Features Are

Place the cursor on an Aegis diagnostic line, then use `Ctrl+.` or the lightbulb.

- `Aegis: ✓ 应用 AI 精准修复`: replaces the vulnerable code when AI confidence is high.
- `Aegis: 应用示例修复代码`: replaces the vulnerable code with a framework-aware safe example.
- `Aegis: 插入 AI 修复建议`: inserts comments only. It does **not** change runtime code.
- `Aegis: 插入修复建议注释`: inserts a non-AI guidance block only. It does **not** fix code.
- `Aegis: Add to baseline`: writes the current finding to `.aegis-baseline.json` and hides it for this workspace. 它**不是修复代码**。
- `Aegis: Ignore this finding`: inserts `aegis-ignore` suppression comments.

To revert inserted comments, use `Ctrl+Z` immediately after the action or run `Aegis: Remove Inserted Remediation Comments`.

Suppressed findings can be inspected in the **Suppressed Findings** view after enabling `aegisAI.showSuppressedFindings`.

---

## Key Features

- **Fast local feedback** — diagnostics appear on save without waiting for CI
- **Language-aware analysis** — Tree-sitter AST, taint tracking, and validated rules
- **One-click AI fix** — click lightbulb → framework-aware patch auto-generated
- **10+ vulnerability types** — SQL/NoSQL injection, XSS, RCE, path traversal, deserialization, SSRF, hardcoded credentials, open redirect
- **Auditable real-project baselines** — DVWA Recall 100.0% / Precision 44.2%; NodeGoat Recall 100.0% / Precision 85.7% on the 2026-07-12 clean snapshots

---

## Supported Vulnerability Types

| ID | Type | Languages |
|----|------|-----------|
| SQL_INJECTION | SQL Injection | JS/TS, Python, Java, Go |
| NOSQL_INJECTION | NoSQL Injection | JS/TS, Java, Go |
| XSS_RISK | Cross-Site Scripting | JS/TS, Python, PHP, Java, Go |
| RCE_COMMAND_EXEC | Remote Code Execution | JS/TS, Python, PHP, Java, Go |
| PATH_TRAVERSAL | Path Traversal | JS/TS, Python, PHP, Java, Go |
| HARDCODED_CREDENTIALS | Hardcoded Credentials | JS/TS, Python, PHP, Java, Go |
| DESERIALIZATION | Unsafe Deserialization | JS/TS, Python, Java, Go |
| SSRF | Server-Side Request Forgery | JS/TS, Python |
| OPEN_REDIRECT | Open Redirect | JS/TS, Python, Java, Go |

---

## Extension Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `aegisAI.enabled` | `true` | Enable/disable the scanner |
| `aegisAI.pythonPath` | `python` | Path to Python 3.10–3.12 used for the managed backend environment |
| `aegisAI.serverCwd` | `` | Advanced/development override for local `aegis-ai-core`; leave blank for bundled backend |
| `aegisAI.serverModule` | `src.lsp` | Python module path for the LSP server |
| `aegisAI.scan.exclude` | `["**/node_modules/**", ...]` | Glob patterns excluded from scanning |
| `aegisAI.experimental.crossFileAnalysis` | `false` | Enable experimental one-hop cross-file parameter-to-sink taint analysis |
| `aegisAI.showSuppressedFindings` | `false` | Show `.aegis-baseline.json` entries in the sidebar |

---

## Known Issues

- First run may take longer while the managed Python backend environment is created
- Python 3.10–3.12 must be installed separately and available through `aegisAI.pythonPath`
- PHP production analysis uses maintained AST/taint rules; niche patterns outside the current rule set may remain undetected
- Cross-file taint propagation requires `module.exports` patterns (CommonJS)

---

## License

MIT © Aegis AI
