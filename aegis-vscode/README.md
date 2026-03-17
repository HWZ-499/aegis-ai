# Aegis AI Security Scanner

**Find and fix SQL injection, XSS, RCE, and 7+ more vulnerability types as you code.**

Real-time SAST scanning for VS Code / Cursor using Tree-sitter AST + taint analysis + AI-driven patches. No CI pipeline. No regex guessing. Framework-aware code generation.

Supports: **JavaScript / TypeScript / Python / PHP / Java / Go**

> **v0.3.2** — Now with full English UI, Python validation, and TreeView empty state. [See what changed →](CHANGELOG.md)

---

## Installation

### Step 1: Install Extension
VS Code Marketplace: search **"Aegis AI Security Scanner"** or ID `wen-zai.aegis-ai-security`

### Step 2: Clone Python Engine
The extension needs the Python core to run:

```bash
git clone https://github.com/HWZ-499/aegis-ai.git
cd aegis-ai/aegis-ai-core
pip install -r requirements.txt
```

**Done.** Extension auto-detects the Python engine. If not, set path in VS Code settings:
```json
{ "aegisAI.serverCwd": "/path/to/aegis-ai-core" }
```

### Step 3: Enable AI Fixes (Optional)
For one-click auto-fix, set an API key:
- **DeepSeek** (cheap): `export DEEPSEEK_API_KEY=your_key`
- **OpenAI**: `export OPENAI_API_KEY=your_key`
- **Ollama** (free, local): `export AI_PROVIDER=ollama` (after `ollama pull llama3`)

**That's it.** Open any `.js`, `.ts`, `.py`, `.php`, `.java`, or `.go` file → save → diagnostics appear.

---

## Key Features

- **1-second feedback** — diagnostics appear on save, no CI pipeline
- **Real data-flow analysis** — Tree-sitter AST + TaintGraph, not regex  
- **One-click AI fix** — click lightbulb → framework-aware patch auto-generated
- **10+ vulnerability types** — SQL/NoSQL injection, XSS, RCE, path traversal, deserialization, SSRF, hardcoded credentials, open redirect
- **Real-world validated** — 100% F1 on OWASP NodeGoat, 92% F1 on Django 3.2 core

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
| `aegisAI.pythonPath` | `python` | Path to the Python interpreter |
| `aegisAI.serverCwd` | `` | Force LSP server working directory (leave blank for auto-detect) |
| `aegisAI.serverModule` | `src.lsp` | Python module path for the LSP server |

---

## Known Issues

- `tree-sitter==0.21.3` may print a FutureWarning on startup (no functional impact)
- PHP analysis uses Tree-sitter AST for core rules; some niche patterns may still fall back to line-level matching
- Cross-file taint propagation requires `module.exports` patterns (CommonJS)

---

## License

MIT © Aegis AI
