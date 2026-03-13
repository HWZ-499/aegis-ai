# Aegis AI Security Scanner

**Real-time SAST security scanning for VS Code / Cursor** — detects vulnerabilities as you type, powered by Tree-sitter AST analysis and DeepSeek AI auto-fix.

> **Preview Release** — Active development. See [changelog](CHANGELOG.md) for latest updates.

---

## Features

- **Save-to-scan** — diagnostics appear within 1 second of saving a file
- **10+ vulnerability types** — SQL injection, NoSQL injection, XSS, RCE, path traversal, hardcoded credentials, deserialization, and more
- **Multi-language** — JavaScript / TypeScript / Python / PHP / Java / Go (full AST + taint analysis via Tree-sitter)
- **AI auto-fix** — click the lightbulb (Code Action) on any High/Critical finding; DeepSeek generates framework-aware patch code
- **Taint analysis** — cross-function and cross-file data-flow tracking via self-developed TaintGraph + Dominator Tree
- **Status bar** — shows `Aegis: N issues` / `Aegis: Secure` / `Aegis: Scanning…` at a glance

---

## Detection Performance (Real-World Benchmarks)

| Target | Language | Recall | Precision | F1 |
|--------|----------|--------|-----------|-----|
| NodeGoat (OWASP) | JavaScript | 100% | 100% | 1.00 |
| django-3.2-core | Python | 92.3% | 92.3% | 0.92 |
| DVWA | PHP | 100% | 45.3% | 0.62 |
| flask-2.3.2 | Python | 66.7% | 50.0% | 0.57 |

*Benchmarks run against OWASP NodeGoat, DVWA, Django 3.2 core, and Flask 2.3.2. As of 2026-03-13.*

---

## Requirements

| Component | Requirement |
|-----------|-------------|
| VS Code | ≥ 1.75 |
| Python | ≥ 3.9 |
| aegis-ai-core | Cloned alongside this extension |

```bash
# Clone the full repository
git clone https://github.com/aegis-ai/aegis-ai.git

# Install Python dependencies
cd aegis-ai/aegis-ai-core
pip install -r requirements.txt

# (Optional) Set up DeepSeek API key for AI auto-fix
echo DEEPSEEK_API_KEY=your_key > .env
```

---

## Quick Start

1. Install the extension from VS Code Marketplace (`aegis-ai.aegis-ai-security`)
2. Open the `aegis-ai-core` directory so the extension can locate the LSP server
3. Open any `.js`, `.ts`, `.py`, `.php`, `.java`, or `.go` file — diagnostics appear on save
4. Click the **lightbulb** on any finding → **Apply AI Fix** to auto-patch

### Manual Configuration

If the LSP server is not found automatically, set the working directory explicitly:

```json
// .vscode/settings.json
{
  "aegisAI.serverCwd": "C:/path/to/aegis-ai/aegis-ai-core",
  "aegisAI.pythonPath": "python"
}
```

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
