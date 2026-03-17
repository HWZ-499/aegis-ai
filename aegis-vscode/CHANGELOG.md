# Changelog

## [0.3.2] - 2026-03-18

### Fixed
- **All UI text translated to English** — status bar, tooltips, error dialogs, progress messages, output logs (was Chinese)
- **Status bar icon confusion** — "issues found" now uses `$(warning)`, "disconnected" uses `$(plug)`, "error" keeps `$(error)`
- **Proper plural handling** — "1 issue" vs "3 issues" in status bar
- **Error dialog buttons in English** — "Configure Python Path" / "View Logs" (was Chinese)

### Added
- **Python validation on startup** — checks Python interpreter exists before LSP start, shows actionable error with "Configure Python Path" button
- **TreeView welcome/empty state** — shows "No security issues found" with scan action buttons when panel is empty
- **Keyboard shortcut for workspace scan** — `Ctrl+Alt+Shift+S` (`Cmd+Alt+Shift+S` on Mac)
- **Improved pythonPath setting description** — includes example values for different platforms

### Improved
- Error messages now provide actionable guidance instead of generic failures
- All code comments translated to English for international contributors

All notable changes to Aegis AI Security Scanner are documented here.

## [0.3.1] — 2026-03-17

### Fixed
- **LSP server crash fix** — `send_notification` → `protocol.notify` for pygls 2.0 compatibility; resolves `AttributeError` that prevented scanning from working

## [0.3.0] — 2026-03-13

### Added
- **Java / Go language support** — full AST + taint analysis via TaintGraph for Java (Servlet, Spring) and Go (net/http, Gin)
- **PHP Tree-sitter AST upgrade** — 8 PHP rules (SQLi, XSS, RCE, Path Traversal, Credentials, Deserialization, SSRF, Open Redirect) upgraded from line-level regex to Tree-sitter AST analysis
- **PhpAnalyzer** added to `_LANGUAGE_ANALYZER_MAP`; `analyze_php()` now uses `_analyze_with()` with regex fallback
- 16 PHP AST test fixtures (8 TP + 8 FP)

### Improved
- **NodeGoat benchmark: F1 0.62 → 1.00** — Precision 44.4% → 100%, 12 TP / 0 FP / 0 FN
- NoSQL injection: route-layer DAO skip, 4+ arg DAO skip, update `$set` fall-through fix
- Hardcoded credentials: seed file skip to eliminate false positives
- Open redirect: ±3 line dedup to remove duplicate findings
- XSS: string-literal exclusion for precision improvement

### Fixed
- Ground truth expanded from 7 → 12 entries for comprehensive NodeGoat validation

## [0.2.0] — 2026-03-02

### Added
- **NoSQL injection: `insert` / `insertMany` detection** — DAO-layer `insert()` calls with variable arguments now correctly flagged as `NOSQL_INJECTION High` (fixed `memos-dao.js` false negative in NodeGoat)
- **NoSQL injection: `$set` nested taint detection** — `update(filter, {$set: {field: taintedVar}})` second-argument analysis; catches `benefits-dao.js` pattern
- **`_has_tainted_update_operator` method** — recursive check of `$set/$push/$addToSet/$pull` operator values for tainted variables or DAO-context identifiers
- **DAO-context sanitizer bypass** — `guard_clause_validation` false sanitization of same-name variables across scopes no longer suppresses `insert` findings in DAO files
- **`tests/rules/` test suite** — 19 parametrized pass/fail sample tests covering all 7 vulnerability rule categories (NoSQL, SQLi, XSS, RCE, Path Traversal, Hardcoded Credentials, Deserialization)
- **`ground_truth_nodegoat.json` updated** — added 2 `HARDCODED_CREDENTIALS` entries for `development.js` and `test.js` `zapApiKey`

### Improved
- **`HARDCODED_CREDENTIALS._is_placeholder`** — now filters `_here`-suffix values (`session_cookie_secret_key_here`), `<placeholder>` wrappers, `your_*`/`change_*` prefixes, ALL_CAPS patterns, and low-entropy short strings (< 8 chars, all lowercase)
- **NodeGoat benchmark**: F1 `0.36 → 0.62`, Recall `66.7% → 100%`, NoSQL TP `1 → 3` (all 3 NoSQL findings detected)

### Fixed
- `insert` (legacy MongoDB API) added to `MONGO_SINKS` — was missing from the sink list despite `insertOne`/`insertMany` being present

## [0.1.2] — 2026-02-14

### Added
- Status bar integration with 4 states: `Secure / N issues / Scanning / Disconnected`
- Code Action (lightbulb) with AI auto-replacement when confidence ≥ 0.75
- PHP TaintGraph rules (SQLi, RCE, XSS, Open Redirect)
- Cross-file taint propagation via `CrossFileAnalyzer`
- Performance optimizer: incremental scan cache + parallel file processing

### Fixed
- `this` keyword handling in member expression extraction
- Crypto API false positives for `.update()` method (SHA256, HMAC, Buffer)

## [0.1.0] — 2026-01-20

### Initial Release
- LSP-based real-time scanning via `pygls` + Tree-sitter
- JavaScript/TypeScript/Python/PHP support
- 8 vulnerability rule categories
- DeepSeek AI integration for auto-fix suggestions
