# Changelog

All notable changes to Aegis AI Security Scanner are documented here.

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
