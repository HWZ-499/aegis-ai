# Changelog

All notable changes to the aegis-ai-core package are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-03-18

### Added

- **Inline Suppression Code Actions (O1)** — LSP server now provides 3 Code Actions per Aegis diagnostic:
  - "Ignore this finding" — generates language-aware `aegis-ignore: RULE_ID` comment
  - "Ignore all on this line" — generates `aegis-ignore` comment (no rule filter)
  - "Add to baseline" — triggers `aegis.addToBaseline` command to persist suppression
- **`aegis.addToBaseline` LSP command** — writes finding to `.aegis-baseline.json` at workspace root, then re-validates the document to clear suppressed diagnostics
- **`aegis/generateFix` LSP request** — generates AI fix code for diff preview, reuses AI cache, returns `fixed_code`, `confidence`, `start_line`, `end_line`, `requires_review`
- **Baseline filtering in scan pipeline** — `_validate_document()` now calls `filter_suppressed_findings()` for inline comments and `Baseline.contains()` for `.aegis-baseline.json` entries before publishing diagnostics

## [1.2.1] - 2026-03-17

### Fixed

- **LSP crash**: `AttributeError: 'LanguageServer' object has no attribute 'send_notification'` — migrated 6 calls from deprecated `server.send_notification()` to `server.protocol.notify()` for pygls 2.0 compatibility

## [1.2.0] - 2026-03

### Added

- Baseline / Suppression: `.aegis-baseline.json`, `--baseline`, `--update-baseline`, line-level `aegis-ignore` comments
- Diff-only scanning: `--incremental --base-ref`, line-level diff filter in IncrementalScanner
- Custom rules: `--rules-dir`, `.aegis/rules/`, LSP `initializationOptions.rules_dirs`
- PyPI publish workflow (Trusted Publishing), README install note `pip install aegis-ai-core`

### Changed

- CLI default engine: `new` (legacy remains available via `--engine legacy`)
- LSP/extension: scanError notification, file size limit, scan timeout
- Core modules: `print()` migrated to `logging` in analysis/scanner (CLI user output unchanged)
- **Exception handling**: narrowed 120+ broad `except Exception` to specific types across 36 source files; only 7 intentional top-level defensive catches remain
- **Import migration**: all imports from deprecated `ast_analyzer` / `security_rules` migrated to `rule_engine`
- **Module hygiene**: `aegis_server.py` ChromaDB lazy init (no import-time side effects); `rag_system.py` wrapped in `__main__` guard
- **Test normalization**: 10 test files standardized to pure pytest style (removed script-style `main()`, `sys.path` hacks)
- **CORS hardening**: default origins changed from `*` to `localhost:3000,localhost:8080`
- **VSCode Webview security**: injected CSP meta tag, disabled `enableScripts`
- **Dependency docs**: `openai` optional dependency documented in `requirements.txt`

### Fixed

- Silent exception handling in LSP server (replaced `except Exception: pass` with logger)
- Build backend in pyproject.toml: `setuptools.build_meta`
- `false_positive_manager.py`: `created_at` field now stores ISO timestamp instead of `str(Path.cwd())`
- `aegis_server.py`: removed duplicate `MAX_CODE_LENGTH` definition in `audit_code()`

## [1.1.0] - 2026-02

### Added

- NoSQL injection: DAO insert variable args, `$set` nested operator taint, legacy `insert()` in MONGO_SINKS
- Guard clause scope fix for cross-scope same-name variable purification
- HARDCODED_CREDENTIALS: placeholder / low-entropy filters to reduce false positives
- Tests: `tests/rules/` TP/FP for 7 vulnerability types
- Cross-file taint: CrossFileAnalyzer, CommonJS module.exports

### Changed

- NodeGoat recall to 100%, F1 to 0.62

## [1.0.0] - 2026-01

### Added

- Core SAST engine: JS/TS/Python/PHP (Tree-sitter AST)
- Taint analysis: TaintGraph, Guard Clause, Dominator Tree
- LSP server (pygls): diagnostics, Code Action, Status Bar
- AI remediation: rich context, framework-aware prompt, high-confidence replace
- SARIF and HTML report output
- CLI: `aegis-scan`, `aegis-lsp` entry points

[1.2.0]: https://github.com/aegis-ai/aegis-ai/releases/tag/v1.2.0
[1.1.0]: https://github.com/aegis-ai/aegis-ai/releases/tag/v1.1.0
[1.0.0]: https://github.com/aegis-ai/aegis-ai/releases/tag/v1.0.0
