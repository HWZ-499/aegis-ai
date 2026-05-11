# Code Review Findings

Generated: 2026-04-26 16:47:50 +08:00
Last updated: 2026-04-27

This document records the issues found so far during the staged code quality review. It is a working review log, not a remediation plan. No code changes were made as part of these findings.

## Scope So Far

- Reviewed source scope: `aegis-ai-core/src` and `aegis-vscode/src`
- Counted source file types: `.py`, `.ts`, `.yaml`, `.yml`
- Excluded from remaining count: tests, docs, generated/cache directories, benchmark input directories
- Total core source files counted: 131
- Files reviewed so far: 131
- Files remaining after batch 16: 0

## Reviewed Files

### Batch 1

- `aegis-ai-core/src/lsp/server.py`
- `aegis-ai-core/src/scanner/project_scanner.py`
- `aegis-ai-core/src/analysis/rule_engine.py`
- `aegis-ai-core/src/scanner/cli.py`
- `aegis-ai-core/src/scanner/ai_analyzer.py`

### Batch 2

- `aegis-vscode/src/extension.ts`
- `aegis-vscode/src/backendBootstrap.ts`
- `aegis-vscode/src/reportWebview.ts`
- `aegis-vscode/src/taintPathWebview.ts`
- `aegis-vscode/src/findingsTreeProvider.ts`

### Batch 3

- `aegis-ai-core/src/scanner/report_generator.py`
- `aegis-ai-core/src/scanner/baseline.py`
- `aegis-ai-core/src/scanner/incremental_scanner.py`
- `aegis-ai-core/src/scanner/performance_optimizer.py`
- `aegis-ai-core/src/analysis/taint/taint_analyzer.py`

### Batch 4

- `aegis-ai-core/src/core/config.py`
- `aegis-ai-core/src/core/models.py`
- `aegis-ai-core/src/analysis/taint/source_sink_registry.py`
- `aegis-ai-core/src/analysis/taint/taint_graph.py`
- `aegis-ai-core/src/scanner/rag_enhancer.py`

### Batch 5

- `aegis-ai-core/src/analysis/base/security_rule.py`
- `aegis-ai-core/src/analysis/analyzers/javascript_analyzer.py`
- `aegis-ai-core/src/analysis/analyzers/python_analyzer.py`
- `aegis-ai-core/src/analysis/dsl/dsl_engine.py`
- `aegis-ai-core/src/analysis/dsl/rule_schema.py`

### Batch 6

- `aegis-ai-core/src/analysis/base/analysis_context.py`
- `aegis-ai-core/src/analysis/base/file_context.py`
- `aegis-ai-core/src/analysis/base/dataflow_tracker.py`
- `aegis-ai-core/src/analysis/base/js_dataflow_collector.py`
- `aegis-ai-core/src/analysis/base/user_input_detector.py`

### Batch 7

- `aegis-ai-core/src/analysis/analyzers/java_analyzer.py`
- `aegis-ai-core/src/analysis/analyzers/go_analyzer.py`
- `aegis-ai-core/src/analysis/analyzers/php_analyzer.py`
- `aegis-ai-core/src/analysis/multi_language_ast.py`
- `aegis-ai-core/src/analysis/ast_analyzer.py`

### Batch 8

- `aegis-ai-core/src/analysis/rules/sql_injection/javascript_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/xss/javascript_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/rce/javascript_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/path_traversal/javascript_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/nosql_injection/javascript_ast_rule.py`

### Batch 9

- `aegis-ai-core/src/analysis/rules/deserialization/ast_rule.py`
- `aegis-ai-core/src/analysis/rules/deserialization/javascript_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/deserialization/go_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/deserialization/java_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/deserialization/php_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/ssrf/python_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/ssrf/javascript_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/open_redirect/javascript_ast_rule.py`

### Batch 10

- `aegis-ai-core/src/analysis/rules/open_redirect/python_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/open_redirect/java_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/open_redirect/go_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/open_redirect/php_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/path_traversal/ast_rule.py`
- `aegis-ai-core/src/analysis/rules/path_traversal/java_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/path_traversal/go_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/path_traversal/php_ast_rule.py`

### Batch 11

- `aegis-ai-core/src/analysis/rules/sql_injection/ast_rule.py`
- `aegis-ai-core/src/analysis/rules/sql_injection/go_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/sql_injection/java_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/sql_injection/php_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/sql_injection/regex_rule.py`
- `aegis-ai-core/src/analysis/rules/xss/ast_rule.py`
- `aegis-ai-core/src/analysis/rules/xss/java_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/xss/go_ast_rule.py`

### Batch 12

- `aegis-ai-core/src/analysis/rules/hardcoded_credentials/ast_rule.py`
- `aegis-ai-core/src/analysis/rules/hardcoded_credentials/javascript_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/hardcoded_credentials/java_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/hardcoded_credentials/go_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/hardcoded_credentials/php_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/nosql_injection/python_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/nosql_injection/java_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/nosql_injection/go_ast_rule.py`

### Batch 13

- `aegis-ai-core/src/analysis/rules/rce/ast_rule.py`
- `aegis-ai-core/src/analysis/rules/rce/go_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/rce/java_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/rce/php_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/xss/php_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/nosql_injection/php_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/php/php_taint_rules.py`
- `aegis-ai-core/src/analysis/rules/__init__.py`

### Batch 14

- `aegis-ai-core/src/analysis/security_rules.py`
- `aegis-ai-core/src/analysis/dependency_tracker.py`
- `aegis-ai-core/src/analysis/incremental_analyzer.py`
- `aegis-ai-core/src/analysis/rule_based_audit.py`
- `aegis-ai-core/src/analysis/dsl/dsl_adapter.py`
- `aegis-ai-core/src/analysis/taint/cross_file_analyzer.py`
- `aegis-ai-core/src/scanner/false_positive_manager.py`
- `aegis-ai-core/src/scanner/rule_config.py`
- `aegis-ai-core/src/scanner/smart_remediation.py`
- `aegis-ai-core/src/scanner/taint_enhancer.py`
- `aegis-ai-core/src/analysis/rules/dsl/go.hardcoded-password.yaml`
- `aegis-ai-core/src/analysis/rules/dsl/go.sql-injection-concat.yaml`
- `aegis-ai-core/src/analysis/rules/dsl/javascript.sql-injection-concat.yaml`
- `aegis-ai-core/src/analysis/rules/dsl/javascript.xss-innerhtml.yaml`
- `aegis-ai-core/src/analysis/rules/dsl/javascript.xss-response-send.yaml`
- `aegis-ai-core/src/analysis/rules/dsl/python.hardcoded-password.yaml`
- `aegis-ai-core/src/analysis/rules/dsl/python.sql-injection-format.yaml`
- `aegis-ai-core/src/analysis/rules/dsl/python.xss-marksafe.yaml`

### Batch 15

- `aegis-ai-core/src/analysis/cfg/dominator_tree.py`
- `aegis-ai-core/src/core/logging_config.py`
- `aegis-ai-core/src/lsp/__main__.py`
- `aegis-ai-core/src/worker_daemon.py`
- `aegis-vscode/src/aiFixResult.ts`
- `aegis-vscode/src/aiPreflight.ts`
- `aegis-vscode/src/baselineTreeProvider.ts`
- `aegis-vscode/src/commentCommands.ts`
- `aegis-vscode/src/fixPreviewProvider.ts`
- `aegis-vscode/src/pythonProbe.ts`
- `aegis-vscode/src/serverCwd.ts`

### Batch 16

- `aegis-ai-core/src/__init__.py`
- `aegis-ai-core/src/analysis/__init__.py`
- `aegis-ai-core/src/analysis/analyzers/__init__.py`
- `aegis-ai-core/src/analysis/base/__init__.py`
- `aegis-ai-core/src/analysis/cfg/__init__.py`
- `aegis-ai-core/src/analysis/dsl/__init__.py`
- `aegis-ai-core/src/analysis/rules/deserialization/__init__.py`
- `aegis-ai-core/src/analysis/rules/hardcoded_credentials/__init__.py`
- `aegis-ai-core/src/analysis/rules/nosql_injection/__init__.py`
- `aegis-ai-core/src/analysis/rules/open_redirect/__init__.py`
- `aegis-ai-core/src/analysis/rules/path_traversal/__init__.py`
- `aegis-ai-core/src/analysis/rules/php/__init__.py`
- `aegis-ai-core/src/analysis/rules/rce/__init__.py`
- `aegis-ai-core/src/analysis/rules/sql_injection/__init__.py`
- `aegis-ai-core/src/analysis/rules/ssrf/__init__.py`
- `aegis-ai-core/src/analysis/rules/xss/__init__.py`
- `aegis-ai-core/src/analysis/taint/__init__.py`
- `aegis-ai-core/src/core/__init__.py`
- `aegis-ai-core/src/lsp/__init__.py`
- `aegis-ai-core/src/scanner/__init__.py`
- `aegis-ai-core/src/scanner/benchmark.py`
- `aegis-ai-core/src/scanner/benchmark_cases.py`

## Findings

### Batch 1 Findings

#### 1. Timeout does not actually stop LSP scans

- Position: `aegis-ai-core/src/lsp/server.py:1577-1594`
- Reason: The scan is submitted to a `ThreadPoolExecutor` and `future.result(timeout=...)` is used, but leaving the `with` block calls `executor.shutdown(wait=True)`, so the timed-out worker can still block until it completes.
- Impact: A scan that appears timed out can still block the LSP. The timeout path also publishes zero findings, which can look like a clean scan.
- Priority: P1
- Fix immediately: Yes

#### 2. CodeAction provider calls AI before explicit fix request

- Position: `aegis-ai-core/src/lsp/server.py:946-1164`
- Reason: The code action provider constructs `AIAnalyzer` and calls `analyze_finding` while building available actions.
- Impact: VS Code can request code actions just to show the lightbulb, so source code can be sent to the configured AI provider before the user explicitly chooses an AI fix.
- Priority: P1
- Fix immediately: Yes

#### 3. Workspace scan only scans open documents

- Position: `aegis-ai-core/src/lsp/server.py:863-883`
- Reason: The workspace scan command iterates `server.workspace._documents`.
- Impact: Unopened files in the workspace are not scanned, even though the UI command is named workspace scan.
- Priority: P1
- Fix immediately: Yes

#### 4. File scan failures become empty findings

- Position: `aegis-ai-core/src/scanner/project_scanner.py:516-518`
- Reason: `scan_file` catches `OSError`, `UnicodeDecodeError`, and `RuntimeError`, logs a warning, and returns an empty list.
- Impact: Callers cannot distinguish a clean file from a failed scan, which is risky for a security scanner and weakens CLI/report correctness.
- Priority: P1
- Fix immediately: Yes

#### 5. Rule engine hides analyzer failures

- Position: `aegis-ai-core/src/analysis/rule_engine.py:397-408`
- Reason: `_analyze_with` logs analyzer exceptions and returns an empty list.
- Impact: LSP and CLI can silently turn a broken analyzer into "no findings".
- Priority: P1
- Fix immediately: Yes

#### 6. AI result cache key ignores file and code context

- Position: `aegis-ai-core/src/scanner/ai_analyzer.py:584-591`
- Reason: The cache key only uses vulnerability type plus an MD5 hash of the first 100 characters of details.
- Impact: AI output depends on file, line, language, and code context, so similar findings in different files can reuse an unrelated `fixed_code` result.
- Priority: P1
- Fix immediately: Yes

#### 7. CLI stdout wraps JSON and SARIF with banners

- Position: `aegis-ai-core/src/scanner/cli.py:158-163`, `aegis-ai-core/src/scanner/cli.py:195-196`, `aegis-ai-core/src/scanner/cli.py:383-386`, `aegis-ai-core/src/scanner/cli.py:390-414`
- Reason: The CLI prints progress banners, labels, and statistics to stdout around machine-readable output.
- Impact: `--format json` or `--format sarif` without `--output` can produce stdout that is not valid JSON/SARIF, breaking CI and tool integration.
- Priority: P2
- Fix immediately: Yes, if stdout output is intended for automation

#### 8. Hard-coded rule registration is easy to drift

- Position: `aegis-ai-core/src/analysis/rule_engine.py:31-78`, `aegis-ai-core/src/analysis/rule_engine.py:271-325`
- Reason: Rule classes are imported and registered manually in language-specific lists.
- Impact: New analyzers or rules can be implemented but omitted from the active default set, producing silent coverage gaps.
- Priority: P3
- Fix immediately: No, but it should be addressed before expanding the rule set further

### Batch 2 Findings

#### 9. Taint path webview can break out of inline handler

- Position: `aegis-vscode/src/taintPathWebview.ts:130-140`
- Reason: `filePath` is inserted into an inline `onclick` JavaScript string after HTML escaping only. The escaping function does not escape single quotes, backslashes, or JavaScript line terminators.
- Impact: With `enableScripts=true`, crafted finding data can break out of `jumpTo('...')` and execute script in the webview.
- Priority: P1
- Fix immediately: Yes

#### 10. AI fix apply range is computed incorrectly

- Position: `aegis-vscode/src/extension.ts:408-445`
- Reason: `fixEnd` is used as a zero-based end line while the character is taken from `lines[fixEnd - 1]`.
- Impact: One-line fixes can target the next line with the previous line's character length, and last-line fixes can point past the document. This can fail or replace the wrong range.
- Priority: P1
- Fix immediately: Yes

#### 11. Applying preview ignores document changes

- Position: `aegis-vscode/src/extension.ts:405-447`
- Reason: The diff preview is built from the document text at request time, but the later apply path does not verify document version or current text.
- Impact: If the user edits while the preview is open, the extension can apply the AI replacement to stale line numbers.
- Priority: P2
- Fix immediately: Yes

#### 12. Workspace scan progress can hang

- Position: `aegis-vscode/src/extension.ts:302-325`
- Reason: `scanWorkspace` creates a promise that only resolves when scan progress reports completion. There is no timeout, cancellation, or LSP error completion path.
- Impact: A server-side failure before the final progress notification leaves the progress UI unresolved.
- Priority: P2
- Fix immediately: Yes

#### 13. Bundled backend stamp can reuse stale code

- Position: `aegis-vscode/src/backendBootstrap.ts:165-183`
- Reason: The managed backend cache stamp only compares backend path, backend version, and bootstrap version.
- Impact: If bundled backend content or dependencies change without a version bump, the extension can reuse the old copied backend and virtual environment.
- Priority: P2
- Fix immediately: Yes

#### 14. Extension config changes are not synced to LSP

- Position: `aegis-vscode/src/extension.ts:771-776`
- Reason: The configuration change listener only handles `aegisAI.showSuppressedFindings`.
- Impact: Other extension configuration changes can be ignored until restart, so UI settings and backend scanning behavior can diverge.
- Priority: P2
- Fix immediately: Not urgent for all settings, but should be fixed before relying on live configuration updates

#### 15. FindingsTreeProvider listeners are not disposed

- Position: `aegis-vscode/src/findingsTreeProvider.ts:67-72`
- Reason: `languages.onDidChangeDiagnostics` and `window.onDidChangeActiveTextEditor` subscriptions are created but not stored or disposed.
- Impact: Listeners can leak across provider lifetimes, especially in extension reloads and tests.
- Priority: P3
- Fix immediately: No

### Batch 3 Findings

#### 16. Incremental scan misses untracked files

- Position: `aegis-ai-core/src/scanner/incremental_scanner.py:68-100`
- Reason: `get_changed_files` only uses Git diffs against HEAD and staged changes.
- Impact: Newly created vulnerable source files are not returned, so incremental scans can report zero issues while untracked vulnerable files exist.
- Priority: P1
- Fix immediately: Yes

#### 17. Non-Git incremental scan silently scans nothing

- Position: `aegis-ai-core/src/scanner/incremental_scanner.py:63-66`
- Reason: The message says non-Git projects will scan all files, but the implementation returns an empty set and `scan_incremental` treats that as no modified files.
- Impact: Users running `--incremental` outside a Git repo get a clean empty result instead of a full scan.
- Priority: P1
- Fix immediately: Yes

#### 18. Parallel optimizer is not parallel

- Position: `aegis-ai-core/src/scanner/performance_optimizer.py:375-392`
- Reason: When `use_parallel` is enabled, the code enters the parallel branch but still loops over files sequentially with `scan_func`.
- Impact: The option name and project scanner wiring imply parallel speedup, but the implementation does not use the parallel executor.
- Priority: P2
- Fix immediately: No, unless scan performance is a current release goal

#### 19. Cache invalidation misses analyzer and DSL changes

- Position: `aegis-ai-core/src/scanner/performance_optimizer.py:55-85`
- Reason: The cache key hashes a limited set of rule files and omits analyzers, taint registries, DSL YAML rules, and scanner configuration.
- Impact: Rule behavior can change while cached findings remain valid by key, causing stale or wrong scan results.
- Priority: P2
- Fix immediately: Yes

#### 20. Corrupt baseline is treated as empty

- Position: `aegis-ai-core/src/scanner/baseline.py:75-95`
- Reason: `Baseline.load` returns an empty baseline on JSON or I/O errors without surfacing the failure.
- Impact: With `--update-baseline`, a corrupt or temporarily unreadable baseline can be overwritten, silently losing suppressions.
- Priority: P2
- Fix immediately: Yes

#### 21. Markdown report does not escape finding content and hardcodes Python fences

- Position: `aegis-ai-core/src/scanner/report_generator.py:122-152`
- Reason: Markdown report generation inserts file paths, details, and content directly, and always uses a `python` code fence.
- Impact: Finding content can break report formatting or inject misleading Markdown. Non-Python findings are mislabeled.
- Priority: P2
- Fix immediately: Yes

#### 22. SARIF output drops character-level ranges

- Position: `aegis-ai-core/src/scanner/report_generator.py:510-528`
- Reason: SARIF generation reads `column` and `end_column` but not the newer `start_character` and `end_character` fields used by LSP diagnostics.
- Impact: SARIF annotations can be imprecise even when the scanner has character-level data.
- Priority: P2
- Fix immediately: Not urgent, but should be fixed for CI and GitHub annotations

#### 23. Taint analyzer failures become empty findings

- Position: `aegis-ai-core/src/analysis/taint/taint_analyzer.py:180-214`, `aegis-ai-core/src/analysis/taint/taint_analyzer.py:236-237`
- Reason: File/code/tree analysis failures are logged and return an empty list.
- Impact: Taint analysis can fail while CLI and LSP display a clean result.
- Priority: P1
- Fix immediately: Yes

### Batch 4 Findings

#### 24. `AEGIS_` prefixed environment variables do not actually work

- Position: `aegis-ai-core/src/core/config.py:49-68`
- Reason: The file header says `AEGIS_DEEPSEEK_API_KEY` and similar prefixed variables are supported, but `model_config` has no `env_prefix`, and field defaults read unprefixed names such as `DEEPSEEK_API_KEY`, `OPENAI_API_KEY`, and `CORS_ALLOW_ORIGINS`.
- Impact: Deployments configured according to the documented `AEGIS_` prefix can miss API keys or CORS settings.
- Priority: P2
- Fix immediately: Yes, before deployment documentation is trusted

#### 25. Path normalization is treated as path traversal sanitization

- Position: `aegis-ai-core/src/analysis/taint/source_sink_registry.py:1519-1533`, `aegis-ai-core/src/analysis/taint/source_sink_registry.py:1587-1593`, `aegis-ai-core/src/analysis/taint/source_sink_registry.py:1658-1664`
- Reason: `path.normalize`, `path.resolve`, `os.path.normpath`, and `realpath` are registered as path traversal sanitizers even though normalization alone does not verify an allowed directory boundary.
- Impact: The scanner can downgrade or skip still-vulnerable path traversal flows.
- Priority: P1
- Fix immediately: Yes

#### 26. Sanitized state is tracked only by variable name

- Position: `aegis-ai-core/src/analysis/taint/taint_graph.py:421-440`
- Reason: `is_var_tainted` first checks whether `var_name` exists in `_sanitized_names`, and `mark_sanitized` stores only the variable name without file path, scope, or line range.
- Impact: A sanitized variable in one file or function can cause a same-named variable elsewhere to be treated as clean.
- Priority: P1
- Fix immediately: Yes

#### 27. Taint path sanitization ignores vulnerability type

- Position: `aegis-ai-core/src/analysis/taint/taint_graph.py:544-561`
- Reason: A path is marked sanitized if any intermediate node is a sanitizer. The implementation does not compare the sanitizer's categories with the sink category.
- Impact: XSS, SQL, path traversal, and command sanitizers can be mixed incorrectly, causing true findings to be downgraded or skipped.
- Priority: P1
- Fix immediately: Yes

#### 28. RAG timeout does not actually release blocking work

- Position: `aegis-ai-core/src/scanner/rag_enhancer.py:610-620`
- Reason: `future.result(timeout=...)` returns on timeout, but leaving the `with ThreadPoolExecutor` block waits for the worker thread.
- Impact: A stuck ChromaDB or RAG retrieval can still block scanning despite the timeout comment saying it should skip RAG.
- Priority: P2
- Fix immediately: Yes

#### 29. XSS remediation suggests a dangerous Angular bypass API

- Position: `aegis-ai-core/src/scanner/rag_enhancer.py:270-273`
- Reason: The built-in XSS remediation suggests `bypassSecurityTrustHtml` in the "must use innerHTML" case.
- Impact: That API bypasses Angular's security model and can mislead users into introducing XSS risk.
- Priority: P2
- Fix immediately: Yes

#### 30. `related_locations` parsing failures are silently dropped

- Position: `aegis-ai-core/src/core/models.py:135-151`
- Reason: `from_legacy_dict` catches `TypeError` and `ValueError` while parsing related locations and directly `pass`es.
- Impact: Taint path and related location context can disappear from LSP diagnostics and reports with no visible reason.
- Priority: P3
- Fix immediately: No

### Batch 5 Findings

#### 31. `safe_find_paths` hides taint path failures

- Position: `aegis-ai-core/src/analysis/base/security_rule.py:94-103`
- Reason: `safe_find_paths` catches `RuntimeError` and `ValueError` from `graph.find_paths_to_sinks()`, logs only at debug level, and returns an empty list.
- Impact: Rules that depend on taint paths behave as if no exploitable path exists, which can suppress real findings.
- Priority: P1
- Fix immediately: Yes

#### 32. JavaScript analyzer swallows taint and AST failures

- Position: `aegis-ai-core/src/analysis/analyzers/javascript_analyzer.py:91-106`
- Reason: The analyzer sets `context.taint_graph = None` when `TaintAnalyzer` fails and silently `pass`es when AST parsing or traversal raises `RuntimeError` or `ValueError`.
- Impact: Most JS/TS rules depend on AST or taint graph state, so a broken parser or taint build can degrade into partial or empty findings without surfacing a scan error.
- Priority: P1
- Fix immediately: Yes

#### 33. TypeScript files use the JavaScript grammar

- Position: `aegis-ai-core/src/analysis/analyzers/javascript_analyzer.py:49-55`
- Reason: `JavaScriptAnalyzer` accepts `language="typescript"`, but the parser is always initialized with `get_language("javascript")`.
- Impact: TypeScript-only syntax can produce parse errors or malformed trees, causing TypeScript findings to be missed or inconsistently analyzed.
- Priority: P2
- Fix immediately: Not urgent, but should be fixed before relying on TypeScript coverage

#### 34. Python syntax errors become clean scan results

- Position: `aegis-ai-core/src/analysis/analyzers/python_analyzer.py:91-96`
- Reason: When `ast.parse` raises `SyntaxError`, `analyze` returns an empty list.
- Impact: An unparsed file becomes indistinguishable from a clean file, and callers receive no error state explaining that Python AST rules did not run.
- Priority: P1
- Fix immediately: Yes

#### 35. Invalid DSL rule files are silently ignored

- Position: `aegis-ai-core/src/analysis/dsl/dsl_engine.py:36-46`
- Reason: YAML parse errors, file read errors, and Pydantic validation errors are all swallowed with `continue`.
- Impact: A broken built-in or project-provided DSL rule can be skipped without warning, so users may believe custom rules are active when they are not.
- Priority: P2
- Fix immediately: Yes

#### 36. DSL regex errors are not surfaced consistently

- Position: `aegis-ai-core/src/analysis/dsl/dsl_engine.py:97-164`, `aegis-ai-core/src/analysis/dsl/rule_schema.py:17-40`
- Reason: Invalid pattern regexes are converted into a never-match regex, while metavariable constraint regexes are not validated in the schema and are evaluated later during matching.
- Impact: A malformed DSL rule can either silently disable itself or raise at scan time, depending on which regex is malformed.
- Priority: P2
- Fix immediately: Yes

### Batch 6 Findings

#### 37. Finding deduplication drops distinct issues on the same line

- Position: `aegis-ai-core/src/analysis/base/analysis_context.py:154-180`
- Reason: `AnalysisContext.add_finding` deduplicates findings by `(rule_id, line, type)` only. It does not include column, sink expression, source expression, details, or range. For `Finding` model instances it also reads `getattr(finding, "type", "")`, while the model field is `vuln_type`.
- Impact: Multiple distinct findings emitted by the same rule on one line can collapse into one result, especially in compact JavaScript/PHP lines or generated code.
- Priority: P2
- Fix immediately: Yes

#### 38. Legacy `DataFlowTracker` treats unsafe conversions as universal sanitizers

- Position: `aegis-ai-core/src/analysis/base/dataflow_tracker.py:167-202`, `aegis-ai-core/src/analysis/base/dataflow_tracker.py:272-286`, `aegis-ai-core/src/analysis/base/dataflow_tracker.py:440-446`
- Reason: The tracker marks variables as sanitized when assigned from broad functions such as `path.normalize`, `path.resolve`, `String`, `Boolean`, `str`, `os.path.normpath`, and `validator.isEmail`. It then exposes only a boolean `is_sanitized` query without vulnerability category.
- Impact: Rules across SQLi, XSS, RCE, path traversal, deserialization, and NoSQL can treat unrelated or incomplete transformations as sufficient sanitization, causing false negatives.
- Priority: P1
- Fix immediately: Yes

#### 39. Sanitizer detection strips namespaces and matches unrelated local functions

- Position: `aegis-ai-core/src/analysis/base/dataflow_tracker.py:528-543`
- Reason: `_detect_sanitizer_call` accepts both `func_name + "("` and the last segment after `.`. This makes `DOMPurify.sanitize` match any `sanitize(...)`, `path.resolve` match any `resolve(...)`, and `os.path.basename` match any `basename(...)`.
- Impact: Local helper functions with these names can mark tainted values as clean even when they do not perform security sanitization.
- Priority: P2
- Fix immediately: Yes

#### 40. Seed/migration detection is too broad and is used to skip findings

- Position: `aegis-ai-core/src/analysis/base/file_context.py:12-67`
- Reason: The default heuristic treats any path containing broad substrings such as `schema`, `fixture`, `artifacts`, or `seed` as seed/migration context. Current callers use the default non-strict mode to skip hardcoded credential, SQL template, and NoSQL insert findings.
- Impact: Business files with names like `schemaValidator.js`, `seedUserController.js`, or paths under unrelated `artifacts` directories can suppress real findings.
- Priority: P2
- Fix immediately: Yes

#### 41. JavaScript dataflow collector is not wired into the analyzer

- Position: `aegis-ai-core/src/analysis/base/js_dataflow_collector.py:57-91`
- Reason: `JavaScriptDataFlowCollector` is implemented as a `SecurityRule`, but repository-wide search found only its definition and export, with no registration in the default JavaScript rule list or analyzer setup.
- Impact: The collector does not populate `context.dataflow_tracker`; if the newer taint graph path is unavailable, this intended fallback dataflow layer is effectively dead code.
- Priority: P3
- Fix immediately: No

### Batch 7 Findings

#### 42. Java analyzer hides taint and AST failures

- Position: `aegis-ai-core/src/analysis/analyzers/java_analyzer.py:73-97`
- Reason: Java taint graph construction catches `ImportError`, `RuntimeError`, and `ValueError` and only sets `context.taint_graph = None`; AST parsing/traversal failures are also swallowed with `pass`.
- Impact: Java AST rules can run with missing taint context or not run at all while callers still receive a normal findings list, making parser/analyzer failure look like a clean or partial scan.
- Priority: P1
- Fix immediately: Yes

#### 43. Go analyzer hides taint and AST failures

- Position: `aegis-ai-core/src/analysis/analyzers/go_analyzer.py:73-97`
- Reason: Go taint graph construction catches analyzer failures and clears `context.taint_graph`; AST parsing/traversal failures are swallowed with `pass`.
- Impact: Go rules can silently lose taint precision or skip AST visits without surfacing a scan error, weakening confidence in Go scan results.
- Priority: P1
- Fix immediately: Yes

#### 44. PHP AST traversal depends on taint graph success

- Position: `aegis-ai-core/src/analysis/analyzers/php_analyzer.py:79-103`
- Reason: PHP only traverses AST when both `self._parser` and `context.taint_graph` are present. If `TaintAnalyzer` fails, AST visitor rules are skipped even though the parser may still be usable; failures are logged only at debug level.
- Impact: A taint graph failure can disable PHP AST rules and produce incomplete results with no visible error.
- Priority: P1
- Fix immediately: Yes

#### 45. Legacy multi-language analyzer parses TypeScript as JavaScript

- Position: `aegis-ai-core/src/analysis/multi_language_ast.py:73-80`, `aegis-ai-core/src/analysis/multi_language_ast.py:206-209`, `aegis-ai-core/src/analysis/multi_language_ast.py:263-271`
- Reason: `.ts` and `.tsx` files are classified as TypeScript, but the analyzer assigns the JavaScript parser to `self.parsers["typescript"]` and `_analyze_javascript` later always uses `self.parsers["javascript"]`.
- Impact: TypeScript-only syntax can be parsed incorrectly or fail in the legacy scan path used by old engine and performance optimizer code, producing missed or inconsistent findings.
- Priority: P2
- Fix immediately: Yes, if legacy or optimized scan paths remain supported

#### 46. Deprecated Python AST analyzer still returns clean results on parse failure

- Position: `aegis-ai-core/src/analysis/ast_analyzer.py:289-304`
- Reason: The deprecated `analyze_code_ast` catches `SyntaxError` and returns an empty list. Despite being deprecated, it is still re-exported through `rule_engine` and used by project scanner legacy paths and performance optimizer code.
- Impact: A Python file that cannot be parsed by this active legacy path is indistinguishable from a clean file.
- Priority: P1
- Fix immediately: Yes

### Batch 8 Findings

#### 47. XSS sanitizer allowlist trusts unrelated local functions

- Position: `aegis-ai-core/src/analysis/rules/xss/javascript_ast_rule.py:76-89`, `aegis-ai-core/src/analysis/rules/xss/javascript_ast_rule.py:157-180`
- Reason: `_is_sanitizer_call` treats any direct or member call named `sanitize`, `escape`, `encode`, `purify`, or similar as an HTML sanitizer without validating the library, namespace, or security contract.
- Impact: Tainted HTML passed through an unrelated local helper such as `encode(userInput)` or `someLib.escape(userInput)` can be treated as safe, suppressing real XSS findings.
- Priority: P1
- Fix immediately: Yes

#### 48. RCE rule skips dynamic template strings in `eval` and `Function`

- Position: `aegis-ai-core/src/analysis/rules/rce/javascript_ast_rule.py:171-173`
- Reason: `_check_eval_or_function` returns immediately for every `template_string` argument, but JavaScript template strings can contain `${...}` interpolations from user-controlled values.
- Impact: Calls such as `eval(`${req.query.code}`)` or `Function(`return ${input}`)` can be missed even though they execute dynamic code.
- Priority: P1
- Fix immediately: Yes

#### 49. RCE command execution detection misses common `child_process` aliases

- Position: `aegis-ai-core/src/analysis/rules/rce/javascript_ast_rule.py:77-108`
- Reason: The rule only reports command execution when the callee is a member expression whose object text is exactly `child_process`. It does not track `require("child_process")` aliases or destructured imports such as `const { exec } = require("child_process")`.
- Impact: Common Node.js patterns like `cp.exec(userInput)` or `exec(userInput)` can bypass the RCE rule.
- Priority: P1
- Fix immediately: Yes

#### 50. Path traversal rule treats `path.join` as a file access sink and suggests unsafe normalization

- Position: `aegis-ai-core/src/analysis/rules/path_traversal/javascript_ast_rule.py:118-120`, `aegis-ai-core/src/analysis/rules/path_traversal/javascript_ast_rule.py:148-156`
- Reason: `_is_file_operation` treats `path.join` itself as a path traversal sink even though it only constructs a string. The generated recommendation also suggests `path.normalize`, which does not prove the resolved path stays inside an allowed directory.
- Impact: The rule can produce false positives on path construction and also recommend an incomplete mitigation for real path traversal issues.
- Priority: P2
- Fix immediately: Yes

#### 51. NoSQL rule skips tainted single-id queries

- Position: `aegis-ai-core/src/analysis/rules/nosql_injection/javascript_ast_rule.py:432-439`, `aegis-ai-core/src/analysis/rules/nosql_injection/javascript_ast_rule.py:628-649`
- Reason: `_is_simple_id_query` returns true for any single `_id` or `id` object whose value is an identifier, and the caller returns without checking whether that identifier is tainted.
- Impact: Patterns such as `const id = req.query.id; users.findOne({ _id: id })` can be skipped, missing NoSQL injection or authorization-sensitive query risks.
- Priority: P1
- Fix immediately: Yes

#### 52. NoSQL operator detection reports static operators as injection

- Position: `aegis-ai-core/src/analysis/rules/nosql_injection/javascript_ast_rule.py:61-80`, `aegis-ai-core/src/analysis/rules/nosql_injection/javascript_ast_rule.py:441-450`, `aegis-ai-core/src/analysis/rules/nosql_injection/javascript_ast_rule.py:651-668`
- Reason: The dangerous operator list includes normal MongoDB operators such as `$exists`, `$type`, and `$text`, and `_has_dangerous_key_or_value` returns true when it sees an operator key without requiring the value to come from user input.
- Impact: Legitimate static filters such as `{ deletedAt: { $exists: false } }` or `$text` searches can be reported as NoSQL injection, increasing noise and reducing trust in findings.
- Priority: P2
- Fix immediately: Yes

#### 53. NoSQL rule treats untracked DAO and DB-call identifiers as user input

- Position: `aegis-ai-core/src/analysis/rules/nosql_injection/javascript_ast_rule.py:806-831`
- Reason: `_contains_identifier_in_object` returns true for any untracked identifier when the file path looks like a DAO/repository or when the caller is considered a DB object, regardless of whether the identifier is a constant, enum, or locally derived safe value.
- Impact: Queries such as `users.find({ role: DEFAULT_ROLE })` in repository files can be reported as injection, creating broad false positives in exactly the files where database code is most common.
- Priority: P2
- Fix immediately: Yes

### Batch 9 Findings

#### 54. Python deserialization rule misses imported aliases and from-import sinks

- Position: `aegis-ai-core/src/analysis/rules/deserialization/ast_rule.py:195-207`, `aegis-ai-core/src/analysis/rules/deserialization/ast_rule.py:235-243`
- Reason: `_extract_module_func` only recognizes direct `module.function(...)` calls and unqualified global function names. It does not track `import pickle as p`, `import yaml as y`, or `from pickle import loads` aliases before looking up `_SINK_INDEX`.
- Impact: Common Python import styles such as `p.loads(request.data)` or `loads(request.data)` can bypass the deserialization rule.
- Priority: P1
- Fix immediately: Yes

#### 55. Python `yaml.load` rule ignores safe Loader arguments

- Position: `aegis-ai-core/src/analysis/rules/deserialization/ast_rule.py:68-75`, `aegis-ai-core/src/analysis/rules/deserialization/ast_rule.py:217-224`
- Reason: `yaml.load` is registered as an unsafe sink, but the visitor only checks the first argument and never inspects keyword or second-position Loader arguments such as `Loader=yaml.SafeLoader`.
- Impact: Safe calls like `yaml.load(data, Loader=yaml.SafeLoader)` can be reported as high-severity deserialization issues, reducing precision.
- Priority: P2
- Fix immediately: Yes

#### 56. JavaScript deserialization taint mode suppresses structured user input fallback

- Position: `aegis-ai-core/src/analysis/rules/deserialization/javascript_ast_rule.py:153-166`
- Reason: When a taint graph or dataflow tracker exists, any identifier-bearing argument that is not explicitly tainted returns before the structured `_looks_like_user_input` fallback runs.
- Impact: Direct inputs such as `JSON.parse(req.body.payload)` or `yaml.load(req.query.config)` can be missed if the exact member expression is not tracked as tainted.
- Priority: P1
- Fix immediately: Yes

#### 57. PHP deserialization treats any `allowed_classes` option as safe

- Position: `aegis-ai-core/src/analysis/rules/deserialization/php_ast_rule.py:44-49`
- Reason: The rule skips `unserialize` whenever the second argument text contains `allowed_classes`, without checking whether the value is actually restrictive.
- Impact: `unserialize($data, ["allowed_classes" => true])` is still unsafe but will be skipped as if it were protected.
- Priority: P1
- Fix immediately: Yes

#### 58. Java deserialization fallback reports same-file source and sink without a dataflow path

- Position: `aegis-ai-core/src/analysis/rules/deserialization/java_ast_rule.py:239-271`
- Reason: If no complete taint path is found, `after_file` still reports when the file contains at least one source and one deserialization sink, without proving that the source reaches the sink.
- Impact: A servlet that reads a request parameter and separately deserializes trusted internal data can be reported as a deserialization vulnerability.
- Priority: P2
- Fix immediately: Yes

#### 59. Java deserialization receiver heuristics over-trust generic variable names

- Position: `aegis-ai-core/src/analysis/rules/deserialization/java_ast_rule.py:41-46`, `aegis-ai-core/src/analysis/rules/deserialization/java_ast_rule.py:132-145`, `aegis-ai-core/src/analysis/rules/deserialization/java_ast_rule.py:324-349`
- Reason: Receiver names such as `decoder` and `ois` are treated as dangerous even when the assignment cannot be resolved. If the same file contains request input, `_receiver_from_untrusted_source` treats the unresolved receiver as untrusted.
- Impact: Generic `decoder.readObject()` code in request-handling files can be flagged even when the decoder is not built from user-controlled data.
- Priority: P2
- Fix immediately: Yes

#### 60. JavaScript SSRF Supertest filter can suppress real sinks inside broad snippets

- Position: `aegis-ai-core/src/analysis/rules/ssrf/javascript_ast_rule.py:74-84`
- Reason: The rule skips a finding if the sink expression contains `request(app)`, `request(this.app)`, or `request(server)`. The comment notes that `sink_expr` may be an entire code block, so a local Supertest call anywhere in that block can suppress another real HTTP sink.
- Impact: A block containing both `request(app)` and `fetch(req.query.url)` can hide the real SSRF sink.
- Priority: P2
- Fix immediately: Yes

#### 61. JavaScript open redirect deduplication skips nearby distinct sinks

- Position: `aegis-ai-core/src/analysis/rules/open_redirect/javascript_ast_rule.py:61-66`
- Reason: The rule deduplicates by line proximity and skips any open redirect sink within three lines of a previously reported line, regardless of sink id or expression.
- Impact: Multiple distinct redirects in a compact handler can collapse into one finding, losing security context and remediation targets.
- Priority: P2
- Fix immediately: Yes

### Batch 10 Findings

#### 62. Java open redirect misses aliased request objects

- Position: `aegis-ai-core/src/analysis/rules/open_redirect/java_ast_rule.py:188-211`
- Reason: `_subtree_has_user_input` special-cases `method_invocation` nodes and only treats receivers named exactly `request` or `req` as Java request input. It then returns without running the generic `is_user_input_node` check on the method invocation.
- Impact: Common code using aliases such as `httpRequest.getParameter("next")` or framework-specific request variable names can flow into `sendRedirect` without being reported by this AST rule.
- Priority: P2
- Fix immediately: Yes

#### 63. PHP open redirect skips tainted header variables unless the argument text contains `location`

- Position: `aegis-ai-core/src/analysis/rules/open_redirect/php_ast_rule.py:44-64`
- Reason: The rule returns immediately when an argument's raw text does not contain `location`, before checking whether that argument is a tainted variable.
- Impact: A pattern such as `$h = "Location: " . $_GET["next"]; header($h);` can be missed because the argument text is only `$h`.
- Priority: P1
- Fix immediately: Yes

#### 64. Python path traversal treats `abspath` and `realpath` as sanitizers

- Position: `aegis-ai-core/src/analysis/rules/path_traversal/ast_rule.py:75-81`, `aegis-ai-core/src/analysis/rules/path_traversal/ast_rule.py:136-152`
- Reason: `_is_sanitized_node` treats `os.path.abspath` and `os.path.realpath` as sufficient sanitizers. These functions normalize or resolve a path but do not verify that it remains inside an allowed base directory.
- Impact: User-controlled traversal payloads can be considered safe after path resolution alone, causing false negatives.
- Priority: P1
- Fix immediately: Yes

#### 65. Python path traversal checks the wrong argument for `send_from_directory`

- Position: `aegis-ai-core/src/analysis/rules/path_traversal/ast_rule.py:29-38`, `aegis-ai-core/src/analysis/rules/path_traversal/ast_rule.py:248-250`
- Reason: `send_from_directory` is grouped with single-path direct sinks and `_check_path_args` is always called with `arg_index=0`. In Flask, the attacker-controlled filename is commonly the second argument.
- Impact: `send_from_directory(upload_dir, request.args["file"])` can be missed.
- Priority: P1
- Fix immediately: Yes

#### 66. Java path traversal checks only the first path argument

- Position: `aegis-ai-core/src/analysis/rules/path_traversal/java_ast_rule.py:47-63`, `aegis-ai-core/src/analysis/rules/path_traversal/java_ast_rule.py:111-143`
- Reason: The method and constructor checks always inspect only `args[0]`. Several Java APIs have additional path arguments, including `new File(parent, child)`, `Files.copy(source, target)`, and `Files.move(source, target)`.
- Impact: User-controlled destination or child paths in multi-argument file APIs can be missed.
- Priority: P1
- Fix immediately: Yes

#### 67. Go path traversal treats path cleanup as a complete sanitizer

- Position: `aegis-ai-core/src/analysis/rules/path_traversal/go_ast_rule.py:64-74`, `aegis-ai-core/src/analysis/rules/path_traversal/go_ast_rule.py:140-143`, `aegis-ai-core/src/analysis/rules/path_traversal/go_ast_rule.py:241-252`
- Reason: `_is_sanitized_call` skips arguments wrapped in `filepath.Clean`, `filepath.Abs`, `filepath.Rel`, `path.Clean`, or `path.Base` without checking whether the resulting path is constrained to an allowed directory.
- Impact: `os.Open(filepath.Clean(userPath))` or `os.Open(filepath.Abs(userPath))` can be treated as safe even if the resolved path escapes the intended root.
- Priority: P1
- Fix immediately: Yes

#### 68. PHP path traversal ignores second path arguments for copy and rename

- Position: `aegis-ai-core/src/analysis/rules/path_traversal/php_ast_rule.py:22-31`, `aegis-ai-core/src/analysis/rules/path_traversal/php_ast_rule.py:95-129`
- Reason: The PHP file-operation check stops after the first argument for every function. This is not sufficient for APIs such as `copy($source, $destination)` and `rename($old, $new)`.
- Impact: User-controlled destination paths can be missed, allowing file overwrite or move operations outside the intended directory to go unreported.
- Priority: P1
- Fix immediately: Yes

### Batch 11 Findings

#### 69. Python SQL rule treats any query variable plus params as safe

- Position: `aegis-ai-core/src/analysis/rules/sql_injection/ast_rule.py:89-118`, `aegis-ai-core/src/analysis/rules/sql_injection/ast_rule.py:293-301`
- Reason: `_is_parameterized` returns true for any `execute(sql_var, params)` call where the first argument is a `Name` or `Attribute`, without resolving whether `sql_var` was built from unsafe concatenation or formatting.
- Impact: `sql = "SELECT ... " + request.args["id"]; cursor.execute(sql, params)` can be skipped before `_check_sql_arg` sees the tainted SQL variable.
- Priority: P1
- Fix immediately: Yes

#### 70. Go SQL rule treats concatenated queries with placeholders as safe

- Position: `aegis-ai-core/src/analysis/rules/sql_injection/go_ast_rule.py:128-137`, `aegis-ai-core/src/analysis/rules/sql_injection/go_ast_rule.py:343-348`
- Reason: `_is_parameterized_query` checks only whether the argument text contains `$1` or `?`, and it runs before the binary-expression SQL concatenation check.
- Impact: A query like `db.Query("SELECT ... WHERE id=$1 " + userSort, id)` can be treated as parameterized even though part of the SQL text is attacker-controlled.
- Priority: P1
- Fix immediately: Yes

#### 71. Java SQL user-input detection misses aliased request objects

- Position: `aegis-ai-core/src/analysis/rules/sql_injection/java_ast_rule.py:374-411`
- Reason: `_subtree_has_user_input` special-cases `method_invocation` nodes and only treats receivers named exactly `request` or `req` as request input. It then returns before generic user-input detection runs.
- Impact: SQL built from `httpRequest.getParameter("id")`, `servletRequest.getParameter(...)`, or similar aliases can be missed.
- Priority: P2
- Fix immediately: Yes

#### 72. PHP SQL rule skips dynamic `prepare` calls entirely

- Position: `aegis-ai-core/src/analysis/rules/sql_injection/php_ast_rule.py:66-77`, `aegis-ai-core/src/analysis/rules/sql_injection/php_ast_rule.py:164-179`
- Reason: `visit` returns immediately for every member call whose method is `prepare`, assuming it is parameterized. It does not inspect whether the SQL passed to `prepare` is itself built from user input.
- Impact: `$pdo->prepare("SELECT * FROM " . $_GET["table"])` can be missed even though prepared statements do not protect dynamic table/column/query fragments.
- Priority: P1
- Fix immediately: Yes

#### 73. Python XSS rule does not actually check `HttpResponse(...)` constructors

- Position: `aegis-ai-core/src/analysis/rules/xss/ast_rule.py:29-33`, `aegis-ai-core/src/analysis/rules/xss/ast_rule.py:202-213`, `aegis-ai-core/src/analysis/rules/xss/ast_rule.py:229-239`
- Reason: `HttpResponse`, `JsonResponse`, `StreamingHttpResponse`, and `FileResponse` are only listed as receiver names for method calls, not as direct callable sinks. The direct sink set only contains `render_template_string` and `mark_safe`.
- Impact: Django patterns such as `return HttpResponse(request.GET["name"])` can be missed despite the rule comments claiming response constructors are covered.
- Priority: P1
- Fix immediately: Yes

#### 74. Python XSS sanitizer detection trusts unrelated `escape` and `quote` methods

- Position: `aegis-ai-core/src/analysis/rules/xss/ast_rule.py:64-73`, `aegis-ai-core/src/analysis/rules/xss/ast_rule.py:100-119`
- Reason: `_is_sanitized_node` treats any attribute named `escape`, `quote`, `htmlspecialchars`, or `bleach_clean` as an HTML sanitizer regardless of module or context. `quote` is URL encoding, not general HTML escaping.
- Impact: User-controlled output wrapped by unrelated helpers such as `obj.escape(user)` or `urllib.parse.quote(user)` can be skipped as safe for HTML output.
- Priority: P1
- Fix immediately: Yes

#### 75. Java XSS sanitizer detection trusts substring matches

- Position: `aegis-ai-core/src/analysis/rules/xss/java_ast_rule.py:37-48`, `aegis-ai-core/src/analysis/rules/xss/java_ast_rule.py:93-97`
- Reason: The rule skips an argument if its text contains any sanitizer token, including generic names such as `encode` and `sanitize`, without validating the called class or method.
- Impact: `customEncode(userInput)` or `someService.sanitize(userInput)` can suppress XSS findings even if those methods do not perform HTML-context escaping.
- Priority: P1
- Fix immediately: Yes

#### 76. Go XSS reports `<script>` formatting without checking user input

- Position: `aegis-ai-core/src/analysis/rules/xss/go_ast_rule.py:275-293`
- Reason: `_is_html_sprintf_with_user_input` returns true for any `fmt.Sprintf` format string containing `<script` before checking whether any formatting argument derives from user input.
- Impact: Static script templates with non-user arguments can be reported as XSS, adding false positives to Go scans.
- Priority: P2
- Fix immediately: Yes

### Batch 12 Findings

#### 77. Python hardcoded credential rule misses short real passwords

- Position: `aegis-ai-core/src/analysis/rules/hardcoded_credentials/ast_rule.py:149-157`, `aegis-ai-core/src/analysis/rules/hardcoded_credentials/ast_rule.py:230-235`
- Reason: `_is_real_secret` rejects every value shorter than `_MIN_REAL_SECRET_LEN` before reporting, even when the variable name is clearly a credential name.
- Impact: Real hardcoded weak credentials such as `password = "admin123"` or `api_key = "dev-key-1"` can be treated as non-secrets and missed.
- Priority: P2
- Fix immediately: Yes

#### 78. JavaScript hardcoded credential rule only evaluates the last declarator

- Position: `aegis-ai-core/src/analysis/rules/hardcoded_credentials/javascript_ast_rule.py:110-130`
- Reason: `_check_variable_declaration` loops through all `variable_declarator` children but stores `var_name` and `value_node` in one pair and performs the check only after the loop.
- Impact: In declarations such as `const password = "real-secret", displayName = "x";`, the earlier credential declarator can be overwritten by the later non-credential declarator and missed.
- Priority: P1
- Fix immediately: Yes

#### 79. JavaScript hardcoded credential rule treats short lowercase secrets as placeholders

- Position: `aegis-ai-core/src/analysis/rules/hardcoded_credentials/javascript_ast_rule.py:306-348`
- Reason: `_is_placeholder` returns true for any pure lowercase value shorter than eight characters.
- Impact: Real weak credentials such as `password = "admin"` or `secret = "prod"` are skipped as if they were harmless examples.
- Priority: P2
- Fix immediately: Yes

#### 80. Java hardcoded credential rule misses class fields

- Position: `aegis-ai-core/src/analysis/rules/hardcoded_credentials/java_ast_rule.py:40-56`
- Reason: `visit` checks only `local_variable_declaration` and `assignment_expression`; it does not inspect Java `field_declaration` nodes.
- Impact: Common patterns like `private static final String API_KEY = "..."` or class-level `password` constants can be missed.
- Priority: P1
- Fix immediately: Yes

#### 81. Java hardcoded credential member assignment reads the qualifier instead of the field

- Position: `aegis-ai-core/src/analysis/rules/hardcoded_credentials/java_ast_rule.py:98-128`
- Reason: For `field_access`, the rule extracts only children of type `identifier`. In Java tree-sitter field access, the credential field is commonly represented as a field node, while the identifier is the qualifier such as `config`.
- Impact: Assignments like `config.password = "secret"` can be checked against `config` instead of `password` and therefore missed.
- Priority: P1
- Fix immediately: Yes

#### 82. Python NoSQL rule does not recurse into dict query values

- Position: `aegis-ai-core/src/analysis/rules/nosql_injection/python_ast_rule.py:69-82`, `aegis-ai-core/src/analysis/rules/nosql_injection/python_ast_rule.py:173-203`
- Reason: The visitor passes the whole query argument into `_is_user_input_node`, but that helper only recognizes top-level `Attribute`, `Subscript`, and `Call` nodes. It does not recursively inspect `ast.Dict` or list contents.
- Impact: Direct queries such as `collection.find({"$where": request.args["q"]})` or `find_one({"name": request.json["name"]})` can be missed unless separate taint tracking already marked a variable.
- Priority: P1
- Fix immediately: Yes

#### 83. Java NoSQL rule is line-bound and hard-codes `request.getParameter`

- Position: `aegis-ai-core/src/analysis/rules/nosql_injection/java_ast_rule.py:25-31`, `aegis-ai-core/src/analysis/rules/nosql_injection/java_ast_rule.py:56-60`
- Reason: The rule scans one stripped source line at a time and only matches `request.getParameter(...)` text.
- Impact: Multi-line Mongo queries and aliases such as `httpRequest.getParameter(...)` are missed even though they are common in Java handlers.
- Priority: P2
- Fix immediately: Yes

#### 84. Go NoSQL regex can match across unrelated code

- Position: `aegis-ai-core/src/analysis/rules/nosql_injection/go_ast_rule.py:26-33`, `aegis-ai-core/src/analysis/rules/nosql_injection/go_ast_rule.py:58-63`
- Reason: `_GO_NOSQL_RE` uses `[\s\S]*?` between the NoSQL method call and the request input call, with no statement, block, or argument boundary.
- Impact: A safe `Find(...)` call can be paired with a later `r.FormValue(...)` in unrelated code and reported as NoSQL injection.
- Priority: P2
- Fix immediately: Yes

### Batch 13 Findings

#### 85. Python RCE rule misses imported aliases and from-import sinks

- Position: `aegis-ai-core/src/analysis/rules/rce/ast_rule.py:251-268`
- Reason: The visitor only recognizes direct `os.method(...)` and `subprocess.method(...)` attribute calls, plus bare `eval`/`exec`/`compile`. It does not resolve `import subprocess as sp`, `from subprocess import run`, or `from os import system`.
- Impact: Common command execution calls such as `sp.run(user_cmd)`, `run(user_cmd)`, or `system(user_cmd)` can bypass the Python RCE rule.
- Priority: P1
- Fix immediately: Yes

#### 86. Go RCE rule reports safe fixed-command arguments as command injection

- Position: `aegis-ai-core/src/analysis/rules/rce/go_ast_rule.py:88-98`
- Reason: After handling shell `-c`, the rule reports if any `exec.Command` argument contains user input, even when the command is fixed and Go passes the user value as an argv element without a shell.
- Impact: Safe patterns such as `exec.Command("grep", userPattern, fixedFile)` can be reported as command injection, reducing signal quality.
- Priority: P2
- Fix immediately: Yes

#### 87. Java RCE rule does not verify the receiver class

- Position: `aegis-ai-core/src/analysis/rules/rce/java_ast_rule.py:34-35`, `aegis-ai-core/src/analysis/rules/rce/java_ast_rule.py:66-80`
- Reason: `_RCE_RECEIVERS` is declared but not used in `_check_method_invocation`. Any method named `exec`, `start`, `eval`, or `loadLibrary` with user input is treated as RCE regardless of receiver type.
- Impact: Application methods such as `job.start(request.getParameter("id"))` or `rules.eval(input)` can be false positives even when they do not execute OS commands or scripts.
- Priority: P2
- Fix immediately: Yes

#### 88. PHP RCE treats all `preg_replace` calls as code execution

- Position: `aegis-ai-core/src/analysis/rules/rce/php_ast_rule.py:22-35`, `aegis-ai-core/src/analysis/rules/rce/php_ast_rule.py:59-72`
- Reason: `preg_replace` is included in `DANGEROUS_FUNCS` without checking for the deprecated `/e` modifier or PHP version behavior.
- Impact: Normal regex replacement with user-controlled subject or replacement text can be reported as RCE even though modern `preg_replace` does not execute code.
- Priority: P2
- Fix immediately: Yes

#### 89. PHP XSS rule treats `strip_tags` as sufficient output escaping

- Position: `aegis-ai-core/src/analysis/rules/xss/php_ast_rule.py:22`, `aegis-ai-core/src/analysis/rules/xss/php_ast_rule.py:68-72`, `aegis-ai-core/src/analysis/rules/xss/php_ast_rule.py:109-114`
- Reason: `strip_tags` is included in the sanitizer set and causes echo/print checks to return. It is not equivalent to context-aware HTML escaping and can leave dangerous output contexts unprotected.
- Impact: User-controlled output wrapped in `strip_tags` can be skipped as safe, causing XSS false negatives.
- Priority: P1
- Fix immediately: Yes

#### 90. PHP NoSQL rule checks only the first argument

- Position: `aegis-ai-core/src/analysis/rules/nosql_injection/php_ast_rule.py:65-82`
- Reason: The rule breaks after inspecting the first argument for every MongoDB method.
- Impact: Update-style calls can miss user-controlled update documents or options in later arguments, for example `$collection->updateOne(["_id" => $id], ['$set' => $_POST])`.
- Priority: P1
- Fix immediately: Yes

#### 91. Deprecated PHP path traversal rule skips `realpath`/`pathinfo` as full sanitizers

- Position: `aegis-ai-core/src/analysis/rules/php/php_taint_rules.py:572-591`
- Reason: The compatibility PHP TaintGraph path traversal rule treats `basename`, `realpath`, `dirname`, and `pathinfo` as a complete extra filter and skips the finding entirely.
- Impact: If the deprecated compatibility rule is used directly, path normalization or metadata extraction can hide paths that still escape the allowed directory. The default PHP path uses AST rules, so this is lower priority than active default-rule issues.
- Priority: P3
- Fix immediately: No

### Batch 14 Findings

#### 92. Legacy local scanner skips broad `help` paths

- Position: `aegis-ai-core/src/analysis/security_rules.py:1103-1106`
- Reason: `scan_code_locally` returns no findings for any PHP/HTML file whose full path contains `help`, not just documentation pages.
- Impact: Real application files such as `helpdesk.php` or files under a `helpers` directory can be treated as clean without running the legacy local rules.
- Priority: P2
- Fix immediately: Yes

#### 93. Dependency tracker misses Python relative imports

- Position: `aegis-ai-core/src/analysis/dependency_tracker.py:52-56`, `aegis-ai-core/src/analysis/dependency_tracker.py:130-140`
- Reason: Python imports are resolved from `project_root` using the raw module string. Relative imports such as `from .utils import sanitize` or `from ..models import User` are not resolved relative to the importing file/package.
- Impact: LSP export-change invalidation can miss files that import the changed module through normal package-relative imports, leaving stale cached diagnostics.
- Priority: P2
- Fix immediately: Yes

#### 94. Dependency export hash ignores APIs after the first 200 lines

- Position: `aegis-ai-core/src/analysis/dependency_tracker.py:61-89`
- Reason: `update_export_hash` only hashes signature-like lines from `code.splitlines()[:200]`.
- Impact: A public function, class, or export declared later in a file can change without invalidating dependent files, so importers can keep stale scan results.
- Priority: P2
- Fix immediately: Yes

#### 95. Function-level incremental analysis is not wired into the scan path

- Position: `aegis-ai-core/src/analysis/incremental_analyzer.py:109-161`, `aegis-ai-core/src/analysis/incremental_analyzer.py:217-244`
- Reason: `get_changed_functions` and `merge_partial_findings` implement partial-function reuse, but repository-wide usage only uses the cache for fully unchanged files and otherwise runs a full scan; `merge_partial_findings` has no caller.
- Impact: The function-level incremental feature described by the module is effectively dead code, so changed-function scans do not get the expected performance benefit and the code path is untested.
- Priority: P3
- Fix immediately: No

#### 96. Cross-file analyzer parses TypeScript with the JavaScript parser

- Position: `aegis-ai-core/src/analysis/taint/cross_file_analyzer.py:128-154`
- Reason: Only a JavaScript parser is initialized, and `scan_project` sends both `.js` and `.ts` files through `_analyze_js_file`.
- Impact: TypeScript import/export syntax involving types, interfaces, enums, decorators, or TS-only annotations can be malformed or missed in the cross-file dependency graph.
- Priority: P2
- Fix immediately: Yes

#### 97. Cross-file analyzer cannot resolve package-local Python imports

- Position: `aegis-ai-core/src/analysis/taint/cross_file_analyzer.py:306-329`, `aegis-ai-core/src/analysis/taint/cross_file_analyzer.py:350-371`
- Reason: `from . import module` records the module path as `"."`, then `_resolve_relative_path` resolves only that path and does not combine it with the imported name or try package `__init__.py` for the directory.
- Impact: Common Python package imports are absent from the dependency graph, weakening cross-file analysis and any dependent invalidation or reporting.
- Priority: P2
- Fix immediately: Yes

#### 98. Inline suppression markers are matched inside string literals

- Position: `aegis-ai-core/src/scanner/false_positive_manager.py:263-293`
- Reason: `InlineSuppressor` applies the `aegis-ignore` regex directly to raw source lines without parsing comments or excluding string literals.
- Impact: A string literal containing `# aegis-ignore` or `// aegis-ignore` can suppress a finding on that line even though no suppression comment was written.
- Priority: P2
- Fix immediately: Yes

#### 99. Smart remediation drops object prefixes from user-input expressions

- Position: `aegis-ai-core/src/scanner/smart_remediation.py:63-85`, `aegis-ai-core/src/scanner/smart_remediation.py:185-197`
- Reason: `_extract_variable_candidates` captures only property names such as `id` from `req.query.id`, then `_apply_replacements` inserts those bare names into suggested code.
- Impact: LSP hover/code-action examples can contain undefined or wrong variables, and applying an example fix can produce broken code.
- Priority: P2
- Fix immediately: Yes

#### 100. JavaScript DSL SQL rule reports any variable query

- Position: `aegis-ai-core/src/analysis/rules/dsl/javascript.sql-injection-concat.yaml:7-8`
- Reason: The second pattern is `$DB.query($SQL)` with no taint, concatenation, or metavariable constraint.
- Impact: Safe constant query variables or prebuilt parameterized SQL variables can be reported as SQL injection by the DSL layer.
- Priority: P2
- Fix immediately: Yes

#### 101. Python DSL SQL format rule only matches exact `SELECT` literals

- Position: `aegis-ai-core/src/analysis/rules/dsl/python.sql-injection-format.yaml:7-8`
- Reason: The patterns require `"SELECT"` or `f"SELECT {...}"` exactly, rather than SQL strings containing a real query body.
- Impact: Common unsafe forms such as `cursor.execute("SELECT * FROM users WHERE id=%s" % user_id)` can be missed by the DSL rule.
- Priority: P2
- Fix immediately: Yes

#### 102. JavaScript DSL response-send rule treats any non-literal expression as XSS

- Position: `aegis-ai-core/src/analysis/rules/dsl/javascript.xss-response-send.yaml:7-14`
- Reason: The rule only excludes expressions that start with a quote and does not require user-controlled input or HTML context.
- Impact: Safe expressions such as internal template variables, objects, or framework-rendered content passed to `res.send`/`res.write` can become broad false positives.
- Priority: P2
- Fix immediately: Yes

### Batch 15 Findings

#### 103. Guard CFG never models the normal post-guard block

- Position: `aegis-ai-core/src/analysis/cfg/dominator_tree.py:456-509`
- Reason: The docstring says each guard is modeled as `guard_block -> [exit_branch, normal_branch]`, but the builder only adds `guard_block -> EXIT_ID` and then finally connects the last guard to exit. For a common single guard clause there is no non-exit normal successor for `get_guard_protected_range` to return.
- Impact: Guard-clause validation support is ineffective for the common case and can fail to reduce false positives for code safely executed after early-return checks.
- Priority: P2
- Fix immediately: Yes

#### 104. Worker daemon auto-port is not machine-readable

- Position: `aegis-ai-core/src/worker_daemon.py:64-74`
- Reason: The module comment says `--port 0` prints the selected port to stdout for the parent process, but the implementation only logs it through the logger, which writes to stderr by default.
- Impact: A caller that starts the daemon with an automatic port cannot reliably discover where to connect, making the daemon integration brittle or unusable.
- Priority: P2
- Fix immediately: Yes

#### 105. Worker daemon returns clean results for supported non-JS/Python languages

- Position: `aegis-ai-core/src/worker_daemon.py:32-41`
- Reason: `run_scan` only dispatches to `analyze_python` and `analyze_javascript`; every other language returns `[]`.
- Impact: If the daemon path is used for PHP, Java, or Go files, the scanner will report no findings even though the main scanner has analyzers for those languages.
- Priority: P2
- Fix immediately: Yes

#### 106. Baseline entry paths are not constrained to the workspace

- Position: `aegis-vscode/src/baselineTreeProvider.ts:139-160`
- Reason: The tree item constructs `targetPath` from `workspaceRoot` plus `entry.file_path.split("/")` without normalizing and verifying that the result remains under `workspaceRoot`.
- Impact: A malformed or malicious `.aegis-baseline.json` entry containing `..` segments can make the extension open a file outside the workspace.
- Priority: P2
- Fix immediately: Yes

#### 107. Removing Aegis comments can delete adjacent user comments

- Position: `aegis-vscode/src/commentCommands.ts:26-43`
- Reason: Once an Aegis marker is found, the removal range extends through every following comment line until a non-comment line, with no explicit end marker.
- Impact: If a user comment immediately follows an inserted Aegis remediation block, the remove command can delete the user's comment as well.
- Priority: P2
- Fix immediately: Yes

#### 108. Corrupt baseline files are hidden as empty state in the VS Code view

- Position: `aegis-vscode/src/baselineTreeProvider.ts:56-80`
- Reason: `readBaselineEntries` catches all parse/read failures and returns an empty list without surfacing an error.
- Impact: Users see no suppressed findings and no warning when `.aegis-baseline.json` is corrupt or temporarily unreadable, making baseline state hard to trust.
- Priority: P3
- Fix immediately: No

### Batch 16 Findings

#### 109. Benchmark dispatch parses TypeScript cases as JavaScript

- Position: `aegis-ai-core/src/scanner/benchmark.py:150-152`
- Reason: `_analyze_case` groups `typescript` and `ts` with JavaScript but calls `analyze_javascript(case.code, "benchmark.js")` without passing `language="typescript"` or a `.ts` filename.
- Impact: Any TypeScript benchmark case would be evaluated with JavaScript parsing behavior, so TS-only syntax could be counted as a scanner failure or success for the wrong reason.
- Priority: P2
- Fix immediately: Yes

#### 110. Benchmark true-positive cases reward findings without user-controlled sources

- Position: `aegis-ai-core/src/scanner/benchmark_cases.py:85-105`
- Reason: Several TP cases use generic variables such as `userId` or `cmd` without modeling a request/input source, while still expecting injection/RCE findings.
- Impact: The benchmark can reward broad sink-only rules and make precision look better for detectors that report dangerous APIs even when no attacker-controlled flow is shown.
- Priority: P2
- Fix immediately: Yes

#### 111. Built-in benchmark barely covers supported non-JS languages

- Position: `aegis-ai-core/src/scanner/benchmark_cases.py:26-232`
- Reason: The built-in benchmark covers mostly JavaScript plus two Python cases, but it has no PHP, Java, or Go TP/TN coverage even though the scanner exposes analyzers for those languages.
- Impact: The generated Recall/Precision/FPR report can be presented as project-wide quality while leaving major supported languages unmeasured.
- Priority: P3
- Fix immediately: No

#### 112. CFG package omits the guard CFG builder from its public exports

- Position: `aegis-ai-core/src/analysis/cfg/__init__.py:17-24`
- Reason: `build_cfg_from_ast_if_statements` is part of the CFG module's guard-clause functionality but is not imported or included in `__all__`; consumers must know to import it from the private module file.
- Impact: The public `analysis.cfg` package surface is inconsistent with its documented guard-clause use case and makes reuse/tests of that helper less discoverable.
- Priority: P3
- Fix immediately: No

## Phase 3 Security Review Findings

### Batch 17 Findings

#### 113. 本地 `.env` 文件包含真实 API Key

- Position: `aegis-ai-core/.env:3,10`
- Reason: 本地 `.env` 中 `DEEPSEEK_API_KEY` 和 `NVD_API_KEY` 都是非占位符长度的真实值。`git ls-files` 显示该文件未被版本控制，`.gitignore` 和 `.dockerignore` 也已排除它，但密钥材料仍然放在仓库工作区内。
- Impact: 这些值容易通过截图、压缩包、手工复制、调试输出或后续新增打包脚本泄露；如果该工作区曾被共享或展示，应按密钥泄露处理。
- Priority: P1
- Fix immediately: Yes

#### 114. Docker 镜像默认以 root 身份运行扫描器

- Position: `Dockerfile:1-26`, `docker-compose.yml:5-11`
- Reason: Dockerfile 没有创建非 root 用户或设置 `USER`，compose 服务也没有设置 `user`、`read_only`、`cap_drop` 或 `security_opt`。虽然目标目录以 `:ro` 挂载，但扫描进程本身仍在容器内以 root 运行。
- Impact: 如果解析器、依赖或扫描逻辑在处理不可信代码时被利用，攻击面会扩大到容器 root 权限，增加写入容器文件系统、篡改运行环境或利用挂载/能力配置错误的风险。
- Priority: P2
- Fix immediately: Yes

#### 115. VS Code 工作区配置可以控制后端启动命令

- Position: `aegis-vscode/package.json:214-232`, `aegis-vscode/src/extension.ts:167-169`, `aegis-vscode/src/extension.ts:593-600`, `aegis-vscode/src/extension.ts:633-641`, `aegis-vscode/src/backendBootstrap.ts:248-264`
- Reason: `aegisAI.pythonPath`、`aegisAI.serverModule`、`aegisAI.serverCwd` 都是普通配置项，扩展激活后直接把这些值传入后端启动流程并执行 `pythonPath -m serverModule`。配置项没有限制 scope，也没有在使用工作区覆盖值前做信任检查或确认。
- Impact: 一个被信任打开的恶意工作区可以通过 `.vscode/settings.json` 指向攻击者控制的 Python 可执行文件、模块或工作目录；用户只要打开受支持语言文件触发扩展激活，就可能运行非预期代码。
- Priority: P1
- Fix immediately: Yes

#### 116. 删除 baseline 后会对未约束路径触发重新扫描

- Position: `aegis-vscode/src/extension.ts:252-255`, `aegis-vscode/src/extension.ts:290-300`
- Reason: 删除 baseline 条目后，扩展用 `path.join(activeRoot, ...node.entry.file_path.split("/"))` 构造 URI 并调用 `aegisAI.scanCurrentFile`，没有 normalize 后验证目标仍在工作区内。
- Impact: 含 `..` 的 baseline 条目不仅可以在树视图中打开工作区外文件，还能在删除条目后触发对工作区外路径的 LSP 扫描请求，扩大本地文件访问和潜在代码外传面。
- Priority: P2
- Fix immediately: Yes

#### 117. 安全 lint 规则被全局忽略

- Position: `aegis-ai-core/pyproject.toml:124-148`
- Reason: Ruff 启用了 Bandit 安全规则集 `S`，但在全局 ignore 中排除了 `S603`、`S607`、`S608`、`S104` 等安全相关规则，没有按文件或代码块限定例外范围。
- Impact: 后续新增的 subprocess 调用、SQL 字符串拼接或绑定全网地址等问题不会被 CI 的 lint 阶段提示，只能依赖人工审查或业务测试发现。
- Priority: P3
- Fix immediately: No
