# Round 8 Progress Report (2026-04-24)

## Scope

- Continue Phase 4 Java/Go hardening with real-project benchmark driven loop.
- Target this round: Go `go-insecure-web-app` recall/precision gaps (Fiber input/output patterns and shell execution chain).

## Baseline (Round 8 Start)

- Java (`java-deserialization-demo`): Recall 100.0%, Precision 100.0%, F1 1.00 (already stable)
- Go (`go-insecure-web-app`): Recall 0.0%, Precision 0.0%, F1 0.00

## Root Cause Summary

1. Go short variable declarations were not registered in taint graph (`short_var_declaration` expected `identifier_list`, real AST is `expression_list`).
2. Go source/sink matching over-relied on broad fallback text and missed Fiber scenarios (`SendString`, `Query` chain behaviors) or produced noisy nested matches.
3. XSS fallback path could duplicate findings (same flow at `fmt.Sprintf` and `SendString`) and allowed cross-function alias pollution for same variable names.
4. Path traversal rule reported `filepath.Join` alone as sink, creating avoidable FP in non-file-operation flows.
5. RCE for `exec.Command("sh", "-c", builder.String())` needed explicit dynamic-shell heuristic for realistic exploit chains.

## Implemented Changes

### Rule logic

- `src/analysis/rules/rce/go_ast_rule.py`
  - Added shell dynamic-exec heuristic for `sh -c` / `bash -c` with non-literal command argument.
  - Added Go web-input regex fallback to improve user-input recognition for Fiber/Gin style calls.

- `src/analysis/rules/xss/go_ast_rule.py`
  - Added `SendString` sink support.
  - Added assignment tracking for Go (`short_var_declaration`/`assignment_statement`/`var_spec`).
  - Added `fmt.Sprintf` HTML construction detection.
  - Added fallback sink guard to suppress non-user-input `SendString` and de-duplicate `Sprintf`->`SendString` same-flow reports.
  - Added line-aware variable assignment resolution for fallback phase to avoid cross-function same-name pollution.

- `src/analysis/rules/path_traversal/go_ast_rule.py`
  - Removed direct reporting on `filepath.Join` alone; keep reporting on actual filesystem access sinks.

### Taint engine / registry

- `src/analysis/taint/taint_analyzer.py`
  - Fixed Go short var declaration parsing: handle `expression_list := expression_list` and pairwise registrations.
  - For Go sink matching, avoid using full `call_text` fallback when `callee_text` exists (prevents nested callback-body sink overmatching).

- `src/analysis/taint/source_sink_registry.py`
  - Added Go web source patterns: `Query`, `Param`, `PostForm`, `PostFormValue`, `DefaultQuery`.
  - Added Go XSS sink pattern: `.SendString(...)`.
  - Added Go path sink pattern: `ioutil.ReadFile` / `os.ReadFile`.
  - Tightened Go SQL sink pattern to database-object receiver names (`db|conn|connection|tx|stmt`).

## New Regression Fixtures (RED -> GREEN)

- XSS TP: `tests/rules/xss/true_positive/tp_go_fiber_sendstring_fmt_query.go`
- XSS FP: `tests/rules/xss/false_positive/fp_go_fiber_sendstring_constant_html_with_input_var.go`
- Path TP: `tests/rules/path_traversal/true_positive/tp_go_ioutil_readfile_join_query.go`
- Path FP: `tests/rules/path_traversal/false_positive/fp_go_filepath_join_user_input_no_fileop.go`
- RCE TP: `tests/rules/rce/true_positive/tp_go_exec_command_shell_builder_query.go`

## Validation

### Targeted tests

- New RED cases all failed first, then passed after fixes:
  - `tp_go_fiber_sendstring_fmt_query`
  - `tp_go_ioutil_readfile_join_query`
  - `tp_go_exec_command_shell_builder_query`
  - `fp_go_fiber_sendstring_constant_html_with_input_var`
  - `fp_go_filepath_join_user_input_no_fileop`

### Regression / quality gates

- `python -m pytest tests/rules/test_all_rules.py -k "go and (XSS_RISK or PATH_TRAVERSAL or RCE_COMMAND_EXEC or SQL_INJECTION)" -q` ✅
- `python -m pytest tests/rules/test_all_rules.py -k "java or go" -q` ✅
- `python -m ruff check src tests` ✅
- `python -m mypy src --hide-error-context --no-color-output` ✅
- `python -m pytest -q` ✅ (`477 passed, 47 deselected, 1 xfailed`)

## Benchmark Outcome (Round 8 End)

- Java (`java-deserialization-demo`): Recall 100.0%, Precision 100.0%, F1 1.00
- Go (`go-insecure-web-app`): Recall 100.0%, Precision 100.0%, F1 1.00

Go improvement in this round:
- Recall: `0.0% -> 100.0%`
- Precision: `0.0% -> 100.0%`
- F1: `0.00 -> 1.00`
