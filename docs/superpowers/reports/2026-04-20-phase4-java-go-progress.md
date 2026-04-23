# Phase 4 Java/Go Progress Report (2026-04-20)

## Scope

- Close a confirmed Go SQLi false negative on variable-chain propagation.
- Keep Java/Go SQLi precision stable while adding regression coverage.

## Root Cause

- `go_ast_rule.py` only handled direct SQL concatenation at sink call sites.
- For `db.Query(q)` where `q` came from `q := "SELECT..." + id`, the rule did not resolve identifier assignments.
- As a result, user input in assignment chains was missed (FN).

## Rule-Sample Metrics (Java/Go)

| Language | TP | TN | FP | FN | Recall | Precision | FPR |
|----------|---:|---:|---:|---:|-------:|----------:|----:|
| java | 9 | 8 | 0 | 0 | 100.0% | 100.0% | 0.0% |
| go | 9 | 8 | 0 | 0 | 100.0% | 100.0% | 0.0% |

Source commands:

- `python scripts/benchmark/phase_metrics.py --language java`
- `python scripts/benchmark/phase_metrics.py --language go`

## Implemented Changes

- Added Go SQLi TP regression sample:
  - `tests/rules/sql_injection/true_positive/tp_go_query_concat_var_chain.go`
- Added Java SQLi TP regression sample:
  - `tests/rules/sql_injection/true_positive/tp_java_statement_concat_var_chain.java`
- Updated Go SQLi AST rule:
  - Track local assignments (`short_var_declaration`, `assignment_statement`, `var_spec`).
  - Resolve identifier sink arguments back to assigned expressions.
  - Reuse SQL + user-input checks on resolved expressions.
  - Add Go input-call pattern matching for request-derived sources in assignment chains.

## Validation Gates

- RED verification:
  - `python -m pytest tests/rules/test_all_rules.py -k "go and SQL_INJECTION" -q` (before fix: 1 failed)
- GREEN and regression:
  - `python -m pytest tests/rules/test_all_rules.py -k "go and SQL_INJECTION" -q` ✅
  - `python -m pytest tests/rules/test_all_rules.py -k "java and SQL_INJECTION" -q` ✅
  - `python -m pytest tests/rules/test_all_rules.py -k "java or go" -q` ✅
  - `python -m pytest tests/rules/test_all_rules.py -q` ✅
- Quality gates:
  - `python -m ruff check src tests` ✅
  - `python -m mypy src --hide-error-context --no-color-output` ✅
  - `python -m pytest` ✅ (`459 passed, 47 deselected, 1 xfailed`)
