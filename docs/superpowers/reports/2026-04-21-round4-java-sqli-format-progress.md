# Round 4 Progress Report (2026-04-21)

## Scope

- Improve Java SQLi detection for `String.format(...)`-based SQL construction.
- Keep existing Java SQLi FP controls stable after enabling method-level argument analysis.

## Root Cause

- `JavaSQLInjectionAstRule` did not recognize SQL built via `String.format(...)` and later passed to `executeQuery(...)`.
- `method_invocation` method-name extraction returned the first identifier (receiver) instead of the actual method, so sink dispatch logic was unreliable for member calls.
- After fixing method extraction, taint-based identifier checks could report parameterized `prepareStatement(sql)` too early before checking whether `sql` was a safe placeholder query.

## Implemented Changes

- Added a new TP fixture:
  - `tests/rules/sql_injection/true_positive/tp_java_statement_format_var_chain.java`
- Added a new FP fixture:
  - `tests/rules/sql_injection/false_positive/fp_java_statement_format_request_attribute.java`
- Updated `src/analysis/rules/sql_injection/java_ast_rule.py`:
  - Track Java local assignments (`local_variable_declaration`, `assignment_expression`) for identifier argument backtracking.
  - Fix method-name extraction to use the invoked method identifier (last identifier in `method_invocation`).
  - Add detection for SQL `String.format(...)` with user input arguments.
  - Add Java request-source call boundary checks for method invocations to avoid broad receiver-only tainting inside call trees.
  - Reorder identifier handling so parameterized-query safety checks run before taint-based reporting, preventing `prepareStatement` false positives.

## Validation

- RED:
  - `python -m pytest tests/rules/test_all_rules.py -k "SQL_INJECTION and tp_java_statement_format_var_chain" -q` (failed before fix)
- GREEN + regression:
  - `python -m pytest tests/rules/test_all_rules.py -k "SQL_INJECTION and tp_java_statement_format_var_chain" -q` ✅
  - `python -m pytest tests/rules/test_all_rules.py -k "java and SQL_INJECTION" -q` ✅
  - `python -m pytest tests/rules/test_all_rules.py -k "java or go" -q` ✅
  - `python -m pytest tests/test_phase2_taint.py -q` ✅
- Quality gates:
  - `python -m ruff check src tests` ✅
  - `python -m mypy src --hide-error-context --no-color-output` ✅
  - `python -m pytest -q` ✅ (`467 passed, 47 deselected, 1 xfailed`)
