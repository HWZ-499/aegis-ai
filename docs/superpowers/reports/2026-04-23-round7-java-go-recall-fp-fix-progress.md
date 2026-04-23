# Round 7 Progress Report (2026-04-23)

## Scope

- Fix Java deserialization recall gap found in the `java-deserialization-demo` pilot benchmark.
- Fix Go SQL injection false positive found in the `go-insecure-web-app` pilot benchmark.

## Root Cause

### Java deserialization false negative

- The Java method-name extractor in this rule path used the first identifier in `method_invocation` (receiver) instead of the invoked method identifier.
- `try-with-resources` declarations were not tracked into local assignment mapping, so `ObjectInputStream` receiver context could not be resolved reliably.
- The unconditional sink branch needed stronger receiver/source resolution to detect risky `readObject()` usage while avoiding broad overmatching.

### Go SQL injection false positive

- The taint fallback reporting branch could report sinks even when the SQL call used safe placeholder parameterization (`?` / `$n` + bound arguments).
- There was no explicit short-circuit for parameterized `Query/QueryRow/Exec` call patterns.

## Implemented Changes

### New regression fixtures

- `tests/rules/deserialization/true_positive/tp_java_read_object_socket_input.java`
- `tests/rules/sql_injection/false_positive/fp_go_queryrow_placeholder_user_input.go`
- `tests/rules/sql_injection/false_positive/fp_go_fiber_queryrow_placeholder_user_input.go`

### Java rule updates

Updated `src/analysis/rules/deserialization/java_ast_rule.py`:

- Added local assignment tracking for:
  - `local_variable_declaration`
  - `resource` (try-with-resources)
  - `assignment_expression`
- Fixed method-name extraction to use the invoked method identifier (last identifier in invocation).
- Added receiver extraction for `method_invocation`.
- Added receiver/source resolution helpers:
  - `_is_dangerous_receiver`
  - `_receiver_has_sanitizer`
  - `_receiver_from_untrusted_source`
  - `_file_has_java_user_input`
  - `_resolve_var_expr`
- Tightened unconditional sink reporting for `readObject`/related methods:
  - report only when receiver is dangerous,
  - no recognized sanitizer present,
  - receiver context resolves to untrusted input.

### Go rule updates

Updated `src/analysis/rules/sql_injection/go_ast_rule.py`:

- Added `_GO_PARAMETERIZED_CALL_RE` for placeholder-based SQL calls with bound parameters.
- Added `_is_safe_parameterized_sink` and `_looks_like_parameterized_query_call`.
- In taint fallback reporting (`after_file`), short-circuit findings when sink is detected as safe parameterized query call.

## Validation

### Targeted rule checks

- `python -m pytest tests/rules/test_all_rules.py -k "DESERIALIZATION and tp_java_read_object_socket_input" -q` -> passed
- `python -m pytest tests/rules/test_all_rules.py -k "DESERIALIZATION and java" -q` -> passed
- `python -m pytest tests/rules/test_all_rules.py -k "SQL_INJECTION and go" -q` -> passed
- `python -m pytest tests/rules/test_all_rules.py -k "java or go" -q` -> passed (`52 passed`)

### Quality gates

- `python -m ruff check src tests` -> passed
- `python -m mypy src --hide-error-context --no-color-output` -> passed
- `python -m pytest -q` -> passed (`472 passed, 47 deselected, 1 xfailed`)

## Outcome

- Java deserialization recall blocker in pilot path is resolved for socket-input `readObject()` scenario.
- Go SQLi parameterized-query false positive is eliminated for both plain handler and Fiber callback patterns.
- Round 7 changes are regression-covered and ready for PR review.
