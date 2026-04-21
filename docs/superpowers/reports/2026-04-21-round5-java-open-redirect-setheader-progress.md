# Round 5 Progress Report (2026-04-21)

## Scope

- Fix Java Open Redirect false negative for `response.setHeader("Location", userInput)` flows.
- Preserve precision by avoiding overmatching on non-user-input request method calls.

## Root Cause

- `JavaOpenRedirectAstRule` used a method-name extractor that returned the first identifier in `method_invocation` (receiver) instead of the invoked method.
- For `response.setHeader(...)`, the extracted value became `response`, so the `setHeader` sink branch was never reached.
- Existing recursive user-input traversal could also overmatch method invocations by treating `request` receiver identifiers as tainted context without validating the called request API.

## Implemented Changes

- Added new TP fixture:
  - `tests/rules/open_redirect/true_positive/tp_java_set_header_location_user_input.java`
- Added new FP fixture:
  - `tests/rules/open_redirect/false_positive/fp_java_set_header_location_request_attribute.java`
- Updated `src/analysis/rules/open_redirect/java_ast_rule.py`:
  - Fixed method-name extraction to use the invoked method identifier (last identifier in `method_invocation`).
  - Added receiver extraction helper for Java method invocation.
  - Added Java request-source method boundary set (`getParameter`, `getHeader`, etc.).
  - Tightened `_subtree_has_user_input` for method invocations:
    - treat only recognized request input calls as user input,
    - recurse into invocation arguments instead of blindly treating receiver identifiers as sources.

## Validation

- RED:
  - `python -m pytest tests/rules/test_all_rules.py -k "OPEN_REDIRECT and tp_java_set_header_location_user_input" -q` (failed before fix)
- GREEN + regression:
  - `python -m pytest tests/rules/test_all_rules.py -k "OPEN_REDIRECT and java" -q` ✅
  - `python -m pytest tests/rules/test_all_rules.py -k "java or go" -q` ✅
  - `python -m pytest tests/test_phase2_taint.py -q` ✅
- Quality gates:
  - `python -m ruff check src tests` ✅
  - `python -m mypy src --hide-error-context --no-color-output` ✅
  - `python -m pytest -q` ✅ (`469 passed, 47 deselected, 1 xfailed`)
