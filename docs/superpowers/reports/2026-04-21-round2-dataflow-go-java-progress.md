# Round 2 Progress Report (2026-04-21)

## Scope

- Improve `DataFlowTracker` source modeling for Go/Java.
- Remove accidental Java false positives caused by Python-style `request.GET` fallback matching.

## Root Cause

- `DataFlowTracker(language=\"go\" | \"java\")` previously used a JS+Python fallback source-pattern set.
- This caused:
  - Go misses for `r.FormValue(...)` / `req.URL.Query().Get(...)`.
  - Java overmatching where `request.getSetting(...)` could be treated as user input due `request.GET` lowercase overlap.

## Implemented Changes

- Updated `src/analysis/base/dataflow_tracker.py`:
  - Added `USER_INPUT_PATTERNS_GO`.
  - Added `USER_INPUT_PATTERNS_JAVA`.
  - Added language-specific initialization branches for `go` and `java`.
  - Extended generic fallback set to include JS/Python/Java/Go patterns.

- Added regression tests in `tests/test_phase2_taint.py`:
  - `test_go_formvalue_assignment_tainted`
  - `test_go_url_query_assignment_tainted`
  - `test_java_getparameter_assignment_tainted`
  - `test_java_non_input_getter_not_tainted`

## Validation

- RED:
  - `python -m pytest tests/test_phase2_taint.py -k "DataFlowTrackerGoJavaSources" -q` (3 failed before fix)
- GREEN:
  - `python -m pytest tests/test_phase2_taint.py -k "DataFlowTrackerGoJavaSources" -q` ✅
  - `python -m pytest tests/test_phase2_taint.py -q` ✅
  - `python -m pytest tests/rules/test_all_rules.py -k "go or java" -q` ✅
  - `python -m ruff check src tests` ✅
  - `python -m mypy src --hide-error-context --no-color-output` ✅
  - `python -m pytest` ✅ (`463 passed, 47 deselected, 1 xfailed`)
