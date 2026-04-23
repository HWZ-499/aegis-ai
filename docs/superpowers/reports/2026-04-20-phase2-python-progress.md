# Phase 2 Python Progress Report (2026-04-20)

## Scope

- Re-enable Python SQLi TP regression sample.
- Reduce Python false positives in RCE / Path Traversal.
- Validate impact on Flask 2.3.2 and Django 3.2 ground-truth evaluations.

## Rule-Sample Metrics (Python)

- Current synthetic metrics: `tp=10 tn=15 fp=0 fn=0`
- Recall: `100.0%`
- Precision: `100.0%`

Source command:

- `python scripts/benchmark/phase_metrics.py --language python --output reports/phase2_python_metrics_2026-04-20.md`

## Real-Project Before/After

### flask-2.3.2

| Metric | Before | After |
|--------|--------|-------|
| TP | 0 | 0 |
| FP | 15 | 10 |
| FN | 1 | 1 |
| TN | 0 | 1 |
| Recall | 0.0% | 0.0% |
| Precision | 0.0% | 0.0% |

### django-3.2

| Metric | Before | After |
|--------|--------|-------|
| TP | 0 | 0 |
| FP | 146 | 129 |
| FN | 1 | 1 |
| TN | 9 | 9 |
| Recall | 0.0% | 0.0% |
| Precision | 0.0% | 0.0% |

## Category Delta Highlights

- Flask:
  - `PATH_TRAVERSAL` FP: `4 -> 0`
  - `RCE_COMMAND_EXEC` FP: `3 -> 2`
- Django:
  - `PATH_TRAVERSAL` FP: `14 -> 0`
  - `RCE_COMMAND_EXEC` FP: `23 -> 20`

## Implemented Changes

- Path Traversal rule:
  - Restrict `join` sink matching to `os.path.join(...)` only (avoid `str.join(...)` noise).
  - Treat env-derived taint sources as non-remote input in path checks.
- RCE rule:
  - Distinguish env-derived taint from HTTP user input.
  - Avoid `compile(...)`-only heuristic reporting when no user-input taint is confirmed.
  - Skip `eval/exec(compile(...))` local-loader pattern when compile input is not user-controlled.
- Test suite:
  - Re-enabled `tp_python_cursor_execute_format.py` in `tests/rules/test_all_rules.py`.
  - Added new Python FP fixtures for path/rce regression coverage.

## Validation Gates

- `python -m pytest tests/rules/test_all_rules.py -k "python and (SQL_INJECTION or RCE_COMMAND_EXEC or PATH_TRAVERSAL or OPEN_REDIRECT or SSRF or NOSQL_INJECTION)" -q` ✅
- `python -m ruff check src tests` ✅
- `python -m mypy src --hide-error-context --no-color-output` ✅
- `python -m pytest` ✅ (`456 passed, 47 deselected, 1 xfailed`)
