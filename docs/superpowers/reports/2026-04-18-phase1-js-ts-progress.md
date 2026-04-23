# Phase 1 JS/TS Progress Report (2026-04-18)

## Scope

- Metrics harness for per-language rule samples
- JS SSRF precision improvements (supertest false-positive suppression)
- Real-project evaluation reproducibility fix (disable cache in benchmark evaluation path)

## Synthetic Metrics (JS)

| Metric | Before | After |
|--------|--------|-------|
| TP | 9 | 10 |
| TN | 8 | 10 |
| FP | 0 | 0 |
| FN | 0 | 0 |
| Recall | 100.0% | 100.0% |
| Precision | 100.0% | 100.0% |

## Acceptance Benchmark

| Metric | Result |
|--------|--------|
| TP | 16 |
| TN | 12 |
| FP | 0 |
| FN | 0 |
| Recall | 100.0% |
| Precision | 100.0% |
| F1 | 100.0% |

## Real-Project Evaluation

| Target | TP Before | FP Before | FN Before | TP After | FP After | FN After |
|--------|----------:|----------:|----------:|---------:|---------:|---------:|
| express-4.18.1 | 0 | 276 | 2 | 0 | 106 | 2 |
| body-parser-1.20.0 | 0 | 215 | 2 | 0 | 0 | 2 |

## Key Outcomes

- `express-4.18.1` false positives reduced by **170** in this phase (`276 -> 106`).
- `body-parser-1.20.0` false positives reduced by **215** (`215 -> 0`).
- Remaining recall bottleneck is dominated by categories currently out of JS Phase 1 scope:
  - `PROTOTYPE_POLLUTION`
  - `DOS_RISK`
  - `UNVALIDATED_INPUT`

## Validation Gates

- `python -m pytest tests/test_acceptance_benchmark.py -m acceptance -q -s` ✅
- `python -m ruff check src tests` ✅
- `python -m mypy src --hide-error-context --no-color-output` ✅
- `python -m pytest` ✅ (`450 passed, 47 deselected, 1 xfailed`)
