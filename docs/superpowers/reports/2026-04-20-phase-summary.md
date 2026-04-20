# Multi-Phase Scanner Optimization Summary (2026-04-20)

## Consolidated Phase Metrics

| Phase | Stack | FP Before | FP After | FN Before | FN After | F1 Before | F1 After |
|------|-------|-----------|----------|-----------|----------|-----------|----------|
| Phase 1 | JS/TS (express-4.18.1 + body-parser-1.20.0) | 491 | 106 | 4 | 4 | 0.0% | 0.0% |
| Phase 2 | Python (flask-2.3.2 + django-3.2) | 161 | 139 | 2 | 2 | 0.0% | 0.0% |
| Phase 3 | PHP (rule samples) | N/A | 0 | N/A | 0 | N/A | 100.0% |
| Phase 4 | Java/Go (rule samples) | N/A | 0 | 1 | 0 | N/A | N/A |

Notes:

- Phase 1/2 numbers are aggregated from real-project benchmark reports.
- Phase 3 currently has no DVWA project-level before/after baseline (directory missing in local targets), so row uses rule-sample metrics.
- Phase 4 "before" reflects the RED run for the new Go variable-chain SQLi regression case (1 FN in 11 SQLi sample cases).

## Final Validation Snapshot

- `aegis-ai-core`
  - `python -m ruff check src tests` ✅
  - `python -m mypy src --hide-error-context --no-color-output` ✅
  - `python -m pytest` ✅ (`459 passed, 47 deselected, 1 xfailed`)
- `aegis-vscode`
  - `npm run check` ✅
  - `npm test` ✅ (`27 passing`)

## Residual Risks

- Real-project recall for current Python/JS targets remains low where ground-truth categories are outside current phase scopes.
- PHP phase lacks DVWA project-level verification in this workspace (`dvwa/DVWA` target not present).
- Go source detection for SQLi variable chains is now covered for common `r/req/request` request APIs, but framework-specific aliases still need broader source modeling.

## Deferred Candidates

- Add `DataFlowTracker` native Go/Java source patterns to reduce heuristic reliance in AST rules.
- Add project-level Java/Go benchmark targets and ground-truth files to measure recall/precision beyond rule samples.
- Re-run full cross-project benchmark after restoring DVWA and adding Java/Go targets, then update a second summary with comparable project-level F1.
