# Multi-Phase Scanner Optimization Summary (2026-04-23)

## Consolidated Phase Metrics

| Phase | Stack | FP Before | FP After | FN Before | FN After | F1 Before | F1 After |
|------|-------|-----------|----------|-----------|----------|-----------|----------|
| Phase 1 | JS/TS (express-4.18.1 + body-parser-1.20.0) | 491 | 106 | 4 | 4 | 0.0% | 0.0% |
| Phase 2 | Python (flask-2.3.2 + django-3.2) | 161 | 139 | 2 | 2 | 0.0% | 0.0% |
| Phase 3 | PHP (rule samples) | N/A | 0 | N/A | 0 | N/A | 100.0% |
| Phase 4 | Java/Go (targeted regression cases) | 0 | 0 | 3 | 0 | N/A | N/A |

Notes:

- Phase 1/2 numbers are aggregated from real-project benchmark reports and the per-phase progress reports.
- Phase 3 currently has no DVWA project-level before/after baseline in this workspace, so this row uses rule-sample metrics.
- Phase 4 FN reduction aggregates three RED->GREEN regression closures:
  - Go SQLi variable-chain sink propagation (`db.Query(q)`)
  - Java SQLi `String.format(...)` SQL construction flow
  - Java Open Redirect `response.setHeader("Location", userInput)` flow

## Final Validation Snapshot (2026-04-23)

- `aegis-ai-core`
  - `python -m ruff check src tests` ✅
  - `python -m mypy src --hide-error-context --no-color-output` ✅
  - `python -m pytest -q` ✅ (`469 passed, 47 deselected, 1 xfailed`)
- `aegis-vscode`
  - `npm run check` ✅
  - `npm test` ✅ (`27 passing`)

## Residual Risks

- Real-project recall for current JS/Python targets is still constrained where ground-truth includes categories not yet fully covered (for example `PROTOTYPE_POLLUTION`, `DOS_RISK`, `UNVALIDATED_INPUT`).
- PHP phase still lacks DVWA project-level verification in this workspace because `real_world_targets/dvwa` (or `DVWA`) is not present.
- Java/Go quality is currently validated mainly by rule-sample and targeted regression fixtures; project-level benchmark targets and ground-truth are still missing.
- Java/Go method-invocation source modeling is now boundary-aware, but wrapper/helper alias flows across deeper inter-procedural chains can still be under-modeled.

## Deferred Candidates

- Add Java/Go real-world benchmark targets plus ground-truth datasets and include them in periodic benchmark runs.
- Expand inter-procedural taint propagation for Java/Go helper wrappers (controller -> service -> sink chains).
- Add per-category phase metrics output in `phase_metrics.py` to track FP/FN movement by vulnerability type over time.
- Re-run a full cross-project benchmark after DVWA restoration and new Java/Go targets, then publish a comparable project-level F1 delta report.
