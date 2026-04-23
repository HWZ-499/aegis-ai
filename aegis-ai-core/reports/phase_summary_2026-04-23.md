# Multi-Phase Scanner Optimization Summary (2026-04-23)

## Consolidated Phase Metrics

| Phase | Stack | FP Before | FP After | FN Before | FN After | F1 Before | F1 After |
|------|-------|-----------|----------|-----------|----------|-----------|----------|
| Phase 1 | JS/TS (express-4.18.1 + body-parser-1.20.0) | 491 | 106 | 4 | 4 | 0.0% | 0.0% |
| Phase 2 | Python (flask-2.3.2 + django-3.2) | 161 | 139 | 2 | 2 | 0.0% | 0.0% |
| Phase 3 | PHP (DVWA project benchmark restored) | N/A | 52 | N/A | 3 | N/A | 43.3% |
| Phase 4 | Java/Go (targeted regression cases) | 0 | 0 | 3 | 0 | N/A | N/A |
| Phase 4 Pilot | Java/Go project benchmarks (java-deserialization-demo + go-insecure-web-app) | N/A | 2 | N/A | 4 | N/A | 0.0% |

Notes:

- Phase 1/2 numbers are aggregated from real-project benchmark reports and the per-phase progress reports.
- Phase 3 now includes DVWA project-level benchmark restoration (target present again in `real_world_targets`).
- Phase 4 FN reduction aggregates three RED->GREEN regression closures:
  - Go SQLi variable-chain sink propagation (`db.Query(q)`)
  - Java SQLi `String.format(...)` SQL construction flow
  - Java Open Redirect `response.setHeader("Location", userInput)` flow
- Phase 4 pilot benchmarks were added for Java/Go:
  - Java target: `java-webapp-security-lab/java-deserialization-demo` (DESERIALIZATION benchmark set)
  - Go target: `go-insecure-web-app` (XSS/PATH_TRAVERSAL/RCE TP + SQLi safe-flow TN set)

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
- PHP precision on DVWA remains a key improvement area (current FP is still high).
- Java/Go now has project-level pilot benchmarks, but recall remains 0.0% on both pilot targets.
- Java/Go method-invocation source modeling is now boundary-aware, but wrapper/helper alias flows across deeper inter-procedural chains can still be under-modeled.

## Deferred Candidates

- Expand Java/Go pilot ground-truth into broader project-level suites (more categories and sinks per target).
- Expand inter-procedural taint propagation for Java/Go helper wrappers (controller -> service -> sink chains).
- Add per-category phase metrics output in `phase_metrics.py` to track FP/FN movement by vulnerability type over time.
- Re-run a full cross-project benchmark after the next Java/Go rule iteration and publish project-level F1 deltas.
