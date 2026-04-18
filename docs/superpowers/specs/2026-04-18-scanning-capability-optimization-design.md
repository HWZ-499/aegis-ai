# Scanning Capability Optimization Design

Date: 2026-04-18  
Owner: Aegis Core Team  
Status: Draft approved for planning

## 1. Problem Statement

The scanner already has broad multi-language coverage, but capability gains need to be delivered with a controlled balance between:

- Recall (reduce false negatives)
- Precision (reduce false positives)
- Stability (no regressions in existing behavior)

The user requested full-scope improvement across all major supported stacks and vulnerability categories, executed in this exact order:

1. JavaScript/TypeScript (Node/Express)
2. Python (Flask/Django)
3. PHP
4. Java and Go

## 2. Goals and Non-Goals

### Goals

- Improve detection quality for all core vulnerability categories per stack.
- Use measurable before/after metrics at each phase (TP, TN, FP, FN, Recall, Precision, F1, FPR).
- Keep full test suite green after each phase.
- Ship each phase as isolated, reviewable commits.

### Non-Goals

- New language onboarding.
- UI/extension feature expansion unrelated to detection quality.
- Large architecture rewrites unrelated to current detection bottlenecks.

## 3. Success Criteria

Each phase is complete only when all criteria pass:

1. Full quality gates pass:
   - `python -m ruff check src tests`
   - `python -m mypy src --hide-error-context --no-color-output`
   - `python -m pytest`
2. Phase target stack shows measurable quality gain:
   - At least one of FP or FN decreases materially.
   - The other metric does not regress.
   - F1 does not decrease.
3. A phase report is generated with explicit before/after values.

## 4. Metrics and Evaluation Sources

Three complementary evaluation layers are used in every phase:

1. Synthetic rule samples (`tests/rules/*/(true_positive|false_positive)`)
2. Acceptance benchmark (`tests/test_acceptance_benchmark.py`, acceptance marker)
3. Real-project ground truth comparison (`scripts/benchmark/evaluate_project.py`)

Ground-truth assets already available:

- `scripts/data/ground_truth_express_4.18.1.json`
- `scripts/data/ground_truth_body_parser_1.20.0.json`
- `scripts/data/ground_truth_flask_2.3.2.json`
- `scripts/data/ground_truth_django_3.2_core.json`
- `scripts/data/ground_truth_dvwa.json`

## 5. Phase Plan

### Phase 1: JavaScript/TypeScript (Node/Express)

Scope:

- SQL injection
- NoSQL injection
- XSS
- RCE
- Path traversal
- Open redirect
- Deserialization
- SSRF

Focus areas:

- Data-flow continuity through aliasing and intermediate variables
- Call-chain semantic filtering to avoid API-name-only false positives
- Better source/sink pairing in framework contexts (Express request lifecycle)
- Sanitizer and safe-pattern recognition hardening

Evaluation targets:

- `tests/rules` JS/TS subset
- Acceptance benchmark JS cases
- Ground truth on Express/body-parser targets

Deliverables:

- Rule-level fixes with regression tests
- Phase 1 metrics report (before/after)

### Phase 2: Python (Flask/Django)

Scope:

- Same vulnerability set as Phase 1

Focus areas:

- Precise request source modeling (`request.args/form/json/data`, etc.)
- ORM/parameterized-query safe pattern recognition
- Command/path flow tracking through helper wrappers
- Deserialization and redirect precision tuning

Evaluation targets:

- `tests/rules` Python subset
- Ground truth on Flask and Django targets

Deliverables:

- Python rule precision/recall improvements with new regression fixtures
- Phase 2 metrics report

### Phase 3: PHP

Scope:

- Same vulnerability set as Phase 1

Focus areas:

- Superglobal propagation (`$_GET`, `$_POST`, `$_REQUEST`, etc.)
- Include/require path-control logic
- Exec-family command injection detection quality
- Parameterized SQL safe-case suppression
- Output encoding/sanitization recognition for XSS

Evaluation targets:

- `tests/rules` PHP subset
- Ground truth on DVWA

Deliverables:

- PHP rule and taint quality improvements
- Phase 3 metrics report

### Phase 4: Java and Go

Scope:

- Same vulnerability set as Phase 1 where language-applicable

Focus areas:

- Java: prepared statements, runtime process execution, deserialization pathways
- Go: exec/open/unmarshal risk boundaries and safe-case handling
- Improve parity between Java and Go behavior where semantically equivalent

Evaluation targets:

- `tests/rules` Java+Go subsets
- Existing real-world fixtures, plus incremental fixtures if needed

Deliverables:

- Java/Go rule quality improvements
- Phase 4 metrics report

## 6. Implementation Strategy

Per phase, use a repeated five-step loop:

1. Baseline capture (current metrics and failing/weak cases)
2. Root-cause analysis for top FP/FN items
3. Minimal bounded fixes (small change sets)
4. Regression fixture additions first (TDD)
5. Full validation and report generation

Change management rules:

- Do not batch unrelated refactors with detection logic changes.
- Keep commits focused by phase and by issue cluster.
- Preserve existing user/untracked workspace assets.

## 7. Risk Management

Primary risks:

- Overfitting to synthetic samples
- Precision improvements accidentally reducing recall
- Recall improvements introducing noisy FPs

Mitigations:

- Require both synthetic and real-project validation before phase completion
- Gate by non-regression metrics, not only absolute gains
- Add targeted regression tests for each fixed issue class

Rollback approach:

- Phase-isolated commits allow clean revert of a single phase if regression appears.

## 8. Reporting Format

Each phase report must include:

1. Baseline and post-change metrics table
2. Top corrected FP/FN examples
3. New regression tests added
4. Residual known gaps and next-phase carry-over items

## 9. Next Step

Start detailed execution planning for Phase 1 with concrete task breakdown, files to touch, validation commands, and checkpoints.
