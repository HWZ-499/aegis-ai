# Round 9 Progress Report (2026-04-25)

## Scope

- Continue real-world precision hardening from Phase 4 follow-up.
- This round focuses on a PHP regex-layer RCE false-positive pattern found in DVWA and rule fixtures.

## Baseline (Round 9 Start)

- DVWA (2026-04-25 baseline):
  - Recall: 87.5%
  - Precision: 28.8%
  - F1: 0.43
  - TP/FP/FN/TN: 21 / 52 / 3 / 1

## Root Cause

The PHP regex supplemental filter in `analyze_php()` used whole-line variable checks:

- For lines like `$out = shell_exec("php -v");`, the left-hand `$out` made the line look "variable-driven".
- That prevented the "constant command" skip path and produced avoidable RCE false positives.

## Implemented Changes

### Code updates

- `aegis-ai-core/src/analysis/rule_engine.py`
  - Added `_extract_first_php_call_argument()` to parse first argument of PHP command-exec sinks (`system/exec/shell_exec/...`) without being confused by left-value variables.
  - Added literal-expression recognition for PHP command arguments.
  - Refined regex supplemental RCE filtering:
    - Skip constant command expressions by default (reduces FP).
    - Keep complex shell-meta commands in non-setup scripts (preserves recall on existing benchmark expectation).
    - Always skip setup/install-like scripts for constant command checks.

### New regression fixture (RED -> GREEN)

- `aegis-ai-core/tests/rules/rce/false_positive/fp_php_shell_exec_constant_assignment.php`
  - Case: `$out = shell_exec("php -v");`
  - Expected: no `RCE_COMMAND_EXEC`.

## Validation

- RED: new fixture initially failed (reported `RCE_COMMAND_EXEC` from `PHP-Regex`).
- GREEN after fix:
  - `python -m pytest -q tests/rules/test_all_rules.py -k "rce and php"` ✅
  - `python -m pytest -q tests/rules/test_all_rules.py` ✅
  - `python -m ruff check src/analysis/rule_engine.py` ✅

## Benchmark Outcome (Round 9 Current)

- DVWA re-evaluated on 2026-04-25:
  - Recall: 87.5% (no regression vs baseline)
  - Precision: 29.6% (improved from 28.8%)
  - F1: 0.44 (improved from 0.43)
  - TP/FP/FN/TN: 21 / 50 / 3 / 1

Net effect in this round:

- FP: `52 -> 50`
- Recall: `87.5% -> 87.5%`
- Precision: `28.8% -> 29.6%`
- F1: `0.43 -> 0.44`
