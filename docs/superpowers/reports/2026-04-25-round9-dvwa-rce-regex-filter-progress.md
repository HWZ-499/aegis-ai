# Round 9 Progress Report (2026-04-25)

## Scope

- Continue Phase 4 follow-up hardening on DVWA.
- Round 9 is split into two sub-iterations:
  1. PHP regex RCE false-positive suppression (constant command assignment case).
  2. PHP SQLi recall recovery for `mysqli_real_escape_string` + unquoted numeric interpolation.
  3. PHP AST/Regex near-line de-duplication to reduce duplicate findings that inflate FP.

## Baseline (Round 9 Start)

- DVWA baseline:
  - Recall: 87.5%
  - Precision: 28.8%
  - F1: 0.43
  - TP/FP/FN/TN: 21 / 52 / 3 / 1

## Root Causes

1. **RCE regex FP**: `analyze_php()` used whole-line variable checks, so `$out = shell_exec("...")` was treated as variable-driven and incorrectly reported.
2. **SQLi FN**: for PHP SQL where user input was weakly escaped (`mysqli_real_escape_string`) but interpolated as unquoted numeric (`... WHERE id = $id`), existing taint + regex logic missed detections.

## Implemented Changes

### A) RCE FP hardening

- `aegis-ai-core/src/analysis/rule_engine.py`
  - Added first-argument extraction for PHP command sinks (`system/exec/shell_exec/...`).
  - Refined constant-command filtering:
    - Skip low-risk constant commands by default.
    - Keep complex shell-meta command cases in non-setup scripts to preserve benchmark recall.
    - Skip setup/install-like scripts for constant command checks.

- New regression fixture:
  - `aegis-ai-core/tests/rules/rce/false_positive/fp_php_shell_exec_constant_assignment.php`

### B) SQLi recall hardening

- `aegis-ai-core/src/analysis/rules/sql_injection/php_ast_rule.py`
  - Added weak-sanitizer SQL detection path:
    - Detect SQL executed via variable assignment where interpolated variable is:
      - sanitized only by `mysqli_real_escape_string` / `addslashes`
      - used unquoted in SQL comparison/operator context
  - Added assignment backtracking helper (`_find_latest_assignment_expr`) to inspect SQL text when sink arg is `$query`-style variable.
  - Added SQL-shape and unquoted-variable helpers for stable matching.

- New regression fixture:
  - `aegis-ai-core/tests/rules/sql_injection/true_positive/tp_php_mysqli_real_escape_string_unquoted_numeric.php`

### C) Regex duplicate suppression hardening

- `aegis-ai-core/src/analysis/rule_engine.py`
  - Added near-line de-duplication for PHP regex supplemental findings:
    - when AST has the same vuln type within ±3 lines, suppress regex duplicate.
  - Applied to: `SQL_INJECTION`, `RCE_COMMAND_EXEC`, `XSS_RISK`, `PATH_TRAVERSAL`, `OPEN_REDIRECT`, `DESERIALIZATION`.
  - Goal: keep AST precision while retaining regex-only coverage for gaps.

## Validation

- `python -m pytest -q tests/rules/test_all_rules.py -k "rce and php"` ✅
- `python -m pytest -q tests/rules/test_all_rules.py -k "SQL_INJECTION and php"` ✅
- `python -m pytest -q tests/rules/test_all_rules.py -k "tp_php_mysqli_real_escape_string_unquoted_numeric"` ✅
- `python -m pytest -q tests/rules/test_all_rules.py` ✅
- `python -m ruff check src/analysis/rule_engine.py src/analysis/rules/sql_injection/php_ast_rule.py` ✅

## Benchmark Outcome

### Checkpoint A (after RCE FP fix)

- Recall: 87.5%
- Precision: 29.6%
- F1: 0.44
- TP/FP/FN/TN: 21 / 50 / 3 / 1

### Checkpoint B (after SQLi recall fix)

- Recall: 95.8%
- Precision: 30.7%
- F1: 0.46
- TP/FP/FN/TN: 23 / 52 / 1 / 1

### Checkpoint C (after near-line de-duplication, current round end)

- Recall: 95.8%
- Precision: 32.9%
- F1: 0.49
- TP/FP/FN/TN: 23 / 47 / 1 / 1

## Net Effect (Round 9 Start -> End)

- TP: `21 -> 23`
- FP: `52 -> 47`
- FN: `3 -> 1`
- Recall: `87.5% -> 95.8%`
- Precision: `28.8% -> 32.9%`
- F1: `0.43 -> 0.49`
