# Scanning Capability Optimization Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve scanner quality across JS/TS, Python, PHP, and Java/Go with balanced FP/FN reduction and measurable per-phase gains.

**Architecture:** Execute four ordered phases (JS/TS -> Python -> PHP -> Java/Go) using a consistent loop: baseline capture -> root-cause debugging -> TDD rule fixes -> full regression -> metrics report. Keep phase boundaries strict so each phase is independently reviewable and reversible.

**Tech Stack:** Python 3.11, pytest, mypy, ruff, Aegis rule engine, AST rules, taint analysis, benchmark/evaluate scripts, JSON/Markdown reports.

---

## Working Rules

- Use `@test-driven-development` for every behavior change.
- Use `@systematic-debugging` before each non-trivial fix.
- Keep changes phase-local and commit frequently.
- Never touch `aegis-ai-core/real_world_targets/*` contents.

## File Map

### Existing files to modify through phases

- `aegis-ai-core/src/analysis/rules/*/*_ast_rule.py`
- `aegis-ai-core/src/analysis/rules/*/ast_rule.py`
- `aegis-ai-core/src/analysis/taint/taint_analyzer.py`
- `aegis-ai-core/src/analysis/base/js_dataflow_collector.py`
- `aegis-ai-core/src/scanner/benchmark.py`
- `aegis-ai-core/src/scanner/benchmark_cases.py`
- `aegis-ai-core/tests/rules/test_all_rules.py`
- `aegis-ai-core/tests/test_acceptance_benchmark.py`

### New files to create

- `aegis-ai-core/scripts/benchmark/phase_metrics.py`
- `aegis-ai-core/reports/phase1_js_ts_metrics_<date>.md`
- `aegis-ai-core/reports/phase2_python_metrics_<date>.md`
- `aegis-ai-core/reports/phase3_php_metrics_<date>.md`
- `aegis-ai-core/reports/phase4_java_go_metrics_<date>.md`
- New TP/FP fixtures under:
  - `aegis-ai-core/tests/rules/sql_injection/*`
  - `aegis-ai-core/tests/rules/nosql_injection/*`
  - `aegis-ai-core/tests/rules/rce/*`
  - `aegis-ai-core/tests/rules/xss/*`
  - `aegis-ai-core/tests/rules/path_traversal/*`
  - `aegis-ai-core/tests/rules/open_redirect/*`
  - `aegis-ai-core/tests/rules/deserialization/*`
  - `aegis-ai-core/tests/rules/ssrf/*`

---

### Task 1: Build Phase Metrics Harness

**Files:**
- Create: `aegis-ai-core/scripts/benchmark/phase_metrics.py`
- Modify: `aegis-ai-core/scripts/benchmark/run_benchmark_report.py`
- Test: `aegis-ai-core/tests/test_benchmark_engine_dispatch.py`

- [ ] **Step 1: Write failing test for language-filtered metrics output**

```python
def test_phase_metrics_prints_language_sections(capsys):
    from scripts.benchmark.phase_metrics import render_summary
    render_summary({"javascript": {"tp": 1, "fp": 0, "fn": 0, "tn": 1}})
    out = capsys.readouterr().out
    assert "javascript" in out
    assert "recall=100.0%" in out
```

- [ ] **Step 2: Run test to verify failure**

Run: `python -m pytest aegis-ai-core/tests/test_benchmark_engine_dispatch.py -k phase_metrics -q`  
Expected: FAIL (`ImportError` / function missing).

- [ ] **Step 3: Write minimal implementation**

```python
def render_summary(stats: dict[str, dict[str, int]]) -> None:
    for lang, s in sorted(stats.items()):
        tp, fp, fn, tn = s["tp"], s["fp"], s["fn"], s["tn"]
        recall = tp / (tp + fn) if tp + fn else 0.0
        print(f"{lang}: tp={tp} fp={fp} fn={fn} tn={tn} recall={recall:.1%}")

if __name__ == "__main__":
    # argparse: --language, --output
    # run language-filtered collection and write markdown report
    ...
```

- [ ] **Step 4: Run test to verify pass**

Run: `python -m pytest aegis-ai-core/tests/test_benchmark_engine_dispatch.py -k phase_metrics -q`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis-ai-core/scripts/benchmark/phase_metrics.py aegis-ai-core/scripts/benchmark/run_benchmark_report.py aegis-ai-core/tests/test_benchmark_engine_dispatch.py
git commit -m "feat(benchmark): add per-language phase metrics harness"
```

---

### Task 2: Prepare Real-World Targets

**Files:**
- Modify (if needed): `aegis-ai-core/scripts/data/clone_test_targets.ps1`

- [ ] **Step 1: Verify required target directories exist**

Run:
- `Get-ChildItem aegis-ai-core/real_world_targets`

Expected directories:
- `express-4.18.1`
- `body-parser-1.20.0`
- `flask-2.3.2`
- `django-3.2`
- `dvwa` (or `DVWA`)

- [ ] **Step 2: Clone missing targets**

Run:
- `powershell -ExecutionPolicy Bypass -File aegis-ai-core/scripts/data/clone_test_targets.ps1`

Expected: all target repos available locally for benchmark evaluation.

- [ ] **Step 3: Commit script updates only if clone script was changed**

```bash
git add aegis-ai-core/scripts/data/clone_test_targets.ps1
git commit -m "chore(data): update benchmark target bootstrap script"
```

---

### Task 3: Phase 1 Baseline (JS/TS)

**Files:**
- Modify: `aegis-ai-core/scripts/benchmark/phase_metrics.py`
- Output: `aegis-ai-core/reports/phase1_js_ts_metrics_<date>.md`

- [ ] **Step 1: Run JS/TS synthetic baseline**

Run: `python aegis-ai-core/scripts/benchmark/phase_metrics.py --language javascript --output aegis-ai-core/reports/phase1_js_ts_metrics_<date>.md`  
Expected: Baseline TP/TN/FP/FN snapshot recorded.

- [ ] **Step 2: Run acceptance baseline**

Run: `python -m pytest aegis-ai-core/tests/test_acceptance_benchmark.py -m acceptance -q -s`  
Expected: printed benchmark table saved to report notes.

- [ ] **Step 3: Run real-project baseline (Express + body-parser)**

Run:
`python aegis-ai-core/scripts/benchmark/evaluate_project.py --project-dir aegis-ai-core/real_world_targets/express-4.18.1 --ground-truth aegis-ai-core/scripts/data/ground_truth_express_4.18.1.json`

Run:
`python aegis-ai-core/scripts/benchmark/evaluate_project.py --project-dir aegis-ai-core/real_world_targets/body-parser-1.20.0 --ground-truth aegis-ai-core/scripts/data/ground_truth_body_parser_1.20.0.json`

Expected: two baseline reports under `aegis-ai-core/reports/`.

- [ ] **Step 4: Commit baseline artifacts**

```bash
git add aegis-ai-core/reports/phase1_js_ts_metrics_*.md
git commit -m "chore(phase1): capture JS/TS baseline metrics"
```

---

### Task 4: Phase 1 Rule Improvements (JS/TS)

**Files:**
- Modify: `aegis-ai-core/src/analysis/rules/sql_injection/javascript_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/nosql_injection/javascript_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/rce/javascript_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/xss/javascript_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/path_traversal/javascript_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/open_redirect/javascript_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/deserialization/javascript_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/ssrf/javascript_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/base/js_dataflow_collector.py`
- Test: `aegis-ai-core/tests/rules/test_all_rules.py`
- Test fixtures: `aegis-ai-core/tests/rules/*/true_positive/*.js`, `aegis-ai-core/tests/rules/*/false_positive/*.js`

- [ ] **Step 1: Add one failing TP fixture for variable propagation SQLi**

```javascript
// tp_js_sql_var_chain.js
const id = req.query.id;
const q = "SELECT * FROM users WHERE id=" + id;
db.query(q);
```

- [ ] **Step 2: Run targeted test and confirm failure**

Run: `python -m pytest aegis-ai-core/tests/rules/test_all_rules.py -k "SQL_INJECTION and js_sql_var_chain" -q`  
Expected: FAIL (FN).

- [ ] **Step 3: Implement minimal propagation fix**

```python
# in javascript_ast_rule.py
if is_identifier(arg) and context.is_var_tainted(arg_name):
    report_sqli(...)
```

- [ ] **Step 4: Re-run targeted test**

Run: `python -m pytest aegis-ai-core/tests/rules/test_all_rules.py -k "SQL_INJECTION and js_sql_var_chain" -q`  
Expected: PASS.

- [ ] **Step 5: Repeat the same RED->GREEN cycle for NoSQL/RCE/XSS/Path/Redirect/Deser/SSRF**

Run command template:  
`python -m pytest aegis-ai-core/tests/rules/test_all_rules.py -k "<TYPE> and <fixture_name>" -q`

- [ ] **Step 6: Commit phase 1 rule fixes**

```bash
git add aegis-ai-core/src/analysis/base/js_dataflow_collector.py aegis-ai-core/src/analysis/rules/*/javascript_ast_rule.py aegis-ai-core/tests/rules
git commit -m "feat(phase1): improve JS/TS detection precision and recall"
```

---

### Task 5: Phase 1 Validation And Report

**Files:**
- Modify: `aegis-ai-core/reports/phase1_js_ts_metrics_<date>.md`

- [ ] **Step 1: Run full quality gates**

Run:
- `python -m ruff check aegis-ai-core/src aegis-ai-core/tests`
- `python -m mypy aegis-ai-core/src --hide-error-context --no-color-output`
- `python -m pytest`

Expected: all PASS.

- [ ] **Step 2: Re-run phase 1 benchmarks**

Run:
- `python -m pytest aegis-ai-core/tests/test_acceptance_benchmark.py -m acceptance -q -s`
- `python aegis-ai-core/scripts/benchmark/evaluate_project.py --project-dir aegis-ai-core/real_world_targets/express-4.18.1 --ground-truth aegis-ai-core/scripts/data/ground_truth_express_4.18.1.json`
- `python aegis-ai-core/scripts/benchmark/evaluate_project.py --project-dir aegis-ai-core/real_world_targets/body-parser-1.20.0 --ground-truth aegis-ai-core/scripts/data/ground_truth_body_parser_1.20.0.json`

- [ ] **Step 3: Write before/after section into report**

```markdown
| Metric | Before | After |
|--------|--------|-------|
| Recall |  |  |
| Precision |  |  |
| F1 |  |  |
| FP |  |  |
| FN |  |  |
```

- [ ] **Step 4: Commit phase 1 report**

```bash
git add aegis-ai-core/reports/phase1_js_ts_metrics_*.md
git commit -m "docs(phase1): publish JS/TS quality improvement report"
```

---

### Task 6: Phase 2 Python Improvements

**Files:**
- Modify: `aegis-ai-core/src/analysis/rules/sql_injection/ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/rce/ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/path_traversal/ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/open_redirect/python_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/ssrf/python_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/nosql_injection/python_ast_rule.py`
- Test fixtures: `aegis-ai-core/tests/rules/*/*/*.py`
- Output: `aegis-ai-core/reports/phase2_python_metrics_<date>.md`

- [ ] **Step 1: Re-enable skipped Python SQLi TP scenario with failing test**

```python
def test_python_execute_variable_query_is_detected():
    code = "q = f'SELECT * FROM users WHERE id={user_id}'; cur.execute(q)"
    findings = analyze_python(code, "case.py")
    assert any(f["type"] == "SQL_INJECTION" for f in findings)
```

- [ ] **Step 2: Run targeted Python tests to verify failure**

Run: `python -m pytest aegis-ai-core/tests/rules/test_all_rules.py -k "SQL_INJECTION and python" -q`  
Expected: at least one FAIL (FN).

- [ ] **Step 3: Implement minimal SQLi flow fix (assignment -> execute)**

```python
# pseudo-implementation detail in ast_rule.py
if call.func.attr == "execute" and is_tainted_sql_expr(call.args[0], context):
    report_sqli(...)
```

- [ ] **Step 4: Repeat RED->GREEN for redirect/path/rce/ssrf edge cases**

Run command template:  
`python -m pytest aegis-ai-core/tests/rules/test_all_rules.py -k "<TYPE> and python" -q`

- [ ] **Step 5: Run Flask/Django project evaluations and write phase report**

Run:
- `python aegis-ai-core/scripts/benchmark/evaluate_project.py --project-dir aegis-ai-core/real_world_targets/flask-2.3.2 --ground-truth aegis-ai-core/scripts/data/ground_truth_flask_2.3.2.json`
- `python aegis-ai-core/scripts/benchmark/evaluate_project.py --project-dir aegis-ai-core/real_world_targets/django-3.2 --ground-truth aegis-ai-core/scripts/data/ground_truth_django_3.2_core.json`

- [ ] **Step 6: Commit phase 2 changes**

```bash
git add aegis-ai-core/src/analysis/rules aegis-ai-core/tests/rules aegis-ai-core/reports/phase2_python_metrics_*.md
git commit -m "feat(phase2): improve Python scanner quality and add regression coverage"
```

---

### Task 7: Phase 3 PHP Improvements

**Files:**
- Modify: `aegis-ai-core/src/analysis/rules/sql_injection/php_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/rce/php_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/xss/php_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/path_traversal/php_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/open_redirect/php_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/nosql_injection/php_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/deserialization/php_ast_rule.py`
- Test fixtures: `aegis-ai-core/tests/rules/*/*/*.php`
- Output: `aegis-ai-core/reports/phase3_php_metrics_<date>.md`

- [ ] **Step 1: Add failing FP fixtures for sanitized flows**

```php
<?php
$id = (int)$_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
```

- [ ] **Step 2: Run targeted PHP tests and verify FP exists**

Run: `python -m pytest aegis-ai-core/tests/rules/test_all_rules.py -k "php and SQL_INJECTION" -q`  
Expected: FAIL on FP case.

- [ ] **Step 3: Implement minimal safe-pattern suppression**

```python
# in php_ast_rule.py
if is_prepared_statement_flow(node):
    return  # safe path, no finding
```

- [ ] **Step 4: Repeat RED->GREEN for include/require path and exec-family flows**

Run command template:  
`python -m pytest aegis-ai-core/tests/rules/test_all_rules.py -k "<TYPE> and php" -q`

- [ ] **Step 5: Run DVWA evaluation and write report**

Run:
`python aegis-ai-core/scripts/benchmark/evaluate_project.py --project-dir aegis-ai-core/real_world_targets/dvwa --ground-truth aegis-ai-core/scripts/data/ground_truth_dvwa.json`

Fallback when directory is uppercase:
`python aegis-ai-core/scripts/benchmark/evaluate_project.py --project-dir aegis-ai-core/real_world_targets/DVWA --ground-truth aegis-ai-core/scripts/data/ground_truth_dvwa.json`

- [ ] **Step 6: Commit phase 3 changes**

```bash
git add aegis-ai-core/src/analysis/rules aegis-ai-core/tests/rules aegis-ai-core/reports/phase3_php_metrics_*.md
git commit -m "feat(phase3): improve PHP detection precision and recall"
```

---

### Task 8: Phase 4 Java/Go Improvements

**Files:**
- Modify: `aegis-ai-core/src/analysis/rules/sql_injection/java_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/sql_injection/go_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/rce/java_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/rce/go_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/deserialization/java_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/deserialization/go_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/path_traversal/java_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/path_traversal/go_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/open_redirect/java_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/open_redirect/go_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/xss/java_ast_rule.py`
- Modify: `aegis-ai-core/src/analysis/rules/xss/go_ast_rule.py`
- Output: `aegis-ai-core/reports/phase4_java_go_metrics_<date>.md`

- [ ] **Step 1: Add failing FN fixture for Java prepared/unsafe split**

```java
String q = "SELECT * FROM users WHERE id=" + req.getParameter("id");
stmt.executeQuery(q);
```

- [ ] **Step 2: Add failing FP fixture for safe prepared statement**

```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id=?");
ps.setString(1, id);
ps.executeQuery();
```

- [ ] **Step 3: Run targeted Java/Go tests to verify RED state**

Run:
- `python -m pytest aegis-ai-core/tests/rules/test_all_rules.py -k "java and SQL_INJECTION" -q`
- `python -m pytest aegis-ai-core/tests/rules/test_all_rules.py -k "go and SQL_INJECTION" -q`

- [ ] **Step 4: Implement minimal data-flow and safe-pattern fixes**

```python
# pattern for both java/go rule files
if uses_prepared_statement(node):
    return
if tainted_input_reaches_sink(node, context):
    context.add_finding(...)
```

- [ ] **Step 5: Re-run targeted tests and then full rules suite**

Run:
- `python -m pytest aegis-ai-core/tests/rules/test_all_rules.py -k "java or go" -q`
- `python -m pytest aegis-ai-core/tests/rules/test_all_rules.py -q`

- [ ] **Step 6: Write metrics report and commit**

```bash
git add aegis-ai-core/src/analysis/rules aegis-ai-core/tests/rules aegis-ai-core/reports/phase4_java_go_metrics_*.md
git commit -m "feat(phase4): improve Java/Go rule quality with balanced FP/FN reduction"
```

---

### Task 9: Final Cross-Phase Validation And Consolidation

**Files:**
- Modify: `aegis-ai-core/reports/phase_summary_<date>.md`
- Optional modify: `docs/technical/DETECTION_QUALITY.md`

- [ ] **Step 1: Run full repository gates once**

Run:
- `python -m ruff check aegis-ai-core/src aegis-ai-core/tests`
- `python -m mypy aegis-ai-core/src --hide-error-context --no-color-output`
- `python -m pytest`
- `cd aegis-vscode && npm run check && npm test`

- [ ] **Step 2: Generate consolidated summary table**

```markdown
| Phase | Stack | FP Before | FP After | FN Before | FN After | F1 Before | F1 After |
|------|-------|-----------|----------|-----------|----------|-----------|----------|
```

- [ ] **Step 3: Record residual risks**

```markdown
- Remaining weak patterns:
  - ...
- Deferred candidates:
  - ...
```

- [ ] **Step 4: Commit final report**

```bash
git add aegis-ai-core/reports/phase_summary_*.md docs/technical/DETECTION_QUALITY.md
git commit -m "docs: publish multi-phase scanner capability optimization summary"
```
