# Round 6 Progress Report (2026-04-23)

## Scope

- Step 2: restore PHP real-project evaluation by reintroducing DVWA target in `real_world_targets` and re-running benchmark.
- Step 3: add first Java/Go project-level benchmark targets and ground-truth baselines.

## Step 2: DVWA Restoration (PHP)

### Actions

- Cloned DVWA target:
  - `real_world_targets/DVWA`
- Ran evaluation:
  - `python scripts/benchmark/evaluate_project.py --project-dir real_world_targets/DVWA --ground-truth scripts/data/ground_truth_dvwa.json`

### Result

- Output:
  - `scripts/reports/evaluate_DVWA_2026-04-23.{md,json}`
- Metrics:
  - TP=21, FP=52, FN=3, TN=0
  - Recall=87.5%, Precision=28.8%, F1=0.43

## Step 3: Java/Go Project-Level Pilot Benchmarks

### New targets

- Java pilot target:
  - `real_world_targets/java-webapp-security-lab`
  - benchmark scope: `java-deserialization-demo` subproject
- Go pilot target:
  - `real_world_targets/go-insecure-web-app`

### New ground-truth files

- `scripts/data/ground_truth_java_deserialization_demo.json`
- `scripts/data/ground_truth_go_insecure_web_app.json`

### Evaluation commands

- Java:
  - `python scripts/benchmark/evaluate_project.py --project-dir real_world_targets/java-webapp-security-lab/java-deserialization-demo --ground-truth scripts/data/ground_truth_java_deserialization_demo.json --target-name java-deserialization-demo --output-dir scripts/reports`
- Go:
  - `python scripts/benchmark/evaluate_project.py --project-dir real_world_targets/go-insecure-web-app --ground-truth scripts/data/ground_truth_go_insecure_web_app.json --target-name go-insecure-web-app --output-dir scripts/reports`

### Pilot results

- Java (`java-deserialization-demo`):
  - TP=0, FP=0, FN=1, TN=1
  - Recall=0.0%, Precision=0.0%, F1=0.00
- Go (`go-insecure-web-app`):
  - TP=0, FP=2, FN=3, TN=2
  - Recall=0.0%, Precision=0.0%, F1=0.00

## Bootstrap script update

Updated target bootstrap scripts to include DVWA + Java/Go pilot repos:

- `scripts/data/clone_test_targets.ps1`
- `scripts/data/clone_test_targets.sh`

Added quick-start evaluation command examples for:

- DVWA (PHP)
- java-deserialization-demo (Java)
- go-insecure-web-app (Go)

## Outcome

- PHP project-level benchmark blocker is removed.
- Java/Go now has reproducible project-level benchmark entry points and baseline metrics.
- Baselines clearly expose current gaps and can be used for next RED->GREEN rule iterations.
