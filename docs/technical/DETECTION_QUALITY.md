# 检测质量：基准与误报/漏报治理

本文说明如何通过**自建基准**（TP/TN 用例）常态化跑 **Recall / Precision / F1**，并用于**误报/漏报治理**与回归。

---

## 1. 指标含义

| 指标 | 公式 | 含义 |
|------|------|------|
| **Recall（检测率）** | TP / (TP + FN) | 应报的漏洞中有多少被检出；漏报少则 Recall 高 |
| **Precision（精确率）** | TP / (TP + FP) | 报出的问题中有多少真是漏洞；误报少则 Precision 高 |
| **FPR（误报率）** | FP / (TN + FP) | 不该报的用例中被误报的比例 |
| **F1** | 2×P×R / (P+R) | Recall 与 Precision 的调和平均，综合质量 |

- **TP**：应报且报了（True Positive）  
- **FP**：不该报却报了（False Positive，误报）  
- **FN**：应报未报（False Negative，漏报）  
- **TN**：不该报且未报（True Negative）

---

## 2. 如何跑基准

### 2.1 单命令跑基准并写报告（推荐）

在 **aegis-ai-core** 目录下执行：

```powershell
cd c:\Users\HT341\aegis-ai\aegis-ai-core

# 跑自建 TP/TN 用例，输出 Markdown + JSON 到 reports/
python scripts/run_benchmark_report.py
```

输出文件：

- `reports/benchmark_report_YYYY-MM-DD.md`：人类可读的 Recall/Precision/F1 及按漏洞类型统计  
- `reports/benchmark_report_YYYY-MM-DD.json`：机器可读，便于 CI 或趋势对比  

控制台会打印摘要，例如：

```
Recall: 85.0%, Precision: 90.0%, F1: 0.87
```

### 2.2 仅跑基准不写文件

```powershell
python -m src.scanner.benchmark
```

### 2.3 用 pytest 跑验收基准（含阈值断言）

```powershell
python -m pytest tests/test_acceptance_benchmark.py -v
```

当前验收阈值（在 `test_acceptance_benchmark.py` 中）：

- **Recall** ≥ 70%  
- **FPR** ≤ 20%  
- **F1** ≥ 0.75  

若修改规则或污点逻辑，应保证上述测试通过，避免检测质量回退。

---

## 3. 误报/漏报治理流程

1. **跑基准**：执行 `python scripts/run_benchmark_report.py`，查看 `reports/benchmark_report_*.md` 中的 FP/FN 明细。  
2. **定位用例**：`src/scanner/benchmark_cases.py` 中 `BENCH_CASES_TP`（应报）与 `BENCH_CASES_TN`（不应报）是唯一数据源；每个用例有 `id`、`category`、`code`、`expect_finding`。  
3. **治理误报（FP）**：若某 TN 用例被误报，在对应规则中增加排除条件（如 NoSQL 规则对 crypto/哈希类 `.update()` 不报、对 `[].find()` 不报）。改完后重跑基准与 `test_acceptance_benchmark`。  
4. **治理漏报（FN）**：若某 TP 用例未报，检查规则/污点是否覆盖该模式（如解构、模板字符串、路由回调）；补规则或用例后重跑。  
5. **回归**：每次规则/污点改动后跑 `python -m pytest tests/test_acceptance_benchmark.py` 与（可选）`python scripts/run_benchmark_report.py`，对比前后 F1/Recall/Precision。

---

## 4. 新增基准用例

在 `src/scanner/benchmark_cases.py` 中：

- **应报的漏洞**：加入 `BENCH_CASES_TP`，`expect_finding=True`，`category` 为规则类型（如 `NOSQL_INJECTION`、`RCE_COMMAND_EXEC`）。  
- **不应报的安全代码**：加入 `BENCH_CASES_TN`，`expect_finding=False`，`category` 为希望不触发的类型。  

用例结构见 `BenchCase`：`id`、`category`、`pattern`（简短描述）、`code`（源码）、`expect_finding`。  
新增后请跑 `tests/test_acceptance_benchmark.py` 与 `run_benchmark_report.py` 确认指标与阈值。

---

## 5. 真实项目评估（可选）

若要对 NodeGoat 等真实项目做 Recall/Precision 评估，需提供 **ground-truth**（预期漏洞列表）。参见：

- `scripts/benchmark/evaluate_project.py`：对指定项目目录 + ground-truth 列表跑扫描并输出 Recall/Precision/F1。
- `src/scanner/benchmark.py` 中 `evaluate_project_against_ground_truth()`：接口与格式说明。  

Ground-truth 格式：每项 `{"file": str, "line": int, "type": str}`，`file` 可为路径后缀或 glob。

---

## 6. M3 常态化流程（何时跑、阈值）

| 时机 | 建议操作 |
|------|----------|
| **规则/污点改动后** | 跑 `python -m pytest tests/test_acceptance_benchmark.py`，确保 Recall ≥ 70%、FPR ≤ 20%、F1 ≥ 0.75。 |
| **发版或 MR 前** | 同上；可选再跑 `python scripts/run_benchmark_report.py` 留存当日报告。 |
| **定期（如每周）** | 跑 `python scripts/run_benchmark_report.py`，查看 `reports/benchmark_report_*.md` 与 JSON，对比历史 F1/Recall。 |

**当前验收阈值**（在 `test_acceptance_benchmark.py`）：Recall ≥ 70%，FPR ≤ 20%，F1 ≥ 0.75。若基准用例扩充，可酌情提高阈值。

---

## 7. CI 建议

在 CI 中增加基准门禁，防止规则改动导致检测质量回退：

```yaml
# 示例：GitHub Actions / GitLab CI
- name: 检测质量门禁（M3）
  run: python -m pytest tests/test_acceptance_benchmark.py -v
```

该测试会断言 Recall ≥ 70%、FPR ≤ 20%、F1 ≥ 0.75；不通过则 CI 失败。  
**当前 CI**（`.github/workflows/security-scan.yml`）：在 M3 基准验收通过后，会执行 `run_benchmark_report.py` 并将 `reports/benchmark_report_*.json` 上传为 artifact（保留 90 天），便于在 Actions 中下载做趋势对比。

---

## 8. 参考

- 基准用例定义：`src/scanner/benchmark_cases.py`  
- 基准运行与报告：`src/scanner/benchmark.py`  
- 验收测试与阈值：`tests/test_acceptance_benchmark.py`  
- 产品验证总览：`docs/VERIFICATION_GUIDE.md`  

---

## 8. 最新真实项目评估快照（2026-06-09）

DVWA 当前复评命令:

```powershell
cd c:\Users\HT341\aegis-ai\aegis-ai-core
python scripts/benchmark/evaluate_project.py --project-dir real_world_targets/DVWA --ground-truth scripts/data/ground_truth_dvwa.json
```

结果已归档到:

- `aegis-ai-core/scripts/reports/evaluate_DVWA_2026-06-09.md`
- `aegis-ai-core/scripts/reports/evaluate_DVWA_2026-06-09.json`

当前指标:

| 目标 | TP | FP | FN | TN | Recall | Precision | F1 |
|------|----|----|----|----|--------|-----------|----|
| DVWA | 24 | 18 | 0 | 3 | 100.0% | 57.1% | 0.73 |

本轮状态说明:

- PHP SQLi 数字 guard 降噪已进入主线；strict digit guard 后的 DVWA BAC medium `user_id` 查询不再按 SQLi 计入 TP。
- 剩余 FP 主要在 XSS、SQLi 和 Path Traversal；继续治理时仍需避免压掉 ground-truth 未标注但真实可疑的弱点。

---

## 9. 阶段收口快照（2026-04-23）

本轮多阶段收口报告已落盘：

- `aegis-ai-core/reports/phase_summary_2026-04-23.md`

本次统一质量门结果：

- `aegis-ai-core`:
  - `python -m ruff check src tests` 通过
  - `python -m mypy src --hide-error-context --no-color-output` 通过
  - `python -m pytest -q` 通过（`469 passed, 47 deselected, 1 xfailed`）
- `aegis-vscode`:
  - `npm run check` 通过
  - `npm test` 通过（`27 passing`）

建议后续继续按“规则样例 + 真实项目 ground-truth”双轨维护，避免仅在样例集上指标乐观。

---

## 10. Round 6 真实项目基准扩展（2026-04-23）

新增了 Java/Go 的项目级 pilot benchmark 与对应 ground-truth：

- `scripts/data/ground_truth_java_deserialization_demo.json`
- `scripts/data/ground_truth_go_insecure_web_app.json`

同时恢复了 PHP 的 DVWA 项目级评估（目标目录已补齐）。

当日评估结果：

- PHP（DVWA）：Recall=87.5%，Precision=28.8%，F1=0.43
- Java（java-deserialization-demo pilot）：Recall=0.0%，Precision=0.0%，F1=0.00
- Go（go-insecure-web-app pilot）：Recall=0.0%，Precision=0.0%，F1=0.00

这组数据可作为后续 Java/Go 规则迭代的项目级基线。
