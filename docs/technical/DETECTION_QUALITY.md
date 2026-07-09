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

# 跑自建 TP/TN 用例和完整规则样本矩阵
python scripts/benchmark/run_benchmark_report.py
```

输出文件：

- `reports/benchmark_report_YYYY-MM-DD.md`：人类可读的 Recall/Precision/F1 及按漏洞类型统计  
- `reports/benchmark_report_YYYY-MM-DD.json`：机器可读，便于 CI 或趋势对比  
- `reports/quality_matrix_YYYY-MM-DD.md`：按语言及“语言 × 漏洞类型”统计的质量矩阵
- `reports/quality_matrix_YYYY-MM-DD.json`：供 CI 趋势比较的机器可读质量矩阵

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
python -m pytest -m acceptance tests/test_acceptance_benchmark.py -v
```

当前验收阈值（在 `test_acceptance_benchmark.py` 中）：

- **Recall** ≥ 70%  
- **FPR** ≤ 20%  
- **F1** ≥ 0.75  

完整 `tests/rules` 受控样本还有一层更严格的门禁：

- 总体与每种语言 **Recall / Precision / F1 = 100%**
- 总体与每种语言 **FPR = 0%**

该严格门禁用于防止已覆盖规则回退，不代表真实项目准确率为 100%。

若修改规则或污点逻辑，应保证上述测试通过，避免检测质量回退。

---

## 3. 误报/漏报治理流程

1. **跑基准**：执行 `python scripts/benchmark/run_benchmark_report.py`，查看 `benchmark_report_*.md` 和 `quality_matrix_*.md` 中的 FP/FN 明细。
2. **定位用例**：`src/scanner/benchmark_cases.py` 中 `BENCH_CASES_TP`（应报）与 `BENCH_CASES_TN`（不应报）是唯一数据源；每个用例有 `id`、`category`、`code`、`expect_finding`。  
3. **治理误报（FP）**：若某 TN 用例被误报，在对应规则中增加排除条件（如 NoSQL 规则对 crypto/哈希类 `.update()` 不报、对 `[].find()` 不报）。改完后重跑基准与 `test_acceptance_benchmark`。  
4. **治理漏报（FN）**：若某 TP 用例未报，检查规则/污点是否覆盖该模式（如解构、模板字符串、路由回调）；补规则或用例后重跑。  
5. **回归**：每次规则/污点改动后跑 `python -m pytest -m acceptance tests/test_acceptance_benchmark.py` 与（可选）`python scripts/benchmark/run_benchmark_report.py`，对比前后 F1/Recall/Precision。

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
| **规则/污点改动后** | 跑 `python -m pytest -m acceptance tests/test_acceptance_benchmark.py`，确保 Recall ≥ 70%、FPR ≤ 20%、F1 ≥ 0.75。 |
| **发版或 MR 前** | 同上；可选再跑 `python scripts/benchmark/run_benchmark_report.py` 留存当日报告。 |
| **定期（如每周）** | 跑 `python scripts/benchmark/run_benchmark_report.py`，查看基准报告和质量矩阵，对比历史 F1/Recall。 |

**当前验收阈值**（在 `test_acceptance_benchmark.py`）：Recall ≥ 70%，FPR ≤ 20%，F1 ≥ 0.75。若基准用例扩充，可酌情提高阈值。

---

## 7. CI 建议

在 CI 中增加基准门禁，防止规则改动导致检测质量回退：

```yaml
# 示例：GitHub Actions / GitLab CI
- name: 检测质量门禁（M3）
  run: python -m pytest -m acceptance tests/test_acceptance_benchmark.py -v
```

该测试同时执行基础基准阈值和完整规则样本严格门禁；不通过则 CI 失败。
**当前 CI**（`.github/workflows/security-scan.yml`）：验收通过后执行 `scripts/benchmark/run_benchmark_report.py`，并上传 `benchmark_report_*.json` 与 `quality_matrix_*.json` artifact（保留 90 天）。

---

## 8. 参考

- 基准用例定义：`src/scanner/benchmark_cases.py`  
- 基准运行与报告：`src/scanner/benchmark.py`  
- 验收测试与阈值：`tests/test_acceptance_benchmark.py`  
- 产品验证总览：`docs/VERIFICATION_GUIDE.md`  

---

## 9. O6 统一质量矩阵（2026-06-21）

统一入口 `run_rule_sample_benchmark()` 会使用与 CLI/LSP 相同的生产分析器扫描
`tests/rules`，并同时记录总体、漏洞类型、语言、语言 × 漏洞类型四个维度。

当前 207 个受控样本结果：

| 语言 | TP | TN | FP | FN | Recall | Precision |
|------|---:|---:|---:|---:|-------:|----------:|
| Go | 17 | 14 | 0 | 0 | 100% | 100% |
| Java | 22 | 16 | 0 | 0 | 100% | 100% |
| JavaScript | 19 | 18 | 0 | 0 | 100% | 100% |
| PHP | 31 | 26 | 0 | 0 | 100% | 100% |
| Python | 26 | 18 | 0 | 0 | 100% | 100% |

此前指标脚本静默跳过的 `tp_python_cursor_execute_format.py` 已恢复统计。
真实项目仍应单独运行 ground-truth 评估，不能用受控样本结果替代。

PHP RCE/XSS 已在 2026-06-21 收敛为 AST-only：公共 API、LSP 和项目扫描
不再接收这两类的 `PHP-Regex` finding。新增覆盖包括反引号命令执行、
`call_user_func()` 动态命令调用、`print`、短 echo、`die/exit` 以及嵌套 sanitizer。

2026-06-22，PHP 生产入口进一步完全移除 regex 补充层。DVWA 剩余 4 个认证查询
SQLi 缺口已迁移到 AST 规则；迁移后 DVWA ground truth 保持 TP 22、FP 29、
FN 2、TN 3，Recall 91.7%、Precision 43.1%。全部真实目标 183 个 PHP 文件中，
AST-only 与迁移前生产 finding 集合一致。

SSRF 同日扩展到 PHP、Java、Go，与现有 Python、JavaScript 形成五语言统一覆盖。
PHP、Java、Go 均增加 LSP / 公共 API / 项目扫描一致性测试。反序列化新增
JavaScript `js-yaml.load` 正负样本，开放重定向新增 Django
`HttpResponseRedirect` 正负样本。

跨文件污点传播增加项目级回归：Python 与 JavaScript/TypeScript 的导入调用会复用
生产规则引擎生成参数 → Sink 摘要，并在调用端追踪用户输入参数。2026-06-22 进一步
增加返回值摘要、Python/ESM/CommonJS 重导出与固定点多跳包装函数传播。覆盖 ESM、
CommonJS 解构、默认导入/导出、`.mjs/.cjs`、安全常量、ProjectScanner、CLI 与 LSP。
这些多文件 fixture 不计入上述 207 个单文件规则样本，因此质量矩阵口径保持不变。
当前全量回归为 `737 passed, 1 xfailed, 50 deselected`，acceptance 为 `30 passed`。
当前传播边界是静态可解析的模块与函数调用；动态分派、反射和条件导出仍需真实项目
ground-truth 基准覆盖。

---

## 10. O10 可复跑真实项目基线（2026-07-10）

DVWA 当前复评命令（在 `aegis-ai-core` 下）：

```powershell
cd c:\Users\HT341\aegis-ai\aegis-ai-core
python scripts/benchmark/evaluate_project.py --project-dir real_world_targets/DVWA --ground-truth scripts/data/ground_truth_dvwa.json
```

结果会输出到：

- `reports/evaluate_DVWA_YYYY-MM-DD.md`
- `reports/evaluate_DVWA_YYYY-MM-DD.json`

每份报告的 `provenance` 都包含 scanner revision、target revision、ground-truth 路径与 SHA-256，
避免不同代码版本、靶场版本或标注版本的指标被混为同一口径。

Ground truth 中明确标记 `"in_scope": false` 的条目会在 `scope.excluded_entries` 和 Markdown 的
“Excluded entries”中保留原因，但默认不计入产品覆盖率；它们通常是未承诺的漏洞类别、
第三方依赖漏洞或与规则语义不一致的 CVE。使用 `--include-out-of-scope` 可复核全量原始口径，
不得通过删除或静默跳过条目改善指标。

当前基线：

| 目标 | TP | FP | FN | TN | Recall | Precision | F1 |
|------|----|----|----|----|--------|-----------|----|
| DVWA | 22 | 29 | 2 | 3 | 91.7% | 43.1% | 0.59 |

2026-07-10 本机复跑使用：

- Scanner revision：`c1676ee030e2577ec8dbf7322f2929636f3c7317`
- DVWA revision：`33e364c556e91473a5e979a4db16ee3b393d05ba`
- Ground-truth SHA-256：`4bcf55cf356042682670b7e988662a4451e82af12a8bf0f0f3a59146385a3202`

当前状态说明：

- 受控样本的 100% 指标仍仅用于防回归，不能替代 DVWA 等真实项目质量。
- DVWA 的当前误报主要在 SSRF、XSS、SQLi 与 Path Traversal；后续治理必须增加相应 TN 与真实项目 ground truth，避免仅通过删除规则“优化”指标。
- `scripts/reports/` 中的旧项目报告为历史资料；公开 README 仅展示带 provenance 的当前基线，其他目标须按同一流程重跑后才可重新发布指标。

---

## 11. 阶段收口快照（2026-04-23）

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

## 12. Round 6 真实项目基准扩展（2026-04-23）

新增了 Java/Go 的项目级 pilot benchmark 与对应 ground-truth：

- `scripts/data/ground_truth_java_deserialization_demo.json`
- `scripts/data/ground_truth_go_insecure_web_app.json`

同时恢复了 PHP 的 DVWA 项目级评估（目标目录已补齐）。

当日评估结果：

- PHP（DVWA）：Recall=87.5%，Precision=28.8%，F1=0.43
- Java（java-deserialization-demo pilot）：Recall=0.0%，Precision=0.0%，F1=0.00
- Go（go-insecure-web-app pilot）：Recall=0.0%，Precision=0.0%，F1=0.00

这组数据可作为后续 Java/Go 规则迭代的项目级基线。
