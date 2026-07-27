# Aegis AI SAST 评估报告

**目标**: body-parser-1.20.0  
**日期**: 2026-07-12  

---

## 检测率 (Recall)

| 漏洞类型 | 应检出 | 已检出 | Recall |
|----------|--------|--------|--------|
| **总计** | **0** | **0** | **0.0%** |

---

## 按语言质量矩阵

| 语言 | TP | TN | FP | FN | Recall | Precision | FPR | F1 |
|------|---:|---:|---:|---:|-------:|----------:|----:|---:|

### 语言 × 漏洞类型

| 语言 | 漏洞类型 | TP | TN | FP | FN | Recall | Precision |
|------|----------|---:|---:|---:|---:|-------:|----------:|

---

## 误报率 (FPR)

- 总发现数: 0
- 真阳性 (TP): 0
- 误报 (FP): 0
- 应阴性总数 (TN+FP): 0
- **误报率 (FPR)**: 0.0%

---

## 综合指标

- **Recall (检测率)**: 0.0%
- **Precision (精确率)**: 0.0%
- **F1 Score**: 0.00

---

## 明细 (TP/TN/FP/FN)

| ID | 类型 | 模式 | 预期 | 结果 | 判定 |
|----|------|------|------|------|------|

---

## Evaluation scope

- Ground-truth entries supplied: 2
- Entries evaluated: 0
- Explicitly out of scope: 2
- Invalid at this target revision: 0

### Excluded entries
- `DOS_RISK` in `lib/types/json.js`: CVE-2022-24434 affects dicer, which is neither body-parser source nor a dependency of body-parser 1.20.0; this target cannot provide a source-level TP for it.
- `PATH_TRAVERSAL` in `lib/read.js`: CVE-2014-6394 affects send before 0.8.4, not body-parser; body-parser 1.20.0 source cannot serve as its TP fixture.

---

## Performance

- Scan duration: `0.341 s`
- RSS before scan: `44.691 MiB`
- RSS after scan: `54.379 MiB`
- RSS delta: `9.688 MiB`
- Process peak RSS: `57.941 MiB`

Peak RSS is the lifetime peak of this standalone evaluator process.

---

## Reproducibility

- Clean release baseline: `yes`
- Engine: `new`
- Scanner revision: `d51bd8b946492fe1799f431b45c1da070a35cbc1`
- Scanner dirty: `no`
- Scanner diff SHA-256: `unavailable`
- Target revision: `1f6f58e1f8dc222f2b6cfc7eb3a3bf5145ff2b56`
- Target subdirectory: `.`
- Target dirty: `no`
- Target diff SHA-256: `unavailable`
- Ground truth: `scripts/data/ground_truth_body_parser_1.20.0.json`
- Ground truth SHA-256: `e9be9cff99a7ec83c429eebd9fdc80b100b6966f43656edf65bea76fb153fc55`
- Python: `3.11.0`
- Platform: `Windows-10-10.0.26200-SP0`
- Processor: `Intel64 Family 6 Model 183 Stepping 1, GenuineIntel`
