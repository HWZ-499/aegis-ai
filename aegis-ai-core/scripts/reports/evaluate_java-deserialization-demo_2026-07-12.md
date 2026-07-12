# Aegis AI SAST 评估报告

**目标**: java-deserialization-demo  
**日期**: 2026-07-12  

---

## 检测率 (Recall)

| 漏洞类型 | 应检出 | 已检出 | Recall |
|----------|--------|--------|--------|
| DESERIALIZATION | 1 | 1 | 100% |
| **总计** | **1** | **1** | **100.0%** |

---

## 按语言质量矩阵

| 语言 | TP | TN | FP | FN | Recall | Precision | FPR | F1 |
|------|---:|---:|---:|---:|-------:|----------:|----:|---:|

### 语言 × 漏洞类型

| 语言 | 漏洞类型 | TP | TN | FP | FN | Recall | Precision |
|------|----------|---:|---:|---:|---:|-------:|----------:|

---

## 误报率 (FPR)

- 总发现数: 1
- 真阳性 (TP): 1
- 误报 (FP): 0
- 应阴性总数 (TN+FP): 1
- **误报率 (FPR)**: 0.0%

---

## 综合指标

- **Recall (检测率)**: 100.0%
- **Precision (精确率)**: 100.0%
- **F1 Score**: 1.00

---

## 明细 (TP/TN/FP/FN)

| # | 判定 | 漏洞类型 | 位置 | 规则 | 说明 |
|---:|------|----------|------|------|------|
| 1 | TP | DESERIALIZATION | src\com\example\vulnerable\VulnerableServer.java:20 | DESERIALIZATION_JAVA_TAINT | 检测到 readObject() 调用中存在不安全的反序列化操作，可能导致任意代码执行，建议改用安全数据格式或加入类型白名单校验。 |
| 2 | TN | DESERIALIZATION | src/com/example/secure/SecureServer.java:50 |  |  |

---

## Evaluation scope

- Ground-truth entries supplied: 2
- Entries evaluated: 2
- Explicitly out of scope: 0
- Invalid at this target revision: 0

---

## Performance

- Scan duration: `0.067 s`
- RSS before scan: `44.660 MiB`
- RSS after scan: `48.602 MiB`
- RSS delta: `3.941 MiB`
- Process peak RSS: `48.797 MiB`

Peak RSS is the lifetime peak of this standalone evaluator process.

---

## Reproducibility

- Clean release baseline: `yes`
- Engine: `new`
- Scanner revision: `d51bd8b946492fe1799f431b45c1da070a35cbc1`
- Scanner dirty: `no`
- Scanner diff SHA-256: `unavailable`
- Target revision: `8bffd34ecb1d5d7a83a9b56c49f578cd4407457c`
- Target subdirectory: `java-deserialization-demo`
- Target dirty: `no`
- Target diff SHA-256: `unavailable`
- Ground truth: `scripts/data/ground_truth_java_deserialization_demo.json`
- Ground truth SHA-256: `28863ae2bcc9874730ddc47cdf7909b17d9634683b334e69ec56056bff1f9c42`
- Python: `3.11.0`
- Platform: `Windows-10-10.0.26200-SP0`
- Processor: `Intel64 Family 6 Model 183 Stepping 1, GenuineIntel`
