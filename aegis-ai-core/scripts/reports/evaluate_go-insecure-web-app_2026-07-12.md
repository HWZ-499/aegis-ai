# Aegis AI SAST 评估报告

**目标**: go-insecure-web-app  
**日期**: 2026-07-12  

---

## 检测率 (Recall)

| 漏洞类型 | 应检出 | 已检出 | Recall |
|----------|--------|--------|--------|
| PATH_TRAVERSAL | 1 | 1 | 100% |
| RCE_COMMAND_EXEC | 1 | 1 | 100% |
| SQL_INJECTION | 0 | 0 | N/A |
| XSS_RISK | 1 | 1 | 100% |
| **总计** | **3** | **3** | **100.0%** |

---

## 按语言质量矩阵

| 语言 | TP | TN | FP | FN | Recall | Precision | FPR | F1 |
|------|---:|---:|---:|---:|-------:|----------:|----:|---:|

### 语言 × 漏洞类型

| 语言 | 漏洞类型 | TP | TN | FP | FN | Recall | Precision |
|------|----------|---:|---:|---:|---:|-------:|----------:|

---

## 误报率 (FPR)

- 总发现数: 3
- 真阳性 (TP): 3
- 误报 (FP): 0
- 应阴性总数 (TN+FP): 2
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
| 1 | TP | XSS_RISK | main.go:100 | XSS_RISK_GO_TAINT | 检测到 fmt.Sprintf() 调用中包含用户可控输入直接写入响应，且未检测到 HTML 转义，存在 XSS 风险，建议使用 template.HTMLEscapeString 转义。 |
| 2 | TP | PATH_TRAVERSAL | main.go:239 | PATH_TRAVERSAL_GO_TAINT | 检测到 ioutil.ReadFile() 调用中包含用户可控输入，仅做 filepath.Clean/path.Clean 等路径清理不能证明路径仍在允许目录内，建议解析后校验目录白名单。 |
| 3 | TP | RCE_COMMAND_EXEC | main.go:270 | RCE_COMMAND_EXEC_GO_TAINT | 检测到 exec.Command() 调用中包含用户可控输入，存在命令注入风险，建议使用固定命令白名单或严格校验参数。 |
| 4 | TN | SQL_INJECTION | main.go:166 |  |  |
| 5 | TN | SQL_INJECTION | main.go:222 |  |  |

---

## Evaluation scope

- Ground-truth entries supplied: 5
- Entries evaluated: 5
- Explicitly out of scope: 0
- Invalid at this target revision: 0

---

## Performance

- Scan duration: `0.066 s`
- RSS before scan: `44.742 MiB`
- RSS after scan: `49.230 MiB`
- RSS delta: `4.488 MiB`
- Process peak RSS: `49.309 MiB`

Peak RSS is the lifetime peak of this standalone evaluator process.

---

## Reproducibility

- Clean release baseline: `yes`
- Engine: `new`
- Scanner revision: `d51bd8b946492fe1799f431b45c1da070a35cbc1`
- Scanner dirty: `no`
- Scanner diff SHA-256: `unavailable`
- Target revision: `6209c83a6f5a170d516b79eef2b46fa2fe6cd015`
- Target subdirectory: `.`
- Target dirty: `no`
- Target diff SHA-256: `unavailable`
- Ground truth: `scripts/data/ground_truth_go_insecure_web_app.json`
- Ground truth SHA-256: `bd5347a5d1995e6ab890cfc5c77bc17212e09b3a588739a39261232ded39d13e`
- Python: `3.11.0`
- Platform: `Windows-10-10.0.26200-SP0`
- Processor: `Intel64 Family 6 Model 183 Stepping 1, GenuineIntel`
