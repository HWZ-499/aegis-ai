# Aegis AI SAST 评估报告

**目标**: django-3.2  
**日期**: 2026-04-25  

---

## 检测率 (Recall)

| 漏洞类型 | 应检出 | 已检出 | Recall |
|----------|--------|--------|--------|
| DESERIALIZATION | 0 | 0 | N/A |
| HARDCODED_CREDENTIALS | 0 | 0 | N/A |
| NOSQL_INJECTION | 0 | 0 | N/A |
| OPEN_REDIRECT | 0 | 0 | N/A |
| PATH_TRAVERSAL | 1 | 0 | 0% |
| RCE_COMMAND_EXEC | 0 | 0 | N/A |
| SQL_INJECTION | 0 | 0 | N/A |
| XSS_RISK | 0 | 0 | N/A |
| **总计** | **1** | **0** | **0.0%** |

---

## 误报率 (FPR)

- 总发现数: 129
- 真阳性 (TP): 0
- 误报 (FP): 129
- 应阴性总数 (TN+FP): 138
- **误报率 (FPR)**: 93.5%

---

## 综合指标

- **Recall (检测率)**: 0.0%
- **Precision (精确率)**: 0.0%
- **F1 Score**: 0.00

---

## 明细 (TP/TN/FP/FN)

| ID | 类型 | 模式 | 预期 | 结果 | 判定 |
|----|------|------|------|------|------|
