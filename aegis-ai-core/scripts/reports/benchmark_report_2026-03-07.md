# Aegis AI SAST 评估报告

**目标**: 自建基准  
**日期**: 2026-03-07  

---

## 检测率 (Recall)

| 漏洞类型 | 应检出 | 已检出 | Recall |
|----------|--------|--------|--------|
| HARDCODED_CREDENTIALS | 1 | 1 | 100% |
| NOSQL_INJECTION | 6 | 6 | 100% |
| PATH_TRAVERSAL | 1 | 0 | 0% |
| RCE_COMMAND_EXEC | 2 | 2 | 100% |
| SQL_INJECTION | 2 | 2 | 100% |
| XSS_RISK | 2 | 2 | 100% |
| **总计** | **14** | **13** | **92.9%** |

---

## 误报率 (FPR)

- 总发现数: 13
- 真阳性 (TP): 13
- 误报 (FP): 0
- 应阴性总数 (TN+FP): 10
- **误报率 (FPR)**: 0.0%

---

## 综合指标

- **Recall (检测率)**: 92.9%
- **Precision (精确率)**: 100.0%
- **F1 Score**: 0.96

---

## 明细 (TP/TN/FP/FN)

| ID | 类型 | 模式 | 预期 | 结果 | 判定 |
|----|------|------|------|------|------|
| TP-NOSQL-01 | NOSQL_INJECTION | direct_source | VULN | FOUND | TP |
| TP-NOSQL-02 | NOSQL_INJECTION | variable_propagation | VULN | FOUND | TP |
| TP-NOSQL-03 | NOSQL_INJECTION | destructuring | VULN | FOUND | TP |
| TP-NOSQL-04 | NOSQL_INJECTION | object_literal | VULN | FOUND | TP |
| TP-NOSQL-05 | NOSQL_INJECTION | dangerous_operator | VULN | FOUND | TP |
| TP-NOSQL-06 | NOSQL_INJECTION | dao_pattern | VULN | FOUND | TP |
| TP-SQL-01 | SQL_INJECTION | string_concat | VULN | FOUND | TP |
| TP-SQL-02 | SQL_INJECTION | template_literal | VULN | FOUND | TP |
| TP-XSS-01 | XSS_RISK | innerHTML | VULN | FOUND | TP |
| TP-XSS-02 | XSS_RISK | dangerouslySetInnerHTML | VULN | FOUND | TP |
| TP-RCE-01 | RCE_COMMAND_EXEC | eval | VULN | FOUND | TP |
| TP-RCE-02 | RCE_COMMAND_EXEC | child_process | VULN | FOUND | TP |
| TP-CRED-01 | HARDCODED_CREDENTIALS | literal | VULN | FOUND | TP |
| TP-PATH-01 | PATH_TRAVERSAL | fs_read | VULN | CLEAN | FN |
| TN-NOSQL-01 | NOSQL_INJECTION | array_find | SAFE | CLEAN | TN |
| TN-NOSQL-02 | NOSQL_INJECTION | variable_name | SAFE | CLEAN | TN |
| TN-XSS-01 | XSS_RISK | textContent | SAFE | CLEAN | TN |
| TN-RCE-01 | RCE_COMMAND_EXEC | regex_exec | SAFE | CLEAN | TN |
| TN-CRED-01 | HARDCODED_CREDENTIALS | env_var | SAFE | CLEAN | TN |
| TN-CRED-02 | HARDCODED_CREDENTIALS | error_var | SAFE | CLEAN | TN |
| TN-NOSQL-03 | NOSQL_INJECTION | sanitized | SAFE | CLEAN | TN |
| TN-SQL-01 | SQL_INJECTION | no_sql_keyword | SAFE | CLEAN | TN |
| TN-SQL-02 | SQL_INJECTION | parameterized | SAFE | CLEAN | TN |
| TN-PATH-01 | PATH_TRAVERSAL | static_path | SAFE | CLEAN | TN |
