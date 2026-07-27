# Aegis AI SAST 评估报告

**目标**: NodeGoat  
**日期**: 2026-07-12  

---

## 检测率 (Recall)

| 漏洞类型 | 应检出 | 已检出 | Recall |
|----------|--------|--------|--------|
| HARDCODED_CREDENTIALS | 2 | 2 | 100% |
| NOSQL_INJECTION | 5 | 5 | 100% |
| OPEN_REDIRECT | 1 | 1 | 100% |
| RCE_COMMAND_EXEC | 3 | 3 | 100% |
| XSS_RISK | 1 | 1 | 100% |
| **总计** | **12** | **12** | **100.0%** |

---

## 按语言质量矩阵

| 语言 | TP | TN | FP | FN | Recall | Precision | FPR | F1 |
|------|---:|---:|---:|---:|-------:|----------:|----:|---:|

### 语言 × 漏洞类型

| 语言 | 漏洞类型 | TP | TN | FP | FN | Recall | Precision |
|------|----------|---:|---:|---:|---:|-------:|----------:|

---

## 误报率 (FPR)

- 总发现数: 14
- 真阳性 (TP): 12
- 误报 (FP): 2
- 应阴性总数 (TN+FP): 2
- **误报率 (FPR)**: 100.0%

---

## 综合指标

- **Recall (检测率)**: 100.0%
- **Precision (精确率)**: 85.7%
- **F1 Score**: 0.92

---

## 明细 (TP/TN/FP/FN)

| # | 判定 | 漏洞类型 | 位置 | 规则 | 说明 |
|---:|------|----------|------|------|------|
| 1 | TP | NOSQL_INJECTION | app\data\user-dao.js:91 | NOSQL_INJECTION_JS_AST | 检测到 usersCol.findOne() 调用，参数是对象字面量且包含标识符（可能是用户输入），存在潜在的 NoSQL 注入风险。建议使用参数化查询。 |
| 2 | TP | NOSQL_INJECTION | app\data\user-dao.js:45 | NOSQL_INJECTION_JS_AST | 检测到 usersCol.insert() 调用，参数是变量 'user'，在 DAO 层 insert 操作中存在 NoSQL 注入风险（DAO 函数参数视为外部输入）。建议净化后再插入。 |
| 3 | TP | NOSQL_INJECTION | app\data\user-dao.js:104 | NOSQL_INJECTION_JS_AST | 检测到 usersCol.findOne() 调用，参数是对象字面量且包含标识符（可能是用户输入），存在潜在的 NoSQL 注入风险。建议使用参数化查询。 |
| 4 | TP | RCE_COMMAND_EXEC | app\routes\contributions.js:32 | RCE_COMMAND_EXEC_JS_AST | JavaScript AST: eval() 参数来自用户输入，存在代码注入风险。 |
| 5 | TP | RCE_COMMAND_EXEC | app\routes\contributions.js:33 | RCE_COMMAND_EXEC_JS_AST | JavaScript AST: eval() 参数来自用户输入，存在代码注入风险。 |
| 6 | TP | RCE_COMMAND_EXEC | app\routes\contributions.js:34 | RCE_COMMAND_EXEC_JS_AST | JavaScript AST: eval() 参数来自用户输入，存在代码注入风险。 |
| 7 | TP | NOSQL_INJECTION | app\data\memos-dao.js:23 | NOSQL_INJECTION_JS_AST | 检测到 memosCol.insert() 调用，参数是变量 'memos'，在 DAO 层 insert 操作中存在 NoSQL 注入风险（DAO 函数参数视为外部输入）。建议净化后再插入。 |
| 8 | TP | NOSQL_INJECTION | app\data\benefits-dao.js:24 | NOSQL_INJECTION_JS_AST | 检测到 usersCol.update() 调用，更新文档（第二个参数）中 $set/$push 等操作符的值来自用户输入或污染变量，存在 NoSQL 注入风险。 |
| 9 | TP | HARDCODED_CREDENTIALS | config\env\development.js:6 | HARDCODED_CREDENTIALS_JS_AST | 发现对象字面量中疑似硬编码凭证属性 'zapApiKey'，建议使用环境变量或安全配置管理。 |
| 10 | TP | HARDCODED_CREDENTIALS | config\env\test.js:6 | HARDCODED_CREDENTIALS_JS_AST | 发现对象字面量中疑似硬编码凭证属性 'zapApiKey'，建议使用环境变量或安全配置管理。 |
| 11 | TP | OPEN_REDIRECT | app\routes\index.js:72 | OPEN_REDIRECT_JS_TAINT | 检测到 JavaScript/TypeScript 代码中用户可控输入直接用于重定向目标（res.redirect/location 等），可能导致 Open Redirect 漏洞，建议使用域名白名单或固定路径映射。 |
| 12 | TP | XSS_RISK | app\routes\research.js:25 | XSS_RISK_JS_AST | 检测到 Node.js HTTP 客户端回调中的响应体直接写入 HTML 响应，未经 HTML 净化可能导致 XSS 风险。 |
| 13 | FP | NOSQL_INJECTION | app\data\contributions-dao.js:57 | NOSQL_INJECTION_JS_AST | 检测到 contributionsDB.findOne() 调用，参数是对象字面量且包含标识符（可能是用户输入），存在潜在的 NoSQL 注入风险。建议使用参数化查询。 |
| 14 | FP | HARDCODED_CREDENTIALS | test\security\profile-test.js:37 | HARDCODED_CREDENTIALS_JS_AST | 发现疑似硬编码凭证变量 'sutUserPassword'，建议使用环境变量或安全配置管理。 |

---

## Evaluation scope

- Ground-truth entries supplied: 12
- Entries evaluated: 12
- Explicitly out of scope: 0
- Invalid at this target revision: 0

---

## Performance

- Scan duration: `0.232 s`
- RSS before scan: `44.883 MiB`
- RSS after scan: `51.289 MiB`
- RSS delta: `6.406 MiB`
- Process peak RSS: `53.020 MiB`

Peak RSS is the lifetime peak of this standalone evaluator process.

---

## Reproducibility

- Clean release baseline: `yes`
- Engine: `new`
- Scanner revision: `d51bd8b946492fe1799f431b45c1da070a35cbc1`
- Scanner dirty: `no`
- Scanner diff SHA-256: `unavailable`
- Target revision: `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`
- Target subdirectory: `.`
- Target dirty: `no`
- Target diff SHA-256: `unavailable`
- Ground truth: `scripts/data/ground_truth_nodegoat.json`
- Ground truth SHA-256: `dd5a525953802218f83b632cf933b3759d6ebaaa7c7015e5973d894c9538e0a4`
- Python: `3.11.0`
- Platform: `Windows-10-10.0.26200-SP0`
- Processor: `Intel64 Family 6 Model 183 Stepping 1, GenuineIntel`
