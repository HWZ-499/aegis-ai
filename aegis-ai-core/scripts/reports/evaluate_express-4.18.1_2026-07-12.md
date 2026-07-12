# Aegis AI SAST 评估报告

**目标**: express-4.18.1  
**日期**: 2026-07-12  

---

## 检测率 (Recall)

| 漏洞类型 | 应检出 | 已检出 | Recall |
|----------|--------|--------|--------|
| HARDCODED_CREDENTIALS | 0 | 0 | N/A |
| OPEN_REDIRECT | 0 | 0 | N/A |
| XSS_RISK | 0 | 0 | N/A |
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

- 总发现数: 24
- 真阳性 (TP): 0
- 误报 (FP): 24
- 应阴性总数 (TN+FP): 24
- **误报率 (FPR)**: 100.0%

---

## 综合指标

- **Recall (检测率)**: 0.0%
- **Precision (精确率)**: 0.0%
- **F1 Score**: 0.00

---

## 明细 (TP/TN/FP/FN)

| # | 判定 | 漏洞类型 | 位置 | 规则 | 说明 |
|---:|------|----------|------|------|------|
| 1 | FP | HARDCODED_CREDENTIALS | examples\auth\index.js:25 | HARDCODED_CREDENTIALS_JS_AST | 发现对象字面量中疑似硬编码凭证属性 'secret'，建议使用环境变量或安全配置管理。 |
| 2 | FP | HARDCODED_CREDENTIALS | examples\cookie-sessions\index.js:13 | HARDCODED_CREDENTIALS_JS_AST | 发现对象字面量中疑似硬编码凭证属性 'secret'，建议使用环境变量或安全配置管理。 |
| 3 | FP | XSS_RISK | examples\cookie-sessions\index.js:21 | XSS_RISK_JS_AST | 检测到 response.send 等输出中拼接用户/会话输入未转义，可能存在反射 XSS 风险，建议对输出进行 HTML 转义。 |
| 4 | FP | HARDCODED_CREDENTIALS | examples\mvc\index.js:43 | HARDCODED_CREDENTIALS_JS_AST | 发现对象字面量中疑似硬编码凭证属性 'secret'，建议使用环境变量或安全配置管理。 |
| 5 | FP | OPEN_REDIRECT | examples\mvc\controllers\user-pet\index.js:21 | OPEN_REDIRECT_JS_TAINT | 检测到 JavaScript/TypeScript 代码中用户可控输入直接用于重定向目标（res.redirect/location 等），可能导致 Open Redirect 漏洞，建议使用域名白名单或固定路径映射。 |
| 6 | FP | HARDCODED_CREDENTIALS | examples\session\index.js:19 | HARDCODED_CREDENTIALS_JS_AST | 发现对象字面量中疑似硬编码凭证属性 'secret'，建议使用环境变量或安全配置管理。 |
| 7 | FP | XSS_RISK | examples\session\index.js:30 | XSS_RISK_JS_AST | 检测到 response.send 等输出中拼接用户/会话输入未转义，可能存在反射 XSS 风险，建议对输出进行 HTML 转义。 |
| 8 | FP | HARDCODED_CREDENTIALS | examples\session\redis.js:23 | HARDCODED_CREDENTIALS_JS_AST | 发现对象字面量中疑似硬编码凭证属性 'secret'，建议使用环境变量或安全配置管理。 |
| 9 | FP | XSS_RISK | examples\session\redis.js:35 | XSS_RISK_JS_AST | 检测到 response.send 等输出中拼接用户/会话输入未转义，可能存在反射 XSS 风险，建议对输出进行 HTML 转义。 |
| 10 | FP | XSS_RISK | test\app.param.js:29 | dsl.javascript.xss-response-send | 检测到将用户输入直接传给 res.send/res.write，存在 XSS 风险。 |
| 11 | FP | XSS_RISK | test\app.param.js:170 | dsl.javascript.xss-response-send | 检测到将用户输入直接传给 res.send/res.write，存在 XSS 风险。 |
| 12 | FP | XSS_RISK | test\app.param.js:191 | dsl.javascript.xss-response-send | 检测到将用户输入直接传给 res.send/res.write，存在 XSS 风险。 |
| 13 | FP | XSS_RISK | test\app.route.js:47 | dsl.javascript.xss-response-send | 检测到将用户输入直接传给 res.send/res.write，存在 XSS 风险。 |
| 14 | FP | XSS_RISK | test\app.router.js:20 | dsl.javascript.xss-response-send | 检测到将用户输入直接传给 res.send/res.write，存在 XSS 风险。 |
| 15 | FP | XSS_RISK | test\app.router.js:94 | dsl.javascript.xss-response-send | 检测到将用户输入直接传给 res.send/res.write，存在 XSS 风险。 |
| 16 | FP | XSS_RISK | test\app.router.js:106 | dsl.javascript.xss-response-send | 检测到将用户输入直接传给 res.send/res.write，存在 XSS 风险。 |
| 17 | FP | XSS_RISK | test\app.router.js:118 | dsl.javascript.xss-response-send | 检测到将用户输入直接传给 res.send/res.write，存在 XSS 风险。 |
| 18 | FP | XSS_RISK | test\app.router.js:130 | dsl.javascript.xss-response-send | 检测到将用户输入直接传给 res.send/res.write，存在 XSS 风险。 |
| 19 | FP | XSS_RISK | test\app.router.js:271 | dsl.javascript.xss-response-send | 检测到将用户输入直接传给 res.send/res.write，存在 XSS 风险。 |
| 20 | FP | XSS_RISK | test\app.router.js:643 | dsl.javascript.xss-response-send | 检测到将用户输入直接传给 res.send/res.write，存在 XSS 风险。 |
| 21 | FP | XSS_RISK | test\app.router.js:732 | dsl.javascript.xss-response-send | 检测到将用户输入直接传给 res.send/res.write，存在 XSS 风险。 |
| 22 | FP | XSS_RISK | test\app.router.js:744 | dsl.javascript.xss-response-send | 检测到将用户输入直接传给 res.send/res.write，存在 XSS 风险。 |
| 23 | FP | XSS_RISK | test\req.query.js:93 | dsl.javascript.xss-response-send | 检测到将用户输入直接传给 res.send/res.write，存在 XSS 风险。 |
| 24 | FP | XSS_RISK | test\req.query.js:119 | dsl.javascript.xss-response-send | 检测到将用户输入直接传给 res.send/res.write，存在 XSS 风险。 |

---

## Evaluation scope

- Ground-truth entries supplied: 2
- Entries evaluated: 0
- Explicitly out of scope: 1
- Invalid at this target revision: 1

### Excluded entries
- `PROTOTYPE_POLLUTION` in `lib/utils.js`: Aegis does not advertise prototype-pollution coverage, and this CVE is in the transitive qs dependency rather than Express source.

### Invalid entries
- `OPEN_REDIRECT` in `lib/router/index.js`: Expected pattern 'res.redirect' is absent within 3 lines of the annotated line.

---

## Performance

- Scan duration: `1.621 s`
- RSS before scan: `44.801 MiB`
- RSS after scan: `56.535 MiB`
- RSS delta: `11.734 MiB`
- Process peak RSS: `62.266 MiB`

Peak RSS is the lifetime peak of this standalone evaluator process.

---

## Reproducibility

- Clean release baseline: `yes`
- Engine: `new`
- Scanner revision: `d51bd8b946492fe1799f431b45c1da070a35cbc1`
- Scanner dirty: `no`
- Scanner diff SHA-256: `unavailable`
- Target revision: `d854c43ea177d1faeea56189249fff8c24a764bd`
- Target subdirectory: `.`
- Target dirty: `no`
- Target diff SHA-256: `unavailable`
- Ground truth: `scripts/data/ground_truth_express_4.18.1.json`
- Ground truth SHA-256: `33f8e3bfc83a0ea0b584f4fb3c48140e36c2c0d6937e736aaf2cc4561e3e5d74`
- Python: `3.11.0`
- Platform: `Windows-10-10.0.26200-SP0`
- Processor: `Intel64 Family 6 Model 183 Stepping 1, GenuineIntel`
