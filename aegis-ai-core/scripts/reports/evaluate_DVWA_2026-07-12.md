# Aegis AI SAST 评估报告

**目标**: DVWA  
**日期**: 2026-07-12  

---

## 检测率 (Recall)

| 漏洞类型 | 应检出 | 已检出 | Recall |
|----------|--------|--------|--------|
| OPEN_REDIRECT | 3 | 3 | 100% |
| PATH_TRAVERSAL | 0 | 0 | N/A |
| RCE_COMMAND_EXEC | 4 | 4 | 100% |
| SQL_INJECTION | 13 | 13 | 100% |
| SSRF | 0 | 0 | N/A |
| XSS_RISK | 3 | 3 | 100% |
| **总计** | **23** | **23** | **100.0%** |

---

## 按语言质量矩阵

| 语言 | TP | TN | FP | FN | Recall | Precision | FPR | F1 |
|------|---:|---:|---:|---:|-------:|----------:|----:|---:|

### 语言 × 漏洞类型

| 语言 | 漏洞类型 | TP | TN | FP | FN | Recall | Precision |
|------|----------|---:|---:|---:|---:|-------:|----------:|

---

## 误报率 (FPR)

- 总发现数: 52
- 真阳性 (TP): 23
- 误报 (FP): 29
- 应阴性总数 (TN+FP): 33
- **误报率 (FPR)**: 87.9%

---

## 综合指标

- **Recall (检测率)**: 100.0%
- **Precision (精确率)**: 44.2%
- **F1 Score**: 0.61

---

## 明细 (TP/TN/FP/FN)

| # | 判定 | 漏洞类型 | 位置 | 规则 | 说明 |
|---:|------|----------|------|------|------|
| 1 | TP | SQL_INJECTION | login.php:40 | SQL_INJECTION_PHP_AST | PHP: mysqli_query() 使用变量 $query 执行 SQL，且其中 $pass 仅经过弱转义。请改用 prepare/bind 参数化查询。 |
| 2 | TP | SQL_INJECTION | vulnerabilities\brute\source\low.php:13 | SQL_INJECTION_PHP_AST | PHP: mysqli_query() 的参数包含用户输入，存在 SQL 注入风险。建议使用 prepare/bind_param 参数化查询。 |
| 3 | TP | SQL_INJECTION | vulnerabilities\brute\source\medium.php:15 | SQL_INJECTION_PHP_AST | PHP: mysqli_query() 使用变量 $query 执行 SQL，且其中 $pass 仅经过弱转义。请改用 prepare/bind 参数化查询。 |
| 4 | TP | SQL_INJECTION | vulnerabilities\brute\source\high.php:20 | SQL_INJECTION_PHP_AST | PHP: mysqli_query() 使用变量 $query 执行 SQL，且其中 $pass 仅经过弱转义。请改用 prepare/bind 参数化查询。 |
| 5 | TP | SQL_INJECTION | vulnerabilities\sqli\source\low.php:11 | SQL_INJECTION_PHP_AST | PHP: mysqli_query() 的参数包含用户输入，存在 SQL 注入风险。建议使用 prepare/bind_param 参数化查询。 |
| 6 | TP | SQL_INJECTION | vulnerabilities\sqli\source\low.php:34 | SQL_INJECTION_PHP_AST | PHP: $obj->query() 的参数包含用户输入，存在 SQL 注入风险。建议使用 prepare/bind_param 参数化查询。 |
| 7 | TP | SQL_INJECTION | vulnerabilities\sqli\source\medium.php:30 | SQL_INJECTION_PHP_AST | PHP: $obj->query() 使用变量 $query 执行 SQL，且其中 $id 仅经过弱转义。请改用 prepare/bind 参数化查询。 |
| 8 | TP | SQL_INJECTION | vulnerabilities\sqli\source\high.php:31 | SQL_INJECTION_PHP_AST | PHP: $obj->query() 的参数包含用户输入，存在 SQL 注入风险。建议使用 prepare/bind_param 参数化查询。 |
| 9 | TP | SQL_INJECTION | vulnerabilities\sqli_blind\source\low.php:13 | SQL_INJECTION_PHP_AST | PHP: mysqli_query() 的参数包含用户输入，存在 SQL 注入风险。建议使用 prepare/bind_param 参数化查询。 |
| 10 | TP | SQL_INJECTION | vulnerabilities\sqli_blind\source\medium.php:36 | SQL_INJECTION_PHP_AST | PHP: $obj->query() 使用变量 $query 执行 SQL，且其中 $id 仅经过弱转义。请改用 prepare/bind 参数化查询。 |
| 11 | TP | SQL_INJECTION | vulnerabilities\sqli_blind\source\high.php:35 | SQL_INJECTION_PHP_AST | PHP: $obj->query() 的参数包含用户输入，存在 SQL 注入风险。建议使用 prepare/bind_param 参数化查询。 |
| 12 | TP | RCE_COMMAND_EXEC | vulnerabilities\exec\source\low.php:10 | RCE_PHP_AST | PHP: shell_exec() 参数来自用户输入，存在远程代码/命令执行风险。 |
| 13 | TP | RCE_COMMAND_EXEC | vulnerabilities\exec\source\medium.php:19 | RCE_PHP_AST | PHP: shell_exec() 参数来自用户输入，存在远程代码/命令执行风险。 |
| 14 | TP | RCE_COMMAND_EXEC | vulnerabilities\exec\source\high.php:26 | RCE_PHP_AST | PHP: shell_exec() 参数来自用户输入，存在远程代码/命令执行风险。 |
| 15 | TP | RCE_COMMAND_EXEC | vulnerabilities\api\src\HealthController.php:88 | RCE_PHP_AST | PHP: exec() 参数来自用户输入，存在远程代码/命令执行风险。 |
| 16 | TP | XSS_RISK | vulnerabilities\xss_r\source\low.php:8 | XSS_PHP_AST | PHP: $html 拼接 HTML 片段时包含未转义用户输入，可能在后续输出阶段触发 XSS。 |
| 17 | TP | XSS_RISK | vulnerabilities\xss_d\index.php:53 | XSS_PHP_AST | PHP 模板中的 document.write 输出 URL 派生值且未经 HTML 净化，可能存在 DOM XSS 风险。 |
| 18 | TP | XSS_RISK | vulnerabilities\sqli\source\low.php:20 | XSS_PHP_AST | PHP: $html 拼接 HTML 片段时包含未转义用户输入，可能在后续输出阶段触发 XSS。 |
| 19 | TP | OPEN_REDIRECT | vulnerabilities\open_redirect\source\low.php:4 | OPEN_REDIRECT_PHP_AST | PHP: header('Location: ...') 的重定向目标包含用户输入，存在开放重定向风险。 |
| 20 | TP | OPEN_REDIRECT | vulnerabilities\open_redirect\source\medium.php:11 | OPEN_REDIRECT_PHP_AST | PHP: header('Location: ...') 的重定向目标包含用户输入，存在开放重定向风险。 |
| 21 | TP | OPEN_REDIRECT | vulnerabilities\open_redirect\source\high.php:5 | OPEN_REDIRECT_PHP_AST | PHP: header('Location: ...') 的重定向目标包含用户输入，存在开放重定向风险。 |
| 22 | TP | SQL_INJECTION | vulnerabilities\authbypass\change_user_details.php:48 | SQL_INJECTION_PHP_AST | PHP: mysqli_query() 的参数包含用户输入，存在 SQL 注入风险。建议使用 prepare/bind_param 参数化查询。 |
| 23 | TP | SQL_INJECTION | vulnerabilities\csrf\test_credentials.php:22 | SQL_INJECTION_PHP_AST | PHP: mysqli_query() 使用变量 $query 执行 SQL，且其中 $pass 仅经过弱转义。请改用 prepare/bind 参数化查询。 |
| 24 | TN | RCE_COMMAND_EXEC | vulnerabilities/exec/source/impossible.php:22 |  |  |
| 25 | TN | RCE_COMMAND_EXEC | vulnerabilities/api/index.php:33 |  |  |
| 26 | TN | RCE_COMMAND_EXEC | setup.php:51 |  |  |
| 27 | TN | SQL_INJECTION | vulnerabilities/bac/source/medium.php:22 |  |  |
| 28 | FP | RCE_COMMAND_EXEC | vulnerabilities\view_help.php:20 | RCE_PHP_AST | PHP: eval() 参数来自用户输入，存在远程代码/命令执行风险。 |
| 29 | FP | PATH_TRAVERSAL | vulnerabilities\view_help.php:20 | PATH_TRAVERSAL_PHP_AST | PHP: file_get_contents() 的路径参数包含用户输入，存在路径遍历风险。 |
| 30 | FP | SSRF | vulnerabilities\view_help.php:20 | SSRF_PHP_AST | PHP: file_get_contents() 的请求目标包含用户输入，可能导致 SSRF（CWE-918）。建议限制 URL 协议和域名，并阻止访问环回、内网和云元数据地址。 |
| 31 | FP | RCE_COMMAND_EXEC | vulnerabilities\view_help.php:22 | RCE_PHP_AST | PHP: eval() 参数来自用户输入，存在远程代码/命令执行风险。 |
| 32 | FP | SSRF | vulnerabilities\view_help.php:22 | SSRF_PHP_AST | PHP: file_get_contents() 的请求目标包含用户输入，可能导致 SSRF（CWE-918）。建议限制 URL 协议和域名，并阻止访问环回、内网和云元数据地址。 |
| 33 | FP | PATH_TRAVERSAL | vulnerabilities\view_source.php:63 | PATH_TRAVERSAL_PHP_AST | PHP: file_get_contents() 的路径参数包含用户输入，存在路径遍历风险。 |
| 34 | FP | SSRF | vulnerabilities\view_source.php:63 | SSRF_PHP_AST | PHP: file_get_contents() 的请求目标包含用户输入，可能导致 SSRF（CWE-918）。建议限制 URL 协议和域名，并阻止访问环回、内网和云元数据地址。 |
| 35 | FP | PATH_TRAVERSAL | vulnerabilities\view_source.php:68 | PATH_TRAVERSAL_PHP_AST | PHP: file_get_contents() 的路径参数包含用户输入，存在路径遍历风险。 |
| 36 | FP | SSRF | vulnerabilities\view_source.php:68 | SSRF_PHP_AST | PHP: file_get_contents() 的请求目标包含用户输入，可能导致 SSRF（CWE-918）。建议限制 URL 协议和域名，并阻止访问环回、内网和云元数据地址。 |
| 37 | FP | PATH_TRAVERSAL | vulnerabilities\view_source_all.php:14 | PATH_TRAVERSAL_PHP_AST | PHP: file_get_contents() 的路径参数包含用户输入，存在路径遍历风险。 |
| 38 | FP | SSRF | vulnerabilities\view_source_all.php:14 | SSRF_PHP_AST | PHP: file_get_contents() 的请求目标包含用户输入，可能导致 SSRF（CWE-918）。建议限制 URL 协议和域名，并阻止访问环回、内网和云元数据地址。 |
| 39 | FP | SSRF | vulnerabilities\view_source_all.php:18 | SSRF_PHP_AST | PHP: file_get_contents() 的请求目标包含用户输入，可能导致 SSRF（CWE-918）。建议限制 URL 协议和域名，并阻止访问环回、内网和云元数据地址。 |
| 40 | FP | PATH_TRAVERSAL | vulnerabilities\view_source_all.php:22 | PATH_TRAVERSAL_PHP_AST | PHP: file_get_contents() 的路径参数包含用户输入，存在路径遍历风险。 |
| 41 | FP | SSRF | vulnerabilities\view_source_all.php:22 | SSRF_PHP_AST | PHP: file_get_contents() 的请求目标包含用户输入，可能导致 SSRF（CWE-918）。建议限制 URL 协议和域名，并阻止访问环回、内网和云元数据地址。 |
| 42 | FP | SSRF | vulnerabilities\view_source_all.php:26 | SSRF_PHP_AST | PHP: file_get_contents() 的请求目标包含用户输入，可能导致 SSRF（CWE-918）。建议限制 URL 协议和域名，并阻止访问环回、内网和云元数据地址。 |
| 43 | FP | XSS_RISK | vulnerabilities\api\help\help.php:39 | XSS_PHP_AST | PHP: short echo 输出包含用户输入且未经 HTML 转义，存在 XSS 风险。 |
| 44 | FP | XSS_RISK | vulnerabilities\authbypass\authbypass.js:43 | XSS_RISK_JS_AST | 检测到 innerHTML 赋值操作，右值包含动态内容且未经 HTML 净化，可能存在 XSS 风险。 |
| 45 | FP | XSS_RISK | vulnerabilities\csp\source\jsonp.php:12 | XSS_PHP_AST | PHP: echo 输出包含用户输入且未经 HTML 转义，存在 XSS 风险。 |
| 46 | FP | RCE_COMMAND_EXEC | vulnerabilities\exec\source\high.php:30 | RCE_PHP_AST | PHP: shell_exec() 参数来自用户输入，存在远程代码/命令执行风险。 |
| 47 | FP | RCE_COMMAND_EXEC | vulnerabilities\exec\source\low.php:14 | RCE_PHP_AST | PHP: shell_exec() 参数来自用户输入，存在远程代码/命令执行风险。 |
| 48 | FP | RCE_COMMAND_EXEC | vulnerabilities\exec\source\medium.php:23 | RCE_PHP_AST | PHP: shell_exec() 参数来自用户输入，存在远程代码/命令执行风险。 |
| 49 | FP | SQL_INJECTION | vulnerabilities\sqli\source\high.php:11 | SQL_INJECTION_PHP_AST | PHP: mysqli_query() 的参数包含用户输入，存在 SQL 注入风险。建议使用 prepare/bind_param 参数化查询。 |
| 50 | FP | XSS_RISK | vulnerabilities\sqli\source\low.php:47 | XSS_PHP_AST | PHP: $html 拼接 HTML 片段时包含未转义用户输入，可能在后续输出阶段触发 XSS。 |
| 51 | FP | SQL_INJECTION | vulnerabilities\sqli\source\medium.php:12 | SQL_INJECTION_PHP_AST | PHP: mysqli_query() 使用变量 $query 执行 SQL，且其中 $id 仅经过弱转义。请改用 prepare/bind 参数化查询。 |
| 52 | FP | SQL_INJECTION | vulnerabilities\sqli_blind\source\high.php:13 | SQL_INJECTION_PHP_AST | PHP: mysqli_query() 的参数包含用户输入，存在 SQL 注入风险。建议使用 prepare/bind_param 参数化查询。 |
| 53 | FP | SQL_INJECTION | vulnerabilities\sqli_blind\source\low.php:34 | SQL_INJECTION_PHP_AST | PHP: $obj->query() 的参数包含用户输入，存在 SQL 注入风险。建议使用 prepare/bind_param 参数化查询。 |
| 54 | FP | SQL_INJECTION | vulnerabilities\sqli_blind\source\medium.php:15 | SQL_INJECTION_PHP_AST | PHP: mysqli_query() 使用变量 $query 执行 SQL，且其中 $id 仅经过弱转义。请改用 prepare/bind 参数化查询。 |
| 55 | FP | XSS_RISK | vulnerabilities\xss_r\source\high.php:11 | XSS_PHP_AST | PHP: $html 拼接 HTML 片段时包含未转义用户输入，可能在后续输出阶段触发 XSS。 |
| 56 | FP | XSS_RISK | vulnerabilities\xss_r\source\medium.php:11 | XSS_PHP_AST | PHP: $html 拼接 HTML 片段时包含未转义用户输入，可能在后续输出阶段触发 XSS。 |

---

## Evaluation scope

- Ground-truth entries supplied: 27
- Entries evaluated: 27
- Explicitly out of scope: 0
- Invalid at this target revision: 0

---

## Performance

- Scan duration: `2.566 s`
- RSS before scan: `47.125 MiB`
- RSS after scan: `54.340 MiB`
- RSS delta: `7.215 MiB`
- Process peak RSS: `58.508 MiB`

Peak RSS is the lifetime peak of this standalone evaluator process.

---

## Reproducibility

- Clean release baseline: `yes`
- Engine: `new`
- Scanner revision: `d51bd8b946492fe1799f431b45c1da070a35cbc1`
- Scanner dirty: `no`
- Scanner diff SHA-256: `unavailable`
- Target revision: `33e364c556e91473a5e979a4db16ee3b393d05ba`
- Target subdirectory: `.`
- Target dirty: `no`
- Target diff SHA-256: `unavailable`
- Ground truth: `scripts/data/ground_truth_dvwa.json`
- Ground truth SHA-256: `ca7b1f6eac6481a18d7e5011670a133e6ccb68fefd446b420af2baee2a0e28cb`
- Python: `3.11.0`
- Platform: `Windows-10-10.0.26200-SP0`
- Processor: `Intel64 Family 6 Model 183 Stepping 1, GenuineIntel`
