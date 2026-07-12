# Aegis AI SAST 评估报告

**目标**: django-3.2  
**日期**: 2026-07-12  

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

## 按语言质量矩阵

| 语言 | TP | TN | FP | FN | Recall | Precision | FPR | F1 |
|------|---:|---:|---:|---:|-------:|----------:|----:|---:|

### 语言 × 漏洞类型

| 语言 | 漏洞类型 | TP | TN | FP | FN | Recall | Precision |
|------|----------|---:|---:|---:|---:|-------:|----------:|

---

## 误报率 (FPR)

- 总发现数: 136
- 真阳性 (TP): 0
- 误报 (FP): 136
- 应阴性总数 (TN+FP): 143
- **误报率 (FPR)**: 95.1%

---

## 综合指标

- **Recall (检测率)**: 0.0%
- **Precision (精确率)**: 0.0%
- **F1 Score**: 0.00

---

## 明细 (TP/TN/FP/FN)

| # | 判定 | 漏洞类型 | 位置 | 规则 | 说明 |
|---:|------|----------|------|------|------|
| 1 | FN | PATH_TRAVERSAL | files/storage.py:76 |  | CVE-2021-31542: Django 3.2 的 MultiPartParser、UploadedFile 与 FieldFile 对恶意上传文件名的路径清理不足；官方定级 Low，并在 3.2.1 修复。该条定位到 3.2 storage.py 中后续补入路径校验的入口。 |
| 2 | FP | SQL_INJECTION | django\core\cache\backends\db.py:120 | dsl.python.sql-injection-format | 检测到使用字符串格式化构造 SQL 语句，存在注入风险。 |
| 3 | FP | SQL_INJECTION | django\core\cache\backends\db.py:263 | dsl.python.sql-injection-format | 检测到使用字符串格式化构造 SQL 语句，存在注入风险。 |
| 4 | TN | SQL_INJECTION | cache/backends/db.py:263 |  | 误报：内部受控操作。 |
| 5 | TN | SQL_INJECTION | cache/backends/db.py:282 |  | 误报：clear() 方法内部操作，完全受框架控制。 |
| 6 | TN | HARDCODED_CREDENTIALS | checks/security/base.py:12 |  | 误报：安全检查工具代码中的常量字符串被误判为硬编码凭据。引擎需要识别'安全工具上下文'。 |
| 7 | TN | XSS_RISK | files/uploadhandler.py:150 |  | 误报：规则混淆了文件 IO write() 与 HTTP response write()，需要区分写入目标（文件对象 vs 响应对象）。 |
| 8 | TN | XSS_RISK | files/uploadhandler.py:190 |  | 误报：文件 IO 被误判为 XSS 输出点。 |
| 9 | TN | XSS_RISK | handlers/exception.py:134 |  | 误报：信号框架 API .send() 被误判为 XSS 输出。需要 type-aware 分析区分信号对象与响应对象。 |
| 10 | TN | XSS_RISK | handlers/exception.py:113 |  | 误报：信号调用被误判为 XSS 输出点。 |
| 11 | FP | RCE_COMMAND_EXEC | django\core\management\commands\shell.py:87 | RCE_COMMAND_EXEC_PY_AST | [工具脚本] 发现 exec()，参数含变量，处于框架工具脚本上下文，已降级。 |
| 12 | FP | RCE_COMMAND_EXEC | django\core\management\commands\shell.py:93 | RCE_COMMAND_EXEC_PY_AST | [工具脚本] 发现 exec()，参数含变量，处于框架工具脚本上下文，已降级。 |
| 13 | FP | RCE_COMMAND_EXEC | django\core\management\commands\shell.py:78 | RCE_COMMAND_EXEC_PY_AST | [工具脚本] 发现 compile()，参数含变量，处于框架工具脚本上下文，已降级。 |
| 14 | FP | HARDCODED_CREDENTIALS | django\conf\__init__.py:24 | HARDCODED_CREDENTIALS_PY_AST | 发现疑似硬编码凭证变量 'PASSWORD_RESET_TIMEOUT_DAYS_DEPRECATED_MSG'（值长度 90），建议从环境变量（os.environ）或 Vault 等安全配置中读取。 |
| 15 | FP | XSS_RISK | django\contrib\admin\helpers.py:145 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 16 | FP | XSS_RISK | django\contrib\admin\helpers.py:150 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 17 | FP | NOSQL_INJECTION | django\contrib\admin\options.py:1138 | NOSQL_INJECTION_PY_AST | pymongo/motor 方法 update() 的查询参数来自用户输入（如 request.json），可能存在 NoSQL 注入（$where/$ne/$regex 等）。建议使用 bson.ObjectId 或白名单字段过滤。 |
| 18 | FP | NOSQL_INJECTION | django\contrib\admin\options.py:1375 | NOSQL_INJECTION_PY_AST | pymongo/motor 方法 update() 的查询参数来自用户输入（如 request.json），可能存在 NoSQL 注入（$where/$ne/$regex 等）。建议使用 bson.ObjectId 或白名单字段过滤。 |
| 19 | FP | NOSQL_INJECTION | django\contrib\admin\options.py:1968 | NOSQL_INJECTION_PY_AST | pymongo/motor 方法 update() 的查询参数来自用户输入（如 request.json），可能存在 NoSQL 注入（$where/$ne/$regex 等）。建议使用 bson.ObjectId 或白名单字段过滤。 |
| 20 | FP | XSS_RISK | django\contrib\admin\options.py:311 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 21 | FP | XSS_RISK | django\contrib\admin\options.py:313 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 22 | FP | XSS_RISK | django\contrib\admin\static\admin\js\SelectBox.js:17 | dsl.javascript.xss-innerhtml | 检测到将用户可控内容直接赋值给 innerHTML，存在 XSS 风险。 |
| 23 | FP | XSS_RISK | django\contrib\admin\templatetags\admin_list.py:261 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 24 | FP | XSS_RISK | django\contrib\admin\templatetags\admin_list.py:291 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 25 | FP | XSS_RISK | django\contrib\admindocs\utils.py:83 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 26 | FP | HARDCODED_CREDENTIALS | django\contrib\auth\views.py:239 | HARDCODED_CREDENTIALS_PY_AST | 发现疑似硬编码凭证变量 'INTERNAL_RESET_SESSION_TOKEN'（值长度 21），建议从环境变量（os.environ）或 Vault 等安全配置中读取。 |
| 27 | FP | OPEN_REDIRECT | django\contrib\auth\views.py:62 | OPEN_REDIRECT_PY_TAINT | 检测到 Python 代码中用户可控输入直接用于 redirect/HttpResponseRedirect 跳转目标，可能导致 Open Redirect 漏洞，建议使用域名白名单或固定路径映射。 |
| 28 | FP | XSS_RISK | django\contrib\flatpages\views.py:69 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 29 | FP | XSS_RISK | django\contrib\flatpages\views.py:66 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 30 | FP | XSS_RISK | django\contrib\flatpages\views.py:67 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 31 | FP | SQL_INJECTION | django\contrib\gis\db\backends\postgis\operations.py:304 | dsl.python.sql-injection-format | 检测到使用字符串格式化构造 SQL 语句，存在注入风险。 |
| 32 | FP | SQL_INJECTION | django\contrib\gis\db\backends\spatialite\operations.py:152 | dsl.python.sql-injection-format | 检测到使用字符串格式化构造 SQL 语句，存在注入风险。 |
| 33 | FP | RCE_COMMAND_EXEC | django\contrib\gis\serializers\geojson.py:53 | RCE_COMMAND_EXEC_PY_AST | 发现 eval()，参数含变量，建议确认参数来源是否可控。 |
| 34 | FP | XSS_RISK | django\contrib\humanize\templatetags\humanize.py:56 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 35 | FP | XSS_RISK | django\contrib\messages\storage\cookie.py:37 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 36 | FP | DESERIALIZATION | django\contrib\sessions\serializers.py:17 | DESERIALIZATION_PY_AST | pickle.loads() 对不可信数据执行反序列化，可导致任意代码执行（RCE）。建议使用 JSON 替代，或在可信边界内使用 hmac 签名验证。 |
| 37 | FP | XSS_RISK | django\contrib\syndication\views.py:172 | XSS_RISK_PY_AST | 发现 render() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 38 | FP | XSS_RISK | django\contrib\syndication\views.py:176 | XSS_RISK_PY_AST | 发现 render() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 39 | FP | RCE_COMMAND_EXEC | django\core\management\utils.py:20 | RCE_COMMAND_EXEC_PY_AST | 发现 subprocess.run() 调用，参数来自用户输入，存在命令注入风险。 |
| 40 | FP | RCE_COMMAND_EXEC | django\db\backends\base\client.py:26 | RCE_COMMAND_EXEC_PY_AST | [安装脚本] subprocess.run() 调用，参数未检测到用户输入，已降级。 |
| 41 | FP | SQL_INJECTION | django\db\backends\base\creation.py:179 | SQL_INJECTION_PY_AST | 检测到 execute() 参数中存在 SQL 字符串拼接且含用户输入，存在 SQL 注入风险，建议使用参数化查询。 |
| 42 | FP | RCE_COMMAND_EXEC | django\db\backends\mysql\creation.py:65 | RCE_COMMAND_EXEC_PY_AST | 发现 subprocess.Popen() 调用，参数含变量，建议确认是否可控。 |
| 43 | FP | RCE_COMMAND_EXEC | django\db\backends\mysql\creation.py:66 | RCE_COMMAND_EXEC_PY_AST | 发现 subprocess.Popen() 调用，参数含变量，建议确认是否可控。 |
| 44 | FP | SQL_INJECTION | django\db\backends\mysql\introspection.py:122 | dsl.python.sql-injection-format | 检测到使用字符串格式化构造 SQL 语句，存在注入风险。 |
| 45 | FP | HARDCODED_CREDENTIALS | django\db\backends\oracle\creation.py:242 | HARDCODED_CREDENTIALS_PY_AST | 发现疑似硬编码凭证变量 'set_password'（值长度 48），建议从环境变量（os.environ）或 Vault 等安全配置中读取。 |
| 46 | FP | SQL_INJECTION | django\db\backends\postgresql\introspection.py:86 | dsl.python.sql-injection-format | 检测到使用字符串格式化构造 SQL 语句，存在注入风险。 |
| 47 | FP | RCE_COMMAND_EXEC | django\db\migrations\questioner.py:139 | RCE_COMMAND_EXEC_PY_AST | 发现 eval()，参数来自用户输入，存在代码注入风险。 |
| 48 | FP | DESERIALIZATION | django\db\migrations\questioner.py:139 | DESERIALIZATION_PY_AST | eval() 执行用户输入内容，等同于任意代码执行。 |
| 49 | FP | XSS_RISK | django\forms\boundfield.py:168 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 50 | FP | XSS_RISK | django\forms\forms.py:266 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 51 | FP | XSS_RISK | django\forms\formsets.py:447 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 52 | FP | XSS_RISK | django\forms\formsets.py:452 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 53 | FP | XSS_RISK | django\forms\formsets.py:457 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 54 | FP | XSS_RISK | django\forms\renderers.py:25 | XSS_RISK_PY_AST | 发现 render() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 55 | FP | HARDCODED_CREDENTIALS | django\middleware\csrf.py:26 | HARDCODED_CREDENTIALS_PY_AST | 发现疑似硬编码凭证变量 'REASON_BAD_TOKEN'（值长度 32），建议从环境变量（os.environ）或 Vault 等安全配置中读取。 |
| 56 | FP | XSS_RISK | django\template\base.py:690 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 57 | FP | XSS_RISK | django\template\base.py:700 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 58 | FP | XSS_RISK | django\template\base.py:782 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 59 | FP | XSS_RISK | django\template\base.py:803 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 60 | FP | XSS_RISK | django\template\base.py:942 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 61 | FP | XSS_RISK | django\template\defaultfilters.py:203 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 62 | FP | XSS_RISK | django\template\defaultfilters.py:401 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 63 | FP | XSS_RISK | django\template\defaultfilters.py:457 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 64 | FP | XSS_RISK | django\template\defaultfilters.py:467 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 65 | FP | XSS_RISK | django\template\defaultfilters.py:549 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 66 | FP | XSS_RISK | django\template\defaultfilters.py:667 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 67 | FP | XSS_RISK | django\template\defaulttags.py:42 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 68 | FP | XSS_RISK | django\template\defaulttags.py:218 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 69 | FP | XSS_RISK | django\template\loader.py:62 | XSS_RISK_PY_AST | 发现 render() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 70 | FP | XSS_RISK | django\template\loader_tags.py:76 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 71 | FP | HARDCODED_CREDENTIALS | django\template\smartif.py:161 | dsl.python.hardcoded-password | 检测到疑似硬编码密码，请改为从安全配置或环境变量加载。 |
| 72 | FP | HARDCODED_CREDENTIALS | django\template\smartif.py:164 | dsl.python.hardcoded-password | 检测到疑似硬编码密码，请改为从安全配置或环境变量加载。 |
| 73 | FP | XSS_RISK | django\templatetags\i18n.py:92 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 74 | FP | RCE_COMMAND_EXEC | django\utils\autoreload.py:258 | RCE_COMMAND_EXEC_PY_AST | 发现 subprocess.run() 调用，参数含变量，建议确认是否可控。 |
| 75 | FP | XSS_RISK | django\utils\html.py:43 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 76 | FP | XSS_RISK | django\utils\html.py:68 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 77 | FP | XSS_RISK | django\utils\html.py:88 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 78 | FP | XSS_RISK | django\utils\html.py:132 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 79 | FP | XSS_RISK | django\utils\html.py:342 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 80 | FP | XSS_RISK | django\utils\html.py:346 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 81 | FP | XSS_RISK | django\utils\html.py:376 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 82 | FP | XSS_RISK | django\utils\numberformat.py:26 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 83 | FP | XSS_RISK | django\utils\safestring.py:50 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 84 | FP | HARDCODED_CREDENTIALS | django\utils\text.py:308 | dsl.python.hardcoded-password | 检测到疑似硬编码密码，请改为从安全配置或环境变量加载。 |
| 85 | FP | XSS_RISK | django\utils\translation\trans_real.py:365 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 86 | FP | XSS_RISK | django\utils\translation\trans_real.py:377 | dsl.python.xss-marksafe | 检测到 mark_safe 直接包装用户输入，存在 XSS 风险。 |
| 87 | FP | XSS_RISK | django\views\defaults.py:60 | XSS_RISK_PY_AST | 发现 render() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 88 | FP | XSS_RISK | django\views\defaults.py:147 | XSS_RISK_PY_AST | 发现 render() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 89 | FP | OPEN_REDIRECT | django\views\i18n.py:56 | OPEN_REDIRECT_PY_TAINT | 检测到 Python 代码中用户可控输入直接用于 redirect/HttpResponseRedirect 跳转目标，可能导致 Open Redirect 漏洞，建议使用域名白名单或固定路径映射。 |
| 90 | FP | HARDCODED_CREDENTIALS | docs\conf.py:317 | HARDCODED_CREDENTIALS_PY_AST | 发现疑似硬编码凭证变量 'epub_author'（值长度 26），建议从环境变量（os.environ）或 Vault 等安全配置中读取。 |
| 91 | FP | RCE_COMMAND_EXEC | scripts\manage_translations.py:76 | RCE_COMMAND_EXEC_PY_AST | [安装脚本] subprocess.run() 调用，参数未检测到用户输入，已降级。 |
| 92 | FP | RCE_COMMAND_EXEC | scripts\manage_translations.py:185 | RCE_COMMAND_EXEC_PY_AST | [工具脚本] 发现 eval()，参数含变量，处于框架工具脚本上下文，已降级。 |
| 93 | FP | RCE_COMMAND_EXEC | scripts\manage_translations.py:124 | RCE_COMMAND_EXEC_PY_AST | [安装脚本] subprocess.run() 调用，参数未检测到用户输入，已降级。 |
| 94 | FP | RCE_COMMAND_EXEC | scripts\manage_translations.py:150 | RCE_COMMAND_EXEC_PY_AST | [安装脚本] subprocess.run() 调用，参数未检测到用户输入，已降级。 |
| 95 | FP | RCE_COMMAND_EXEC | scripts\manage_translations.py:165 | RCE_COMMAND_EXEC_PY_AST | [安装脚本] subprocess.run() 调用，参数未检测到用户输入，已降级。 |
| 96 | FP | RCE_COMMAND_EXEC | scripts\manage_translations.py:166 | RCE_COMMAND_EXEC_PY_AST | [安装脚本] subprocess.run() 调用，参数未检测到用户输入，已降级。 |
| 97 | FP | RCE_COMMAND_EXEC | scripts\manage_translations.py:154 | RCE_COMMAND_EXEC_PY_AST | [安装脚本] subprocess.run() 调用，参数未检测到用户输入，已降级。 |
| 98 | FP | RCE_COMMAND_EXEC | tests\runtests.py:372 | RCE_COMMAND_EXEC_PY_AST | 发现 subprocess.run() 调用，参数含变量，建议确认是否可控。 |
| 99 | FP | RCE_COMMAND_EXEC | tests\runtests.py:377 | RCE_COMMAND_EXEC_PY_AST | 发现 subprocess.run() 调用，参数含变量，建议确认是否可控。 |
| 100 | FP | RCE_COMMAND_EXEC | tests\runtests.py:419 | RCE_COMMAND_EXEC_PY_AST | 发现 subprocess.call() 调用，参数含变量，建议确认是否可控。 |
| 101 | FP | HARDCODED_CREDENTIALS | tests\test_sqlite.py:24 | HARDCODED_CREDENTIALS_PY_AST | 发现疑似硬编码凭证变量 'SECRET_KEY'（值长度 23），建议从环境变量（os.environ）或 Vault 等安全配置中读取。 |
| 102 | FP | RCE_COMMAND_EXEC | tests\admin_scripts\test_django_admin_py.py:20 | RCE_COMMAND_EXEC_PY_AST | 发现 subprocess.run() 调用，参数含变量，建议确认是否可控。 |
| 103 | FP | HARDCODED_CREDENTIALS | tests\admin_views\customadmin.py:19 | HARDCODED_CREDENTIALS_PY_AST | 发现疑似硬编码凭证变量 'password_change_template'（值长度 38），建议从环境变量（os.environ）或 Vault 等安全配置中读取。 |
| 104 | FP | HARDCODED_CREDENTIALS | tests\admin_views\customadmin.py:20 | HARDCODED_CREDENTIALS_PY_AST | 发现疑似硬编码凭证变量 'password_change_done_template'（值长度 38），建议从环境变量（os.environ）或 Vault 等安全配置中读取。 |
| 105 | FP | XSS_RISK | tests\admin_views\views.py:7 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 106 | FP | XSS_RISK | tests\admin_views\views.py:12 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 107 | FP | XSS_RISK | tests\asgi\urls.py:7 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 108 | FP | HARDCODED_CREDENTIALS | tests\auth_tests\test_hashers.py:189 | HARDCODED_CREDENTIALS_PY_AST | 发现疑似硬编码凭证变量 'password'（值长度 100），建议从环境变量（os.environ）或 Vault 等安全配置中读取。 |
| 109 | FP | HARDCODED_CREDENTIALS | tests\auth_tests\test_views.py:310 | HARDCODED_CREDENTIALS_PY_AST | 发现疑似硬编码凭证变量 'reset_url_token'（值长度 18），建议从环境变量（os.environ）或 Vault 等安全配置中读取。 |
| 110 | FP | HARDCODED_CREDENTIALS | tests\backends\tests.py:344 | dsl.python.hardcoded-password | 检测到疑似硬编码密码，请改为从安全配置或环境变量加载。 |
| 111 | FP | HARDCODED_CREDENTIALS | tests\csrf_tests\test_context_processor.py:11 | HARDCODED_CREDENTIALS_PY_AST | 发现疑似硬编码凭证变量 'test_token'（值长度 64），建议从环境变量（os.environ）或 Vault 等安全配置中读取。 |
| 112 | FP | RCE_COMMAND_EXEC | tests\dbshell\test_mysql.py:199 | RCE_COMMAND_EXEC_PY_AST | 发现 subprocess.run() 调用，参数含变量，建议确认是否可控。 |
| 113 | FP | RCE_COMMAND_EXEC | tests\dbshell\test_postgresql.py:130 | RCE_COMMAND_EXEC_PY_AST | 发现 subprocess.run() 调用，参数含变量，建议确认是否可控。 |
| 114 | FP | HARDCODED_CREDENTIALS | tests\extra_regress\tests.py:15 | dsl.python.hardcoded-password | 检测到疑似硬编码密码，请改为从安全配置或环境变量加载。 |
| 115 | FP | NOSQL_INJECTION | tests\file_uploads\views.py:21 | NOSQL_INJECTION_PY_AST | pymongo/motor 方法 update() 的查询参数来自用户输入（如 request.json），可能存在 NoSQL 注入（$where/$ne/$regex 等）。建议使用 bson.ObjectId 或白名单字段过滤。 |
| 116 | FP | NOSQL_INJECTION | tests\file_uploads\views.py:37 | NOSQL_INJECTION_PY_AST | pymongo/motor 方法 update() 的查询参数来自用户输入（如 request.json），可能存在 NoSQL 注入（$where/$ne/$regex 等）。建议使用 bson.ObjectId 或白名单字段过滤。 |
| 117 | FP | XSS_RISK | tests\file_uploads\views.py:77 | XSS_RISK_PY_AST | 发现 JsonResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 118 | FP | XSS_RISK | tests\file_uploads\views.py:88 | XSS_RISK_PY_AST | 发现 JsonResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 119 | FP | RCE_COMMAND_EXEC | tests\i18n\test_compilation.py:197 | RCE_COMMAND_EXEC_PY_AST | 发现 subprocess.run() 调用，参数含变量，建议确认是否可控。 |
| 120 | FP | XSS_RISK | tests\messages_tests\urls.py:46 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 121 | FP | HARDCODED_CREDENTIALS | tests\migrations\test_commands.py:1767 | HARDCODED_CREDENTIALS_PY_AST | 发现疑似硬编码凭证变量 'did_you_mean_auth_error'（值长度 71），建议从环境变量（os.environ）或 Vault 等安全配置中读取。 |
| 122 | FP | RCE_COMMAND_EXEC | tests\migrations\test_writer.py:205 | RCE_COMMAND_EXEC_PY_AST | 发现 exec()，参数含变量，建议确认参数来源是否可控。 |
| 123 | FP | RCE_COMMAND_EXEC | tests\postgres_tests\test_integration.py:14 | RCE_COMMAND_EXEC_PY_AST | 发现 subprocess.run() 调用，参数含变量，建议确认是否可控。 |
| 124 | FP | HARDCODED_CREDENTIALS | tests\syndication_tests\feeds.py:15 | HARDCODED_CREDENTIALS_PY_AST | 发现疑似硬编码凭证变量 'author_link'（值长度 23），建议从环境变量（os.environ）或 Vault 等安全配置中读取。 |
| 125 | FP | HARDCODED_CREDENTIALS | tests\syndication_tests\feeds.py:37 | HARDCODED_CREDENTIALS_PY_AST | 发现疑似硬编码凭证变量 'item_author_link'（值长度 23），建议从环境变量（os.environ）或 Vault 等安全配置中读取。 |
| 126 | FP | XSS_RISK | tests\test_client\views.py:26 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 127 | FP | XSS_RISK | tests\test_client\views.py:68 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 128 | FP | XSS_RISK | tests\test_client\views.py:85 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 129 | FP | XSS_RISK | tests\test_client\views.py:99 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 130 | FP | XSS_RISK | tests\test_client\views.py:122 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 131 | FP | XSS_RISK | tests\test_client\views.py:212 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 132 | FP | XSS_RISK | tests\test_client\views.py:268 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 133 | FP | XSS_RISK | tests\test_client\views.py:277 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 134 | FP | XSS_RISK | tests\test_client\views.py:285 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 135 | FP | XSS_RISK | tests\test_client\views.py:295 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 136 | FP | XSS_RISK | tests\test_client\views.py:335 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 137 | FP | XSS_RISK | tests\test_client\views.py:386 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 138 | FP | XSS_RISK | tests\test_client\views.py:311 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 139 | FP | XSS_RISK | tests\test_client\views.py:320 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 140 | FP | XSS_RISK | tests\test_client\views.py:55 | XSS_RISK_PY_AST | 发现 HttpResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 141 | FP | OPEN_REDIRECT | tests\test_client\views.py:145 | OPEN_REDIRECT_PY_TAINT | 检测到 Python 代码中用户可控输入直接用于 redirect/HttpResponseRedirect 跳转目标，可能导致 Open Redirect 漏洞，建议使用域名白名单或固定路径映射。 |
| 142 | FP | XSS_RISK | tests\test_client_regress\views.py:109 | XSS_RISK_PY_AST | 发现 JsonResponse() 调用参数含疑似用户输入且未经 HTML 转义，存在 XSS 风险。建议使用 html.escape() 或模板自动转义。 |
| 143 | FP | RCE_COMMAND_EXEC | tests\view_tests\tests\test_debug.py:593 | RCE_COMMAND_EXEC_PY_AST | 发现 exec()，参数含变量，建议确认参数来源是否可控。 |
| 144 | FP | RCE_COMMAND_EXEC | tests\view_tests\tests\test_debug.py:630 | RCE_COMMAND_EXEC_PY_AST | 发现 exec()，参数含变量，建议确认参数来源是否可控。 |

---

## Evaluation scope

- Ground-truth entries supplied: 13
- Entries evaluated: 13
- Explicitly out of scope: 0
- Invalid at this target revision: 0

---

## Performance

- Scan duration: `39.491 s`
- RSS before scan: `64.125 MiB`
- RSS after scan: `94.777 MiB`
- RSS delta: `30.652 MiB`
- Process peak RSS: `141.875 MiB`

Peak RSS is the lifetime peak of this standalone evaluator process.

---

## Reproducibility

- Clean release baseline: `yes`
- Engine: `new`
- Scanner revision: `d51bd8b946492fe1799f431b45c1da070a35cbc1`
- Scanner dirty: `no`
- Scanner diff SHA-256: `unavailable`
- Target revision: `b6475d7d7940f3ce575e0b0f2d83e517f899b4cf`
- Target subdirectory: `.`
- Target dirty: `no`
- Target diff SHA-256: `unavailable`
- Ground truth: `scripts/data/ground_truth_django_3.2_core.json`
- Ground truth SHA-256: `9041cf468016f68899f48701e145e31d1d8b189c9d216c5efdd01373ace829e6`
- Python: `3.11.0`
- Platform: `Windows-10-10.0.26200-SP0`
- Processor: `Intel64 Family 6 Model 183 Stepping 1, GenuineIntel`
