# Active Context

最后更新: 2026-05-25

## 当前任务

根据 `docs/technical/CODE_REVIEW_FINDINGS.md` 和 `PROJECT_OPTIMIZATION_PLAN.md` 持续推进第一阶段项目优化；P1 安全边界与 M2 扫描失败可见性已完成首轮落地，下一步继续处理规则语义与漏报/误报质量。

## 当前项目状态

- 根目录 README 显示项目定位为 local-first SAST scanner + AI auto-fix。
- Python core 当前版本为 `1.4.0`。
- VS Code extension 当前版本为 `0.6.1`。
- 已支持 JS/TS、Python、PHP、Java、Go。
- 已有 baseline / suppression、增量扫描、AI provider、多语言 AST + taint 规则、LSP、CLI、VS Code 扩展。
- 当前仓库已有 `docs/planning`、`docs/superpowers`、`docs/technical` 等历史文档；`memory-bank` 作为下一次 AI 工作的入口和摘要层。

## 最新质量进展

已从历史 `docs/superpowers/reports` 中提炼到 memory bank:

2026-05-25 外部试用准备:

- 删除本地未跟踪的 `aegis-ai-core/.env`，避免工作区继续保留真实 API key；用户仍需在对应 AI provider 控制台轮换/废弃旧 key。
- VS Code extension 从 `0.6.0` 升为 `0.6.1`，并重新打包 `aegis-vscode/aegis-ai-security-0.6.1.vsix`，该包包含 2026-05 最新 bundled backend。
- 用户通过 `vsce publish --packagePath aegis-ai-security-0.6.1.vsix` 成功发布 Marketplace 版本 `wen-zai.aegis-ai-security v0.6.1`。
- 验证通过: `npm run package`。发布后仍需做 Marketplace 安装 smoke test，并确认 provider key 已轮换。

- 2026-04-25 Round 9: DVWA 方向继续优化，F1 从 `0.43` 提升到 `0.60`，Recall `95.8%`，Precision `43.4%`，TP/FP/FN/TN 为 `23 / 30 / 1 / 1`。
- 2026-04-24 Round 8: Java demo 和 Go `go-insecure-web-app` 达到 Recall / Precision / F1 全部 `100%`。
- 2026-04-18 到 2026-04-25 的阶段报告显示 scanner capability optimization 已完成多轮 JS/TS、Python、PHP、Java/Go 修复。

历史阶段/轮次 progress report 文件已在 2026-04-26 删除，保留其关键信息在 `progress.md`。

2026-04-28 第一批优化已落地:

- VS Code taint path Webview 移除 inline `onclick` 字符串拼接，改为 JSON 数据岛 + nonce script 事件监听。
- LSP CodeAction 不再在 lightbulb 请求阶段实例化/调用 AI provider，AI 修复改为用户显式选择 `aegisAI.previewFix` 后再走 `aegis/generateFix`。
- AI fix preview apply 前校验文档版本和原始文本，并修正 line range 计算，避免 stale preview 或越界替换。
- Baseline Tree 和删除 baseline 后的 rescan 路径增加 workspace containment 检查，拒绝 `..` 或绝对路径越界。
- VS Code 后端启动敏感配置 `pythonPath` / `serverModule` / `serverCwd` 改为 application scope，并在运行时只读取 global/default 值；untrusted workspace 禁用 workspace backend discovery。
- 验证通过: `aegis-ai-core` LSP 单元测试 58 个、VS Code 扩展测试 29 个、`npm run check`、`ruff check`、`ruff format --check`。

2026-04-28 第二批优化已落地:

- 修复 M4: 非 Git 项目运行 incremental scan 时不再返回空结果，而是回退为扫描发现到的所有源码文件。
- 修复 M4: Git incremental scan 纳入 `git ls-files --others --exclude-standard` 返回的未跟踪源码文件，避免新建漏洞文件被漏扫。
- 推进 M3: LSP `aegis/requestScanWorkspace` 不再遍历已打开文档，而是基于 workspace root 文件发现扫描未打开源码文件，并在异常路径也发送 progress 完成通知。
- 推进 M10/S4: 移除扫描结束后的后台 AI precache，AI provider 调用只保留在用户显式触发 `aegis/generateFix` 时发生。
- 验证通过: `python -m pytest tests/`、`ruff check src tests`、`python scripts/typecheck_gate.py --group ci`、`npm run check`，以及本轮触碰文件的 `ruff format --check`。

2026-04-28 第三批优化已落地:

- 修复 M2: `ProjectScanner` 扫描/分析失败不再静默返回 clean，会在 stats 中输出 `partial`、`error_count` 和结构化 `errors`。
- 修复 M2: JSON、Markdown、HTML、增强版 HTML、SARIF 报告暴露 partial scan 状态；SARIF 通过 `invocations.toolExecutionNotifications` 标记扫描错误。
- 修复 M2: CLI verbose 输出扫描错误，且扫描错误返回退出码 `2`；`--no-fail-on-findings` 只影响 finding，不隐藏扫描失败。
- 修复 M2: `RuleEngine` analyzer failure 不再吞掉并返回空列表，而是抛出 `RuntimeError` 交给 ProjectScanner/LSP/CLI 错误路径处理。
- 修复 M2: Incremental scan stats 也继承 partial/error 语义；失败的空结果不会写入扫描缓存。
- 验证通过: `python -m pytest tests/`、`ruff check src tests`、`python scripts/typecheck_gate.py --group ci`，以及本轮触碰文件的 `ruff format --check`。全量 `ruff format --check src tests` 仍有 32 个历史未格式化文件。

2026-04-28 第四批优化已落地:

- 推进 M7: Python XSS 规则现在会检测 Django `HttpResponse(...)` / `JsonResponse(...)` / `StreamingHttpResponse(...)` / `FileResponse(...)` 和 Flask `make_response(...)` 构造器中的未转义用户输入。
- 推进 M5/M7: Python XSS sanitizer 判断改为上下文敏感，只信任明确的 HTML sanitizer (`html.escape`、`markupsafe.escape`、`bleach.clean` 等)，不再把 `urllib.parse.quote` 或任意对象 `.escape()` 当 HTML 输出净化。
- 新增 3 个 XSS TP fixture 覆盖 `HttpResponse(request.GET[...])`、URL quote 非 HTML sanitizer、业务对象 `.escape()` 非 sanitizer。
- 验证通过: `tests/rules/test_all_rules.py -k "XSS_RISK"`、完整 `tests/rules/test_all_rules.py`、`python -m pytest tests/`、`ruff check src tests`、`python scripts/typecheck_gate.py --group ci`，以及本轮触碰文件的 `ruff format --check`。

2026-04-30 第五批优化已落地:

- 推进 M7: PHP XSS 规则不再把 `strip_tags(...)` 视为 HTML 输出转义 sanitizer，只保留 `htmlspecialchars(...)` / `htmlentities(...)`。
- 推进 M7: PHP NoSQL 规则会检查 MongoDB 调用的所有参数，不再只看第一个 argument；覆盖 `updateOne(..., ['$set' => $_POST[...]])` 这类 update document 漏报。
- 新增 2 个 TP fixture: `tp_php_strip_tags_not_escape.php`、`tp_php_mongo_update_second_arg.php`。
- 验证通过: `tests/rules/test_all_rules.py` 121 个规则样本、`python -m pytest tests/`、`ruff check src tests`、`python scripts/typecheck_gate.py --group ci`，以及本轮触碰 Python 文件的 `ruff format --check`。

2026-04-30 第六批优化已落地:

- 推进 M7: Python RCE 规则现在解析 `import subprocess as sp`、`from subprocess import run`、`from os import system` 等 import alias / from-import sink。
- 新增 3 个 RCE TP fixture: `tp_python_subprocess_alias_run.py`、`tp_python_from_subprocess_run.py`、`tp_python_from_os_system.py`。
- 验证通过: `tests/rules/test_all_rules.py` 124 个规则样本、`python -m pytest tests/`、`ruff check src tests`、`python scripts/typecheck_gate.py --group ci`，以及本轮触碰 Python 文件的 `ruff format --check`。

2026-04-30 第七批优化已落地:

- 推进 M7: Python NoSQL 规则的用户输入判断递归进入 dict/list/tuple/set 和 call 参数，能检测 `collection.find_one({"name": request.json["name"]})`、`collection.find({"$where": request.args["q"]})` 等直接查询参数。
- 新增 2 个 NoSQL TP fixture: `tp_pymongo_dict_request_json.py`、`tp_pymongo_where_request_args.py`。
- 验证通过: `tests/rules/test_all_rules.py` 126 个规则样本、`python -m pytest tests/`、`ruff check src tests`、`python scripts/typecheck_gate.py --group ci`，以及本轮触碰 Python 文件的 `ruff format --check`。

2026-04-30 第八批优化已落地:

- 推进 M7: Python 反序列化规则现在解析 `import pickle as p`、`from pickle import loads`、`import yaml as y` 等 import alias / from-import sink。
- 新增 3 个反序列化 TP fixture: `tp_pickle_alias_loads.py`、`tp_from_pickle_loads.py`、`tp_yaml_alias_load.py`。
- 验证通过: `tests/rules/test_all_rules.py` 129 个规则样本、`python -m pytest tests/`、`ruff check src tests`、`python scripts/typecheck_gate.py --group ci`，以及本轮触碰 Python 文件的 `ruff format --check`。

2026-04-30 第九批优化已落地:

- 推进 M5/M7: Python 反序列化规则对 `yaml.load(...)` 增加 Loader 语义判断；显式使用 `SafeLoader` / `CSafeLoader` 的调用不再作为反序列化风险上报。
- 新增 2 个反序列化 FP fixture: `fp_yaml_load_safe_loader_keyword.py`、`fp_yaml_load_safe_loader_positional.py`，覆盖 keyword 与第二个 positional Loader 写法。
- 验证通过: `tests/rules/test_all_rules.py -k "DESERIALIZATION"` 15 个样本、完整 `tests/rules/test_all_rules.py` 131 个规则样本、`python -m pytest tests/` 506 passed、`ruff check src tests`、`python scripts/typecheck_gate.py --group ci`，以及本轮触碰 Python 文件的 `ruff format --check`。

2026-04-30 第十批优化已落地:

- 推进 M5/M7: Python Path Traversal 规则不再把 `os.path.abspath(...)` / `os.path.realpath(...)` 当作完整路径净化；这些调用只解析路径，仍需白名单目录约束。
- 推进 M7: Flask `send_from_directory(directory, path)` 会检查第二个 path/filename 参数，同时保留对 directory 参数和关键字参数的检查。
- 新增 2 个 Path Traversal TP fixture: `tp_python_abspath_realpath_not_sanitizer.py`、`tp_python_send_from_directory_second_arg.py`。
- 验证通过: `tests/rules/test_all_rules.py -k "PATH_TRAVERSAL"` 14 个样本、完整 `tests/rules/test_all_rules.py` 133 个规则样本、`python -m pytest tests/` 508 passed、`ruff check src tests`、`python scripts/typecheck_gate.py --group ci`，以及本轮触碰 Python 文件的 `ruff format --check`。

2026-04-30 第十一批优化已落地:

- 推进 M7: Python SQLi 规则不再把所有 `cursor.execute(sql_var, params)` 变量查询直接视为安全；如果 `sql_var` 在本文件中由用户输入拼接/格式化成 SQL，第二个 params 参数不能消除动态 SQL 片段风险。
- 为避免误伤正常参数化变量，规则预扫描本文件赋值，只记录明确含 SQL 关键词和用户输入的 query 变量；保留 `sql = "SELECT ..."; cursor.execute(sql, (user,))` FP 保护。
- 新增 1 个 SQLi TP fixture: `tp_python_tainted_query_var_with_params.py`。
- 验证通过: `tests/rules/test_all_rules.py -k "SQL_INJECTION"` 37 个样本、完整 `tests/rules/test_all_rules.py` 134 个规则样本、`python -m pytest tests/` 509 passed、`ruff check src tests`、`python scripts/typecheck_gate.py --group ci`，以及本轮触碰 Python 文件的 `ruff format --check`。

2026-05-03 第十二批优化已落地:

- 收口 M5/M7 进行中的跨语言 P1 规则语义缺口，覆盖 PHP、Go、Java、JavaScript。
- PHP: `unserialize(..., ["allowed_classes" => true])` 不再被当作安全；`header($location)` 能追踪变量中的 `Location:` 重定向；`copy()` / `rename()` 同时检查第二个路径参数；`prepare()` 动态 SQL 纳入 AST 语义判断。
- Go: `filepath.Clean()` / `path.Clean()` 不再被视为完整 Path Traversal sanitizer；规则会追踪本地赋值链并在文件操作 sink 前解析用户输入来源。
- Java: class-level field declarations 中的硬编码凭证纳入检测；本轮新增的 Java path second arg、field assignment password、custom encode XSS 样本确认已由既有规则覆盖。
- JavaScript: XSS 只信任 `DOMPurify.sanitize()` 或明确 HTML escaping helper，不再信任通用 `encode()` / `escape()` / 本地 `sanitize()`；RCE 覆盖 eval 动态 template string 和 `child_process` require/import alias；NoSQL 单键 `_id` 查询若 id 变量已污染则不再跳过；硬编码凭证逐个检查 multi-declarator。
- 新增/调整规则 fixtures 后，完整 `tests/rules/test_all_rules.py` 达到 152 passed。
- 验证通过: `python -m pytest tests/` -> 527 passed, 47 deselected, 1 xfailed；`ruff check src tests` -> passed；`python scripts/typecheck_gate.py --group ci` -> passed；本轮触碰 Python 文件 `ruff format --check` -> passed。全量 `ruff format --check src tests` 仍因 21 个未修改的历史格式文件失败，本轮未做无关 mass-format。

2026-05-03 第十三批优化已落地:

- 修复 M11: `AIAnalyzer` 分析缓存 key 绑定漏洞类型、CWE、文件路径、行列位置、语言、details 和代码上下文哈希，不再只按漏洞类型 + details 前 100 字符复用结果。
- 修复 E7: `InlineSuppressor` 只解析真实行注释中的 `aegis-ignore`，字符串字面量里的 `# aegis-ignore` / `// aegis-ignore` 不再抑制 finding；真实上一行注释和行内注释语义保持不变。
- 新增回归测试覆盖不同文件/源码上下文的 AI cache 隔离、同上下文 cache 命中，以及 Python/JS 字符串 suppression marker 不生效。
- 验证通过: 针对性 RED -> GREEN 测试，最终 `tests/test_ai_provider.py::TestAiAnalysisCache::test_cache_is_bound_to_file_and_source_context tests/test_inline_suppressor.py` -> 20 passed；`python -m pytest tests/` -> 531 passed, 47 deselected, 1 xfailed；`ruff check src tests` -> passed；`python scripts/typecheck_gate.py --group ci` -> passed；本轮触碰文件 `ruff format --check` -> passed。全量 `ruff format --check src tests` 仍因 20 个历史格式文件失败。

2026-05-03 第十四批优化已落地:

- 清理 `ruff format --check src tests` 暴露的 20 个历史格式债，只对 Ruff 报告的 core 源文件执行机械格式化。
- 未修改 `aegis-ai-core/real_world_targets/*`，未做规则语义或 benchmark 输入变更。
- 验证通过: `ruff format --check src tests` -> 158 files already formatted；`ruff check src tests` -> passed；`python scripts/typecheck_gate.py --group ci` -> passed；`python -m pytest tests/` -> 531 passed, 47 deselected, 1 xfailed。

2026-05-04 第十五批优化已落地:

- 推进 M6: benchmark TypeScript case 现在按 `.ts` / `.tsx` 文件名并携带 `language="typescript"` 进入 JS/TS analyzer，不再退化成 `benchmark.js` + JavaScript 语境。
- 推进 M6: `JavaScriptAnalyzer` 为 JavaScript 和 TypeScript 分别维护 parser，并在 `language == "typescript"` 时优先选择 TypeScript parser，避免 TS-only 语法在 benchmark/分析路径中解析失败。
- 新增 RED -> GREEN 回归覆盖 TypeScript benchmark dispatch 和 analyzer parser 选择。
- 验证通过: TypeScript dispatch RED 用例先失败为 TP 0 / FN 1，修复后专项 benchmark 测试 7 passed, 29 deselected；`ruff check src tests` -> passed；`ruff format --check src tests` -> 158 files already formatted；`python scripts/typecheck_gate.py --group ci` -> passed；`python -m pytest tests/` -> 533 passed, 47 deselected, 1 xfailed。

2026-05-04 第十六批优化已落地:

- 继续推进 M6: `CrossFileAnalyzer` 现在为 JavaScript、TypeScript、Python 分别初始化 parser，`.ts` / `.tsx` 跨文件分析优先使用 TypeScript parser，缺失时才回退 JavaScript parser。
- `scan_project()` 同时发现 `.jsx` / `.tsx`，相对模块解析也补齐 `.jsx`、`.tsx`、`index.jsx`、`index.tsx` 候选路径。
- 新增 RED -> GREEN 回归覆盖 `.ts` 文件 parser dispatch，并用真实 TS-only type annotation / interface / import-export 样本确认依赖边可解析。
- 验证通过: cross-file TS dispatch RED 用例先失败为 `['javascript'] != ['typescript']`，修复后 `tests/test_taint_regressions.py tests/test_benchmark_engine_dispatch.py` -> 11 passed；`ruff check src tests` -> passed；`ruff format --check src tests` -> 158 files already formatted；`python scripts/typecheck_gate.py --group ci` -> passed；`python -m pytest tests/` -> 535 passed, 47 deselected, 1 xfailed。

2026-05-04 第十七批优化已落地:

- 收口 M6 legacy TypeScript 路径: `MultiLanguageASTAnalyzer` 不再把 `typescript` 直接绑定到 JavaScript parser；`.ts` / `.tsx` 或 `language="typescript"` 优先使用 TypeScript parser，缺失时才回退 JavaScript parser。
- 转向 DVWA/PHP precision: `preg_replace()` 只有在静态 regex pattern 使用 `/e` modifier 时才作为 PHP RCE sink；普通替换即使 subject/replacement 含用户输入也不再按 RCE 报告。
- 转向 DVWA/PHP precision: PHP hardcoded credentials 对 `token` / `auth` / `api_key` / `credential` 类变量要求值呈 opaque secret 形态，避免把 `userid:2` 这类低熵业务载荷当凭证；`password` / `secret` 等名称的既有检测保持。
- 新增 RED -> GREEN fixtures 覆盖 legacy TS parser dispatch、`preg_replace` 无 `/e` FP 与 `/e` TP、低熵 token payload FP 与 opaque auth token TP。
- 验证通过: `tests/rules/test_all_rules.py` -> 156 passed；`python -m pytest tests/` -> 540 passed, 47 deselected, 1 xfailed；`ruff check src tests` -> passed；`ruff format --check src tests` -> 158 files already formatted；`python scripts/typecheck_gate.py --group ci` -> passed。只读 DVWA 分类脚本显示当前规则下 55 findings，24 TP / 31 FP / 0 FN / 1 TN，Precision 43.6%，较本轮开始 58 findings、34 FP 降低 3 个 FP。

2026-05-07 第十八批优化已落地:

- 继续 DVWA/PHP precision: JavaScript RCE 的 `eval(...)` / `Function(...)` 不再把任意 call expression 参数直接兜底为 RCE；`eval(buildBundle("status"))` 这类本地静态 builder 调用不再上报，`eval(buildCode(req.query.cmd))` 仍由 source/taint 语义检出。
- 继续 DVWA/PHP precision: PHP hardcoded credentials 将低熵占位值 `"password"` 视为 safe placeholder，过滤 DVWA `vulnerabilities/sqli/test.php` 的 `$password = "password"` FP；强密码样式的硬编码 password 仍上报。
- 新增 RED -> GREEN fixtures: `fp_js_eval_static_builder_call.js`、`tp_js_eval_builder_req_query.js`、`fp_php_low_entropy_password_placeholder.php`、`tp_php_strong_hardcoded_password.php`。
- 验证通过: `tests/rules/test_all_rules.py` -> 160 passed；`python -m pytest tests/` -> 544 passed, 47 deselected, 1 xfailed；`ruff check src tests` -> passed；`ruff format --check src tests` -> 158 files already formatted；`python scripts/typecheck_gate.py --group ci` -> passed。
- 只读 DVWA 分类脚本显示当前规则下 53 findings，24 TP / 29 FP / 0 FN / 1 TN，Recall 100.0%，Precision 45.3%，F1 0.62。相对第十七批末尾继续降低 2 个 FP，且不牺牲 recall。

2026-05-07 第十九批优化已落地:

- 继续 DVWA/PHP precision: PHP Open Redirect regex 补充层现在同时处理 `header("Location: {$location}")` 插值写法；局部变量只有在近邻赋值能追到 `$_GET` / `$_POST` / `$_REQUEST` / `$_COOKIE` 时才由 regex 层上报，普通 helper 参数不再误报。
- 继续 DVWA/PHP precision: PHP RCE 对 `explode('.')` 后四段 `is_numeric($octet[0..3])` + `sizeof/count($octet) == 4` + 同一 guard 块内重组 IP 再进入 `shell_exec/exec/system/...` 的命令执行场景降噪；缺失完整 guard 或直接使用原始输入仍上报。
- 新增 RED -> GREEN fixtures: `fp_php_header_location_interpolated_function_param.php`、`tp_php_header_location_interpolated_user_input.php`、`fp_php_shell_exec_numeric_ip_rebuild.php`、`tp_php_shell_exec_incomplete_numeric_guard.php`。
- 验证通过: `tests/rules/test_all_rules.py` -> 164 passed；`python -m pytest tests/` -> 548 passed, 47 deselected, 1 xfailed；`ruff check src tests` -> passed；`ruff format --check src tests` -> 158 files already formatted；`python scripts/typecheck_gate.py --group ci` -> passed。
- 只读 DVWA 分类脚本显示当前规则下 51 findings，24 TP / 27 FP / 0 FN / 2 TN，Recall 100.0%，Precision 47.1%，F1 0.64。相对第十八批末尾继续降低 2 个 FP，并保持 recall。

2026-05-09 第二十批优化已落地:

- 继续 DVWA/PHP precision: PHP regex XSS 补充层不再扫描明确 `$html .= "..."` 多行模板字符串内部的 JS DOM sink 行，除非该行含 PHP 超全局或 `{$var}` 插值；避免把模板内纯前端变量当 PHP XSS。
- 继续 DVWA/PHP precision: PHP regex XSS 对 `echo $var` 增加最近赋值静态字面量判断，`$var` 最近赋值为纯静态字符串/数字拼接时不再上报。
- 继续 DVWA/PHP precision: PHP Path Traversal 规则将 `$_FILES[...]["tmp_name"]` 识别为服务端临时上传路径，并对 `md5/uniqid/...` 随机 basename + 已 allowlist 校验扩展名的上传目标路径降噪；未校验扩展名仍保留 TP。
- 新增 RED -> GREEN fixtures: `fp_php_embedded_js_innerhtml_without_php_input.php`、`fp_php_echo_static_local_var.php`、`fp_php_randomized_upload_filename_validated_ext.php`、`tp_php_randomized_upload_filename_unvalidated_ext.php`。
- 验证通过: `tests/rules/test_all_rules.py` -> 168 passed；`python -m pytest tests/` -> 552 passed, 47 deselected, 1 xfailed；`ruff check src tests` -> passed；`ruff format --check src tests` -> 158 files already formatted；`python scripts/typecheck_gate.py --group ci` -> passed。
- 只读 DVWA 分类脚本显示当前规则下 45 findings，24 TP / 21 FP / 0 FN / 2 TN，Recall 100.0%，Precision 53.3%，F1 0.696。相对第十九批末尾继续降低 6 个 FP，并保持 0 FN。

## 短期优先级

1. 处理 M1 后续: 本地 `aegis-ai-core/.env` 已删除，但用户仍需要在供应商控制台轮换/废弃旧 API key；AI 不应输出或打包该文件。
2. 继续 M5-M7/M6: sanitizer 作用域/漏洞类型语义、P1 漏报规则 fixture 驱动修复；benchmark、cross-file 与 legacy TypeScript parser 路径已完成，剩余 TypeScript 一致性重点转向真实项目样本验证。
3. 继续以真实靶场指标驱动 DVWA / PHP precision 优化，当前 DVWA 剩余 21 个 FP 主要集中在 XSS、SQLi、Path Traversal 与少量未标注 RCE；避免为了指标压掉 ground truth 未标注但真实可疑的弱点。
4. 收口 legacy 引擎移除计划，保持 LSP 与 CLI 共享核心扫描逻辑。
5. 扩展侧继续验证 scan error、status bar、baseline tree 的端到端体验。

## 当前工作树注意事项

- `git status` 显示 `aegis-ai-core/real_world_targets/body-parser-1.20.0`、`django-3.2`、`express-4.18.1`、`flask-2.3.2` 为未跟踪目录。
- 这些目录看起来是真实项目基准输入，本次 memory-bank 工作不修改它们。
- 后续 AI agent 不应清理、重置或格式化这些目录。
