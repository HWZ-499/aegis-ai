# Progress

最后更新: 2026-05-25

## 已完成能力

- 多语言 AST 分析: JS/TS、Python、PHP、Java、Go。
- 污点分析: TaintGraph、Guard Clause、Dominator Tree、source/sink registry。
- LSP 实时诊断与 VS Code / Cursor 扩展集成。
- CLI 扫描、HTML/JSON 报告、SARIF/GitHub Actions 支持。
- AI 修复: DeepSeek、OpenAI、Ollama、custom provider。
- Baseline / suppression: `.aegis-baseline.json` 与 `aegis-ignore`。
- 增量扫描、自定义规则目录、DSL 规则 PoC。
- 真实靶场 benchmark: NodeGoat、DVWA、Django、Flask、Express、body-parser、Java/Go targets。
- 规则测试体系: `tests/rules/<vuln>/<true_positive|false_positive>/`。

## 2026-05-25 外部试用准备

- 本地未跟踪的 `aegis-ai-core/.env` 已删除；该操作只移除本机文件，不会让已经创建的 provider API key 失效，仍需用户去供应商控制台轮换或废弃。
- VS Code extension 版本从 `0.6.0` 升为 `0.6.1`，生成试用包 `aegis-vscode/aegis-ai-security-0.6.1.vsix`，并已发布到 Marketplace: `wen-zai.aegis-ai-security v0.6.1`。
- 打包脚本确认只复制 `aegis-ai-core/pyproject.toml` 与 `aegis-ai-core/src` 到 `resources/aegis-ai-core`，不复制 `.env`。

## 2026-04-28 优化进展

已根据 `CODE_REVIEW_FINDINGS.md` / `PROJECT_OPTIMIZATION_PLAN.md` 完成第一批 P1 安全边界修复:

- 修复 M8: `taintPathWebview` 不再使用 inline handler 拼接 finding 字段，新增 Webview 序列化回归测试。
- 推进 M10: LSP CodeAction 阶段不再调用 AI provider，只返回惰性 preview 命令，用户选择后才生成 AI fix。
- 推进 M9: AI fix preview 应用前校验文档未变化，并修正 line replacement range。
- 推进 M12: baseline entry 打开和删除后的 rescan 都会拒绝 workspace 外路径，新增 path containment 测试。
- 推进 M13: 后端启动敏感配置限制为 application/global 读取；untrusted workspace 不再参与 backend discovery。

本轮验证:

- `cd aegis-ai-core && python -m pytest tests/test_lsp_server.py` -> 58 passed。
- `cd aegis-ai-core && ruff check src/lsp/server.py tests/test_lsp_server.py` -> passed。
- `cd aegis-ai-core && ruff format --check src/lsp/server.py tests/test_lsp_server.py` -> passed。
- `cd aegis-ai-core && python -m pytest tests/` -> 482 passed, 47 deselected, 1 xfailed。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- `cd aegis-ai-core && ruff format --check src tests` -> failed on 34 pre-existing files outside this change set; this round intentionally did not mass-format unrelated modules.
- `cd aegis-vscode && npm run check` -> passed。
- `cd aegis-vscode && npm test` -> 29 passed。测试过程中 VS Code extension host 曾短暂 unresponsive，随后恢复，测试最终通过。

第二批修复:

- 修复 M4: `IncrementalScanner` 非 Git 场景回退为扫描项目发现到的源码文件，不再假干净返回 `{}`。
- 修复 M4: Git 增量扫描包含未跟踪源码文件，覆盖新建漏洞文件未进入 diff 的情况。
- 推进 M3: LSP workspace scan 改为从 workspace root 发现源码文件并扫描未打开文件；异常路径也会发送 scan progress 结束通知，降低扩展进度卡住风险。
- 推进 M10/S4: 删除 LSP 扫描后的后台 AI precache，避免用户未显式请求时调用 AI provider。

第二批验证:

- `cd aegis-ai-core && python -m pytest tests/test_lsp_server.py tests/test_incremental_scanner.py -q` -> 66 passed。
- `cd aegis-ai-core && ruff check src/lsp/server.py src/scanner/incremental_scanner.py tests/test_lsp_server.py tests/test_incremental_scanner.py` -> passed。
- `cd aegis-ai-core && ruff format --check src/lsp/server.py src/scanner/incremental_scanner.py tests/test_lsp_server.py tests/test_incremental_scanner.py` -> passed。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- `cd aegis-ai-core && python -m pytest tests/` -> 486 passed, 47 deselected, 1 xfailed。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-vscode && npm run check` -> passed。

第三批修复:

- 修复 M2: `ProjectScanner.scan_file` 捕获 `OSError` / `UnicodeDecodeError` / `RuntimeError` 时记录结构化 scan error，`get_stats()` 输出 `partial`、`error_count`、`errors`。
- 修复 M2: `RuleEngine._analyze_with` 不再吞掉 analyzer exception，改为抛出 `RuntimeError`，由调用方统一进入 partial scan 路径。
- 修复 M2: CLI JSON / Markdown / HTML / enhanced HTML / SARIF 均显示扫描错误；SARIF `invocations` 标记 `executionSuccessful=false` 并输出 tool execution notifications。
- 修复 M2: CLI 在扫描错误时返回退出码 `2`；`--no-fail-on-findings` 不覆盖扫描失败。
- 修复 M2: Incremental scan stats 同样暴露 partial/error；扫描失败的空结果不会写入缓存。

第三批验证:

- `cd aegis-ai-core && python -m pytest tests/test_project_scanner.py tests/test_report_xss.py tests/test_incremental_scanner.py -q` -> 23 passed。
- `cd aegis-ai-core && ruff check <本轮触碰的 9 个文件>` -> passed。
- `cd aegis-ai-core && ruff format --check <本轮触碰的 9 个文件>` -> passed。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- `cd aegis-ai-core && python -m pytest tests/` -> 491 passed, 47 deselected, 1 xfailed。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-ai-core && ruff format --check src tests` -> failed on 32 pre-existing files outside this change set; this round intentionally did not mass-format unrelated modules.

第四批修复:

- 推进 M7: 修复 Python XSS `HttpResponse(...)` 等响应构造器漏报，新增 `tp_python_httpresponse_request_get.py`。
- 推进 M5/M7: Python XSS 只信任明确 HTML sanitizer，不再把 `urllib.parse.quote(...)` 或任意对象 `.escape(...)` 视为 HTML 输出净化。
- 新增 TP fixture: `tp_python_quote_is_not_html_escape.py`、`tp_python_unrelated_escape_method.py`。
- 规则实现记录 import alias，用于识别 `html.escape` / `markupsafe.escape` / `bleach.clean` 的真实来源，避免同名业务方法误消毒。

第四批验证:

- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "XSS_RISK and python"` -> 5 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "XSS_RISK"` -> 17 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py` -> 119 passed。
- `cd aegis-ai-core && python -m pytest tests/` -> 494 passed, 47 deselected, 1 xfailed。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- `cd aegis-ai-core && ruff format --check <本轮触碰的 4 个文件>` -> passed。
- `cd aegis-ai-core && ruff format --check src tests` -> failed on 32 pre-existing files outside this change set。

第五批修复:

- 推进 M7: PHP XSS 规则移除 `strip_tags` sanitizer 信任，避免把去标签误当成上下文安全 HTML escaping。
- 推进 M7: PHP NoSQL 规则遍历 MongoDB 调用全部参数，修复 update-style 第二参数用户输入漏报。
- 新增 TP fixture: `tp_php_strip_tags_not_escape.php`、`tp_php_mongo_update_second_arg.php`。

第五批验证:

- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "tp_php_strip_tags_not_escape"` -> RED: 1 failed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "tp_php_mongo_update_second_arg"` -> RED: 1 failed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "XSS_RISK and php"` -> 5 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "NOSQL_INJECTION and php"` -> 3 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py` -> 121 passed。
- `cd aegis-ai-core && python -m pytest tests/` -> 496 passed, 47 deselected, 1 xfailed。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- `cd aegis-ai-core && ruff format --check src/analysis/rules/xss/php_ast_rule.py src/analysis/rules/nosql_injection/php_ast_rule.py` -> passed。

第六批修复:

- 推进 M7: Python RCE 规则解析 import alias 和 from-import sink，覆盖 `subprocess as sp`、`from subprocess import run`、`from os import system`。
- 新增 TP fixture: `tp_python_subprocess_alias_run.py`、`tp_python_from_subprocess_run.py`、`tp_python_from_os_system.py`。

第六批验证:

- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "tp_python_subprocess_alias_run or tp_python_from_subprocess_run or tp_python_from_os_system"` -> RED: 3 failed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "RCE_COMMAND_EXEC and python"` -> 7 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py` -> 124 passed。
- `cd aegis-ai-core && python -m pytest tests/` -> 499 passed, 47 deselected, 1 xfailed。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- `cd aegis-ai-core && ruff format --check src/analysis/rules/rce/ast_rule.py` -> passed。

第七批修复:

- 推进 M7: Python NoSQL 规则递归检查 dict/list/tuple/set 与 call 参数中的用户输入，修复 direct query dict 漏报。
- 新增 TP fixture: `tp_pymongo_dict_request_json.py`、`tp_pymongo_where_request_args.py`。

第七批验证:

- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "tp_pymongo_dict_request_json or tp_pymongo_where_request_args"` -> RED: 2 failed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "NOSQL_INJECTION"` -> 18 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py` -> 126 passed。
- `cd aegis-ai-core && python -m pytest tests/` -> 501 passed, 47 deselected, 1 xfailed。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- `cd aegis-ai-core && ruff format --check src/analysis/rules/nosql_injection/python_ast_rule.py` -> passed。

第八批修复:

- 推进 M7: Python 反序列化规则解析 import alias 和 from-import sink，覆盖 `pickle as p`、`from pickle import loads`、`yaml as y`。
- 新增 TP fixture: `tp_pickle_alias_loads.py`、`tp_from_pickle_loads.py`、`tp_yaml_alias_load.py`。

第八批验证:

- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "tp_pickle_alias_loads or tp_from_pickle_loads or tp_yaml_alias_load"` -> RED: 3 failed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "DESERIALIZATION"` -> 13 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py` -> 129 passed。
- `cd aegis-ai-core && python -m pytest tests/` -> 504 passed, 47 deselected, 1 xfailed。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- `cd aegis-ai-core && ruff format --check src/analysis/rules/deserialization/ast_rule.py` -> passed。

第九批修复:

- 推进 M5/M7: Python 反序列化规则识别 `yaml.load(...)` 的显式安全 Loader，`SafeLoader` / `CSafeLoader` 不再触发 DESERIALIZATION finding。
- 新增 FP fixture: `fp_yaml_load_safe_loader_keyword.py`、`fp_yaml_load_safe_loader_positional.py`。
- 保持未指定 Loader 或危险 Loader 的 `yaml.load(...)` 继续作为风险上报。

第九批验证:

- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "fp_yaml_load_safe_loader_keyword or fp_yaml_load_safe_loader_positional"` -> RED: 2 failed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "DESERIALIZATION"` -> 15 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py` -> 131 passed。
- `cd aegis-ai-core && python -m pytest tests/` -> 506 passed, 47 deselected, 1 xfailed。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- `cd aegis-ai-core && ruff format --check src/analysis/rules/deserialization/ast_rule.py` -> passed。

第十批修复:

- 推进 M5/M7: Python Path Traversal 规则移除 `os.path.abspath(...)` / `os.path.realpath(...)` 的完整 sanitizer 信任；路径解析不等于目录边界校验。
- 推进 M7: `send_from_directory(directory, path)` 检查第二个 positional path 参数，并覆盖 `directory` / `path` / `filename` keyword 参数。
- 新增 TP fixture: `tp_python_abspath_realpath_not_sanitizer.py`、`tp_python_send_from_directory_second_arg.py`。

第十批验证:

- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "tp_python_abspath_realpath_not_sanitizer or tp_python_send_from_directory_second_arg"` -> RED: 2 failed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "PATH_TRAVERSAL"` -> 14 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py` -> 133 passed。
- `cd aegis-ai-core && python -m pytest tests/` -> 508 passed, 47 deselected, 1 xfailed。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- `cd aegis-ai-core && ruff format --check src/analysis/rules/path_traversal/ast_rule.py` -> passed。

第十一批修复:

- 推进 M7: Python SQLi 规则识别 `cursor.execute(sql_var, params)` 中已污染的 SQL query 变量；params 只保护 value placeholder，不能保护已拼接进 SQL 文本的动态片段。
- 规则在 `before_file` 预扫描本文件赋值，只把明确由 SQL 关键词 + 用户输入拼接/格式化出来的 query 变量标为 unsafe，避免把正常参数化变量误报。
- 新增 TP fixture: `tp_python_tainted_query_var_with_params.py`。

第十一批验证:

- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "tp_python_tainted_query_var_with_params"` -> RED: 1 failed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "tp_python_tainted_query_var_with_params or fp_python_parameterized"` -> 2 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "SQL_INJECTION"` -> 37 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py` -> 134 passed。
- `cd aegis-ai-core && python -m pytest tests/` -> 509 passed, 47 deselected, 1 xfailed。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- `cd aegis-ai-core && ruff format --check src/analysis/rules/sql_injection/ast_rule.py` -> passed。

第十二批修复:

- 收口 M5/M7 进行中 P1 规则缺口，按 RED -> GREEN 补充 PHP、Go、Java、JS 最小 fixtures。
- PHP: 修复 `allowed_classes => true` 反序列化漏报、`header($location)` 开放重定向变量追踪、`copy/rename` 第二路径参数检查，并让动态 SQL `prepare()` 进入 AST SQLi 判断。
- Go: `filepath.Clean` / `path.Clean` 不再作为完整路径遍历净化器，增加赋值链解析后再判断文件操作 sink。
- Java: class-level field declarations 中的硬编码凭证被检测；新增 Java path second arg、field access password、custom encode XSS fixtures 锁住既有覆盖。
- JavaScript: generic `encode/escape/sanitize` 不再消除 innerHTML XSS；`DOMPurify.sanitize` 继续作为 FP 保护；RCE 覆盖 eval 动态 template string、`const cp = require("child_process")`、`const { exec } = require("child_process")`；NoSQL tainted `_id` 查询不再被 simple-id skip 吞掉；硬编码凭证逐 declarator 检查。

第十二批验证:

- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "<PHP P1 targets>"` -> RED: 3 failed, 1 passed（`prepare()` 动态 SQL 已被既有补充路径检出）。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "<Go P1 targets>"` -> RED: 1 failed, 2 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "<Java P1 targets>"` -> RED: 1 failed, 3 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "<JS P1 targets>"` -> RED: 6 failed, 3 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py` -> 152 passed。
- `cd aegis-ai-core && python -m pytest tests/` -> 527 passed, 47 deselected, 1 xfailed。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- `cd aegis-ai-core && ruff format --check <本轮触碰 Python 文件>` -> passed。
- `cd aegis-ai-core && ruff format --check src tests` -> failed on 21 pre-existing clean tracked files outside this change set; this round intentionally did not mass-format unrelated modules.

第十三批修复:

- 修复 M11: `AIAnalyzer._get_cache_key()` 从漏洞类型 + details 前缀哈希，改为结构化 payload + SHA-256，包含文件、位置、语言、CWE、details 与 `source_code` / `code_context` 哈希。
- 修复 E7: `InlineSuppressor` 新增行级注释提取逻辑，只在简单字符串字面量之外识别 `#` / `//` 注释，避免字符串内容触发 suppression。
- 新增 `tests/test_inline_suppressor.py`，并在 `tests/test_ai_provider.py` 增加 AI cache 隔离回归测试。

第十三批验证:

- `cd aegis-ai-core && python -m pytest -q tests/test_ai_provider.py::TestAiAnalysisCache::test_cache_is_bound_to_file_and_source_context tests/test_inline_suppressor.py` -> RED: 3 failed, 1 passed；最终 GREEN: 20 passed（恢复既有 inline suppressor 测试并追加字符串字面量回归）。
- `cd aegis-ai-core && python -m pytest tests/` -> 531 passed, 47 deselected, 1 xfailed。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- `cd aegis-ai-core && ruff format --check <本轮触碰的 4 个文件>` -> passed。
- `cd aegis-ai-core && ruff format --check src tests` -> failed on 20 historical files outside this change set; this round intentionally did not mass-format unrelated modules.

第十四批修复:

- 清理全量 `ruff format --check src tests` 的 20 个历史格式文件，只做 Ruff 机械排版，不修改 benchmark target 或规则语义。
- 格式化范围: analyzer、legacy/security_rules、部分 JS/PHP/Go AST rules、taint、scanner helper、worker daemon 等 Ruff 报告文件。

第十四批验证:

- `cd aegis-ai-core && ruff format --check src tests` -> 158 files already formatted。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- `cd aegis-ai-core && python -m pytest tests/` -> 531 passed, 47 deselected, 1 xfailed。

第十五批修复:

- 推进 M6: `BenchmarkEngine._analyze_case()` 对 `typescript` / `ts` / `tsx` case 使用 `.ts` / `.tsx` benchmark 文件名，并向共享 JS/TS analyzer 传递 `language="typescript"`。
- 推进 M6: `JavaScriptAnalyzer` 拆分 JavaScript 与 TypeScript parser，`analyze()` 根据规范化语言选择 parser；TypeScript parser 缺失时才回退 JavaScript parser。
- 新增 `tests/test_benchmark_engine_dispatch.py` 回归测试，锁定 TypeScript benchmark dispatch 不再丢失 TS 语境，并锁定 analyzer 对 TypeScript parser 的选择。

第十五批验证:

- `cd aegis-ai-core && python -m pytest -q tests/test_benchmark_engine_dispatch.py::test_run_benchmark_dispatches_typescript_case_with_ts_context` -> RED: failed，`tp == 0` / `fn == 1`。
- `cd aegis-ai-core && python -m pytest -q tests/test_benchmark_engine_dispatch.py::test_run_benchmark_dispatches_typescript_case_with_ts_context tests/test_benchmark_engine_dispatch.py::test_javascript_analyzer_uses_typescript_parser_for_typescript` -> GREEN: 2 passed。
- `cd aegis-ai-core && python -m pytest -q tests/test_benchmark_engine_dispatch.py tests/test_acceptance_benchmark.py` -> 7 passed, 29 deselected。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-ai-core && ruff format --check src tests` -> 158 files already formatted。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- `cd aegis-ai-core && python -m pytest tests/` -> 533 passed, 47 deselected, 1 xfailed。

第十六批修复:

- 继续推进 M6: `CrossFileAnalyzer` 拆分 JavaScript / TypeScript / Python parser 初始化，避免 TypeScript parser 初始化或解析语境依附 JavaScript parser。
- `.ts` / `.tsx` 文件跨文件分析优先使用 TypeScript parser，TypeScript parser 不可用时才回退到 JavaScript parser。
- `scan_project()` 与模块路径解析补齐 `.jsx` / `.tsx`、`index.jsx` / `index.tsx` 候选，保持 JS-family 文件发现和 import resolution 一致。
- 新增 `tests/test_taint_regressions.py` 回归测试，锁定 `.ts` parser dispatch，并验证 TS-only type annotation / interface / import-export 场景能产生正确依赖边。

第十六批验证:

- `cd aegis-ai-core && python -m pytest -q tests/test_taint_regressions.py::test_cross_file_analyzer_uses_typescript_parser_for_ts_files` -> RED: failed，实际调用 `javascript` parser 而不是 `typescript` parser。
- `cd aegis-ai-core && python -m pytest -q tests/test_taint_regressions.py` -> 4 passed。
- `cd aegis-ai-core && python -m pytest -q tests/test_taint_regressions.py tests/test_benchmark_engine_dispatch.py` -> 11 passed。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-ai-core && ruff format --check src tests` -> 158 files already formatted。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- `cd aegis-ai-core && python -m pytest tests/` -> 535 passed, 47 deselected, 1 xfailed。

第十七批修复:

- 收口 M6 legacy 路径: `MultiLanguageASTAnalyzer` 为 TypeScript 单独初始化 parser，并在 `language="typescript"` 或 `.ts` / `.tsx` 文件路径下优先使用 TypeScript parser；TypeScript parser 不可用时才回退 JavaScript parser。
- DVWA/PHP precision: `PhpRCEAstRule` 对 `preg_replace()` 增加 regex `/e` modifier 语义判断，无 `/e` 的普通替换不再作为 RCE finding；保留 `/e` 且参数来自用户输入时的 TP。
- DVWA/PHP precision: `PhpHardcodedCredentialsAstRule` 对 `token` / `auth` / `api_key` / `credential` 类名称要求值为长度足够的 opaque secret，过滤 `userid:2` 等低熵业务载荷；`password` / `secret` 等名称的明文凭证检测不放宽。
- 新增 fixtures: `fp_php_preg_replace_without_eval_modifier.php`、`tp_php_preg_replace_eval_modifier.php`、`fp_php_low_entropy_token_payload.php`、`tp_php_hardcoded_auth_token.php`，以及 legacy TS parser dispatch 回归。

第十七批验证:

- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "preg_replace"` -> RED: 1 failed, 1 passed；修复后 2 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "php_low_entropy_token_payload or php_hardcoded_auth_token"` -> RED: 1 failed, 1 passed；修复后 2 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py` -> 156 passed。
- `cd aegis-ai-core && ruff check src/analysis/rules/rce/php_ast_rule.py src/analysis/rules/hardcoded_credentials/php_ast_rule.py` -> passed。
- `cd aegis-ai-core && ruff format --check src/analysis/rules/rce/php_ast_rule.py src/analysis/rules/hardcoded_credentials/php_ast_rule.py` -> passed。
- `cd aegis-ai-core && python -m pytest tests/` -> 540 passed, 47 deselected, 1 xfailed。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-ai-core && ruff format --check src tests` -> 158 files already formatted。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- 只读 DVWA 分类脚本（`ProjectScanner(..., use_cache=False, use_parallel=False)` + `ground_truth_dvwa.json`）显示 55 findings，24 TP / 31 FP / 0 FN / 1 TN，Precision 43.6%；本轮开始为 58 findings、34 FP。

第十八批修复:

- 继续 DVWA/PHP precision: `JavaScriptRCEAstRule` 移除 `eval(...)` / `Function(...)` 对任意 call expression 参数的未知来源兜底上报，改为只在参数能通过 source/taint 语义证明来自用户输入时上报。
- 保留既有 `eval(code)` / `Function(code)` 标识符兜底行为，避免本轮把 legacy 单元语义扩大为新的规则行为变化。
- 继续 DVWA/PHP precision: `PhpHardcodedCredentialsAstRule` 将低熵占位值 `"password"` 纳入 safe values，过滤 `$password = "password"` 这类测试/默认占位值；强密码样式的硬编码 password 仍作为 TP。
- 新增 fixtures: `fp_js_eval_static_builder_call.js`、`tp_js_eval_builder_req_query.js`、`fp_php_low_entropy_password_placeholder.php`、`tp_php_strong_hardcoded_password.php`。

第十八批验证:

- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "eval_static_builder_call or eval_builder_req_query"` -> RED: FP 失败、TP 通过；修复后 2 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "RCE_COMMAND_EXEC"` -> 24 passed。
- `cd aegis-ai-core && python -m pytest -q tests/test_rules_positive_negative.py -k "RCE"` -> 5 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "php_low_entropy_password_placeholder or php_strong_hardcoded_password"` -> RED: FP 失败、TP 通过；修复后 2 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py -k "HARDCODED_CREDENTIALS"` -> 19 passed。
- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py` -> 160 passed。
- `cd aegis-ai-core && python -m pytest tests/` -> 544 passed, 47 deselected, 1 xfailed。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-ai-core && ruff format --check src tests` -> 158 files already formatted。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- 只读 DVWA 分类脚本（`evaluate_project_against_ground_truth(real_world_targets/dvwa, scripts/data/ground_truth_dvwa.json, engine="new")`）显示 53 findings，24 TP / 29 FP / 0 FN / 1 TN，Recall 100.0%，Precision 45.3%，F1 0.62；相对第十七批末尾继续降低 2 个 FP。

第十九批修复:

- 继续 DVWA/PHP precision: PHP Open Redirect regex 补充层支持 `header("Location: {$location}")` 插值写法，且局部变量只有能追到超全局输入时才上报。
- 继续 DVWA/PHP precision: PHP RCE 对完整四段 `is_numeric($octet[...])` + `sizeof/count($octet) == 4` guard 内重组 IP 后进入 shell sink 的模式降噪；直接使用原始输入或 guard 不完整时仍上报。
- 新增 fixtures: `fp_php_header_location_interpolated_function_param.php`、`tp_php_header_location_interpolated_user_input.php`、`fp_php_shell_exec_numeric_ip_rebuild.php`、`tp_php_shell_exec_incomplete_numeric_guard.php`。

第十九批验证:

- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py` -> 164 passed。
- `cd aegis-ai-core && python -m pytest tests/` -> 548 passed, 47 deselected, 1 xfailed。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-ai-core && ruff format --check src tests` -> 158 files already formatted。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- 只读 DVWA 分类脚本显示 51 findings，24 TP / 27 FP / 0 FN / 2 TN，Recall 100.0%，Precision 47.1%，F1 0.64。

第二十批修复:

- 继续 DVWA/PHP precision: PHP regex XSS 补充层跳过明确 `$html .= "..."` 多行模板字符串内部、且不含 PHP 输入/插值的 JS DOM sink 行；保留 heredoc 中 `document.location` DOM XSS 的检测。
- 继续 DVWA/PHP precision: PHP regex XSS 跳过 `echo $var` 中最近赋值为静态字面量的本地变量输出。
- 继续 DVWA/PHP precision: PHP Path Traversal 规则把 `$_FILES[...]["tmp_name"]` 识别为服务端临时上传路径，并允许随机 basename + 扩展名 allowlist 的上传目标路径；未校验扩展名仍作为 TP。
- 新增 fixtures: `fp_php_embedded_js_innerhtml_without_php_input.php`、`fp_php_echo_static_local_var.php`、`fp_php_randomized_upload_filename_validated_ext.php`、`tp_php_randomized_upload_filename_unvalidated_ext.php`。

第二十批验证:

- `cd aegis-ai-core && python -m pytest -q tests/rules/test_all_rules.py` -> 168 passed。
- `cd aegis-ai-core && python -m pytest tests/` -> 552 passed, 47 deselected, 1 xfailed。
- `cd aegis-ai-core && ruff check src tests` -> passed。
- `cd aegis-ai-core && ruff format --check src tests` -> 158 files already formatted。
- `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci` -> passed。
- 只读 DVWA 分类脚本显示 45 findings，24 TP / 21 FP / 0 FN / 2 TN，Recall 100.0%，Precision 53.3%，F1 0.696。

## 关键指标

根目录 README 当前记录:

| 目标 | 语言 | Recall | Precision | F1 |
|------|------|--------|-----------|----|
| NodeGoat | JavaScript | 100% | 100% | 1.00 |
| django-3.2-core | Python | 92.3% | 92.3% | 0.92 |
| DVWA | PHP | 100% | 53.3% | 0.70 |
| flask-2.3.2 | Python | 66.7% | 50.0% | 0.57 |

已归档的 Round 9 报告记录 DVWA 当前轮末:

| 目标 | Recall | Precision | F1 | TP / FP / FN / TN |
|------|--------|-----------|----|-------------------|
| DVWA Round 9 end | 95.8% | 43.4% | 0.60 | 23 / 30 / 1 / 1 |

已归档的 Round 8 报告记录:

| 目标 | Recall | Precision | F1 |
|------|--------|-----------|----|
| Java demo | 100% | 100% | 1.00 |
| Go go-insecure-web-app | 100% | 100% | 1.00 |

## 当前风险和缺口

- M1 本地文件已处理: `aegis-ai-core/.env` 已删除；仍需用户在供应商侧轮换/废弃旧 API key。
- M5-M7 仍需继续做 benchmark 驱动的 FP/FN 优化；M6 的 benchmark、cross-file 与 legacy TypeScript parser 路径已完成，剩余 TypeScript 一致性集中在真实项目样本验证。
- 全量 `ruff format --check src tests` 已通过；格式债本轮已清理。
- DVWA / PHP precision 当前为 53.3%，FP 仍是优先优化对象，但不能 suppress 掉 ground truth 未标注却真实可疑的弱点。
- Flask benchmark 仍存在配置文件扫描或跨文件场景覆盖不足。
- Cross-file taint 仍应按实验能力处理，默认可信度需要更多 benchmark 支撑。
- Legacy 规则路径仍可能造成认知和维护成本，需要继续推进 v1.5 移除。
- 部分 docs/planning 文档版本较旧，使用时需和 README、memory bank、源码交叉确认。

## 已清理历史文档

2026-04-26 删除以下已完成或已被当前状态覆盖的规划/进度文档:

- 旧测试计划: `TEST_PLAN_v0.3.1.md`, `TEST_PLAN_v0.5.0.md`。
- 已完成总结/技术深度计划: `OPTIMIZATION_SUMMARY.md`, `TECH_DEPTH_PLAN.md`。
- 已完成执行计划: Marketplace bundled backend, scanning capability optimization。
- 已完成阶段/轮次 progress reports: 2026-04-18 到 2026-04-25 的 reports。

## 下一步建议

1. 对 Round 9 剩余 DVWA FP 做分类，优先处理高重复、低风险 source、setup/bootstrap 噪音。
2. 为每个 FP/FN 修复补充最小 fixture，并用 `tests/rules/test_all_rules.py -k ...` 或对应 benchmark dispatch 测试锁定。
3. 将最新 benchmark 结果同步到 `docs/technical/DETECTION_QUALITY.md` 或 `memory-bank/progress.md`。
4. 对 `security_rules.py` legacy 依赖做调用点盘点，形成移除清单。
5. 在扩展侧继续验证 scan error、status bar、baseline tree 的端到端体验。
