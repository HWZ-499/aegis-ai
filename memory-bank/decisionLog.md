# Decision Log

最后更新: 2026-05-09

## 2026-05-09 - PHP regex XSS 不扫描无 PHP 输入的模板内 JS DOM sink

决定:

- PHP regex 补充层遇到明确 `$html .= "..."` 多行模板字符串内部的 JS DOM sink 行时，若该行不含 PHP 超全局或 `{$var}` 插值，不再按 PHP XSS 上报。
- heredoc 中的 DOM XSS 仍保留检测，尤其是 `document.location` / querystring 进入 `document.write` 的场景。
- `echo $var` 若 `$var` 最近一次赋值为纯静态字面量或静态拼接，不再按 XSS 上报。

原因:

- Regex 补充层逐行扫描 PHP 多行字符串时，会把模板里纯前端变量如 `user_json.name` 当作 PHP 用户输入，导致 DVWA API 模板类误报。
- 没有 PHP 输入或插值时，regex 层无法证明服务端 XSS；这类前端数据流应由 JS AST/taint 或更明确的跨语言模板分析覆盖。
- 静态本地变量输出不是用户可控输出；继续上报只会制造低价值噪音。

影响:

- 后续如果要检测 PHP 模板内嵌 JS 的真实 DOM XSS，应实现专门的模板抽取 + JS analyzer 路径，而不是依赖 PHP regex 逐行兜底。
- PHP regex XSS 降噪必须保留 ground truth DOM XSS 回归，避免再次压掉 heredoc 中的真实 `document.location` source。

## 2026-05-09 - PHP 上传临时路径与随机 basename 需要区别对待

决定:

- PHP Path Traversal 规则将 `$_FILES[...]["tmp_name"]` 视为服务端生成的上传临时路径，不按用户可控路径遍历上报。
- 用户上传文件名若只进入 `md5` / `sha1` / `hash` / `uniqid` / `bin2hex(random_bytes(...))` 等随机 basename，且拼接的扩展名在 sink 前经过固定 allowlist 校验，则目标路径不按 Path Traversal 上报。
- 随机 basename 但扩展名或路径后缀未校验时，仍保留 Path Traversal finding。

原因:

- PHP upload `tmp_name` 不是客户端提供的目标路径；把它当作路径遍历 source 会误报 `rename($tmp, $safeTarget)` 这类标准上传流程。
- 随机 basename 能切断原始文件名中的目录分隔符；扩展名 allowlist 再约束后缀，二者组合可以证明目标路径不由用户控制目录。

影响:

- 上传路径规则后续应区分 source path、destination path、basename、extension 和 allowlist guard，不能只看是否出现 `$_FILES` 派生变量。
- 未校验扩展名的随机文件名仍可能带入危险后缀或路径片段，相关 TP fixture 需要长期保留。

## 2026-05-07 - JS `eval` call expression 需要 source/taint 证明

决定:

- `eval(...)` / `Function(...)` 参数若是 call expression，不再仅凭“动态调用”兜底上报 RCE。
- 只有参数调用链、成员访问、模板字符串或已有赋值能证明来自用户输入/污染源时，才作为 RCE finding。
- 本轮保留 `eval(code)` / `Function(code)` 标识符参数的既有保守兜底，避免把规则语义变更扩大到未评估路径。

原因:

- `eval(buildBundle("status"))` 这类本地静态 builder 调用可能是坏味道，但不能等同于远程代码执行漏洞。
- DVWA JavaScript high security 样本中的 eval FP 来自静态数据构造；直接按 call expression 上报会削弱 precision。
- `eval(buildCode(req.query.cmd))` 仍应由 source/taint 语义检出，不能用静态 builder FP 修复牺牲真实用户输入路径。

影响:

- 后续 JS RCE 优化应优先增强跨函数/返回值 taint，而不是恢复无来源的动态表达式兜底。
- 若需要报告所有 eval 使用，应作为 code smell 或 policy rule，而不是 `RCE_COMMAND_EXEC` 高风险语义。

## 2026-05-07 - PHP 低熵 `"password"` 视为 hardcoded credential placeholder

决定:

- PHP hardcoded credential 规则将字面值 `"password"` 纳入 safe placeholder values。
- `$password = "password"` 这类测试/默认占位值不再上报硬编码凭证；`$password = "SuperSecretPass123!"` 等强密码形态仍上报。

原因:

- `"password"` 低熵、公开、常用于测试表单或默认占位，不具备真实 secret 形态。
- DVWA `vulnerabilities/sqli/test.php` 的 `$password = "password"` 属于 benchmark 噪音；继续按凭证上报不会提升真实风险检测质量。

影响:

- 后续各语言 hardcoded credential 规则应继续把“变量名敏感”和“值像真实 secret”分开建模。
- 不应把所有弱密码一概 suppress；只有明确 placeholder/test value 才进入 safe set。

## 2026-05-04 - PHP `preg_replace` 只有 `/e` modifier 才属于 RCE sink

决定:

- PHP RCE 规则不再把所有 `preg_replace(...)` 调用都视为代码执行。
- 只有当静态 regex pattern 能证明包含 deprecated `/e` modifier 时，`preg_replace()` 才进入 RCE sink 判断；无 `/e` 的普通替换不按 RCE 上报。

原因:

- 现代 PHP 的 `preg_replace` 不执行 replacement 代码；没有 `/e` modifier 的普通正则替换即使处理用户输入，也不是 RCE。
- DVWA `xss_r/source/high.php` 使用 `preg_replace('/.../i', '', $_GET['name'])` 属于 XSS 过滤逻辑弱点，但不应被 RCE 规则误报。

影响:

- 需要检测用户输入进入 `preg_replace` 的安全问题时，应由 XSS/sanitizer 语义规则覆盖，而不是 RCE sink 兜底。
- 如果后续支持 PHP 版本感知，应继续把 `/e` 判定绑定到 PHP 5 兼容语义或明确降级提示。

## 2026-05-04 - PHP token/auth 类硬编码值需要 opaque secret 形态

决定:

- PHP hardcoded credentials 对变量/常量名中的 `token`、`auth`、`api_key`、`credential` 采用更严格的值形态门槛。
- 这些名称只有在值长度足够且呈 opaque secret/API key 形态时才上报；`userid:2` 这类低熵业务载荷不视为硬编码凭证。
- `password`、`secret`、`private_key` 等明确凭证名称的既有检测不放宽。

原因:

- `token` 在业务代码中也常表示结构化载荷、临时值或响应字段，不等同于密钥。
- 只按名称匹配会在 DVWA cryptography token payload 这类代码中制造高置信误报，同时不提升真实密钥检测质量。

影响:

- 后续各语言 hardcoded credential 规则应逐步区分“名称敏感”和“值像真实 secret”，避免把所有低熵业务字符串当凭证。

## 2026-05-03 - AI 分析缓存必须绑定代码上下文

决定:

- `AIAnalyzer` 缓存 key 必须包含文件、位置、语言、漏洞类型、CWE、details 和代码上下文哈希。
- 同一漏洞描述出现在不同文件或不同源码上下文时，不得复用之前的 AI 分析或修复结果。

原因:

- AI 修复输出依赖文件、行号、语言、框架和局部代码；只按漏洞类型和 details 前缀缓存会把不相关修复套到另一个 finding 上。

影响:

- 后续新增 AI/RAG 缓存也必须把代码上下文作为 key 的一部分，只能缓存结构化哈希，不记录原始代码或密钥。

## 2026-05-03 - Inline suppression 只接受真实注释

决定:

- `aegis-ignore` 只在行注释中生效；字符串字面量里的 `# aegis-ignore` 或 `// aegis-ignore` 不应抑制 finding。
- 上一行独立注释抑制下一行、行内注释抑制当前行的既有语义保留。

原因:

- 扫描目标源码可以自然包含这些字符串，甚至攻击者可控字符串也可能包含 suppression marker；把字符串内容当注释会制造假阴性。

影响:

- 后续扩展 suppression 语法时必须先确认 marker 位于注释 token 中，不能直接对原始行文本做全行 regex。

## 2026-05-03 - 跨语言 sanitizer / safe API 必须证明当前漏洞语义

决定:

- JS XSS 不再把通用 `encode()`、`escape()`、本地 `sanitize()` 或任意对象方法名当作 HTML sanitizer；只信任 `DOMPurify.sanitize()` 和明确 HTML escaping helper。
- Go Path Traversal 不再把 `filepath.Clean()` / `path.Clean()` 当作完整 sanitizer；路径规范化不能替代安全根目录约束。
- PHP 反序列化中 `allowed_classes => true` 不视为安全；只有 `false` 或明确数组 allowlist 能降低风险。

原因:

- sanitizer 是否有效取决于漏洞类型和输出/执行上下文；同名函数、路径规范化、或宽松选项不能证明风险已被消除。
- 这些误判会直接造成 P1 假阴性，比保守报告更危险。

影响:

- 后续 safe API / sanitizer 扩展必须写出语义条件和 FP fixture，不能只把函数名加入全局 allowlist。
- 规则应优先检查参数语义、对象来源、赋值链和 taint 状态。

## 2026-05-03 - 单键 ID 查询只有在未污染时才可作为 NoSQL FP 降噪

决定:

- JS NoSQL `findOne({ _id: id })` / `find({ id })` 的 simple-id skip 需要检查 `id` 是否已被 taint graph 标记为用户输入。
- tainted id 不再被 simple-id 降噪逻辑吞掉；本地常量 id 继续作为 FP 保护。

原因:

- 单键 id 查询本身很常见，但当 id 来自 `req.query` / `req.body` 且未验证时仍是用户可控查询输入。
- 先做宽泛 skip 会隐藏真实认证绕过或查询注入入口。

影响:

- NoSQL 降噪逻辑必须结合 taint 状态，不应只看 query shape。
- 新增 `tp_js_findone_tainted_id.js` 与 `fp_js_findone_constant_id.js` 作为回归保护。

## 2026-04-30 - SQL 参数化只保护参数值，不保护已污染查询文本

决定:

- Python SQLi 规则不再把所有 `cursor.execute(sql_var, params)` 形式直接视为安全。
- 只有当 `sql_var` 没有在本文件中被识别为“SQL 关键词 + 用户输入拼接/格式化”的 unsafe query variable 时，变量查询加 params 才按参数化查询跳过。

原因:

- `params` 只能绑定 SQL value placeholder；如果用户输入已经进入表名、列名、排序、WHERE 片段等 SQL 文本，仍然存在注入风险。
- 单纯使用 taint graph 的 `is_var_tainted(sql)` 会误伤普通 `sql = "SELECT ..."` 变量，因此需要用本规则的结构化赋值预扫描缩小范围。

影响:

- 后续 SQLi 参数化判断必须区分“值参数化”与“查询文本动态拼接”，不能只看 execute 是否有第二个参数。
- 对正常常量 SQL 变量加参数的写法继续保留 FP 保护。

## 2026-04-30 - Python 路径解析不等于路径遍历净化

决定:

- Python Path Traversal 规则不再把 `os.path.abspath(...)` / `os.path.realpath(...)` 当作完整 sanitizer。
- `send_from_directory(directory, path)` 同时检查目录参数、第二个 path/filename 参数和相关 keyword 参数。

原因:

- 绝对路径解析和符号链接解析只能改变路径形态，不能证明结果仍在允许目录内；缺少白名单目录校验时仍可能发生路径遍历。
- Flask `send_from_directory` 的常见攻击入口是第二个 filename/path 参数，只检查第一个 directory 参数会漏掉真实下载接口风险。

影响:

- 后续 Path Traversal sanitizer 只有在能证明限制到安全文件名或安全目录边界时才应消除 finding。
- 针对多参数文件 API 的规则应按 API 签名检查所有可能承载路径的参数。

## 2026-04-30 - Python yaml.load 安全 Loader 不应上报反序列化风险

决定:

- Python 反序列化规则对 `yaml.load(...)` 检查 `Loader=` keyword 和第二个 positional Loader 参数。
- 当 Loader 明确解析为 `SafeLoader` 或 `CSafeLoader` 时跳过 DESERIALIZATION finding；未指定 Loader 或无法证明安全的 Loader 仍保留 finding。

原因:

- PyYAML 的 `yaml.load` 风险取决于 Loader；把显式 `SafeLoader` / `CSafeLoader` 的调用也当作漏洞会制造高置信误报。
- 只豁免明确安全 Loader，能降低误报，同时避免把未知业务变量或危险 Loader 误当安全。

影响:

- 后续 sanitizer / safe API 判断应优先检查语义参数，而不是只按函数名做全局危险或全局安全判定。
- 反序列化规则继续保留 `yaml.safe_load(...)` 等安全 API 的 FP 保护，并新增 `yaml.load(..., SafeLoader)` 保护。

## 2026-04-30 - Python 反序列化 sink 识别必须解析 import alias

决定:

- Python 反序列化规则在文件级预扫描中记录 `import ... as ...` 和 `from ... import ...` 映射。
- `pickle.loads(...)`、`yaml.load(...)`、`jsonpickle.decode(...)` 等 sink 的识别基于解析后的限定名，而不是只匹配源码中直写的模块名。

原因:

- `import pickle as p`、`from pickle import loads`、`import yaml as y` 是常见写法；只匹配直写模块名会造成真实反序列化漏报。
- alias 解析可以覆盖常见导入风格，同时避免把没有危险模块导入来源的本地 `loads(...)` 误识别为 sink。

影响:

- 后续 Python sink 类规则应优先沉淀共享 import alias 解析模式，避免每条规则重复实现或扩大裸函数名匹配。

## 2026-04-30 - Python NoSQL 查询参数必须递归检查结构化值

决定:

- Python NoSQL 规则在判断 MongoDB 查询参数是否包含用户输入时，递归检查 `dict`、`list`、`tuple`、`set` 和 call 参数。
- 直接传入的查询 document 如 `{"name": request.json["name"]}`、`{"$where": request.args["q"]}` 应被识别为 NoSQL injection 风险。

原因:

- Pymongo/Motor 的危险输入通常嵌在查询 document 或 update document 的值里；只检查顶层节点会漏掉最常见的直接查询写法。
- `$where`、`$regex` 等操作符值来自请求输入时风险更高，不能依赖变量赋值路径才被发现。

影响:

- 后续 NoSQL 规则扩展应优先按结构化 AST 递归检查 query/update/operator document，避免退回字符串 regex。
- ObjectId 和 literal false-positive fixture 需要继续保留，防止递归检查变成宽泛误报。

## 2026-04-30 - Python RCE sink 识别必须解析 import alias

决定:

- Python RCE 规则在文件级预扫描中记录 `import ... as ...` 和 `from ... import ...` 映射。
- `subprocess.run(...)`、`os.system(...)` 等 sink 的识别基于解析后的限定名，而不是只匹配源码中直写的模块名。

原因:

- `import subprocess as sp`、`from subprocess import run`、`from os import system` 是 Python 项目中的常见写法；只匹配 `subprocess.run` / `os.system` 会造成真实命令执行漏报。
- alias 解析后仍能避免把普通业务函数 `run(...)` 或 `system(...)` 当成 RCE sink，前提是它们没有对应危险模块导入。

影响:

- 后续 Python 规则遇到标准库或框架 sink 时，应优先解析 import alias，而不是扩大裸函数名 allow/deny list。

## 2026-04-30 - PHP 输出与 MongoDB 参数规则必须覆盖真实风险位置

决定:

- PHP XSS 规则不把 `strip_tags(...)` 视为 HTML 输出 sanitizer；只有明确做 HTML escaping 的 `htmlspecialchars(...)` / `htmlentities(...)` 能消除当前 PHP echo/print XSS finding。
- PHP NoSQL 规则检查 MongoDB 方法调用的全部参数；update document、options 等非第一个参数中的用户输入也应触发 finding。

原因:

- 去标签不是上下文安全 HTML 转义，不能阻止全部 XSS 输出风险。
- MongoDB update-style API 的危险数据常在第二个参数，单看 filter 会造成真实漏报。

影响:

- 后续 PHP sanitizer 扩展必须证明其输出上下文安全，不能只按“看起来像清洗函数”的名称加入。
- NoSQL 规则新增语言或 API 变体时，应按方法签名检查所有可能承载 query/update/operator document 的参数。

## 2026-04-28 - XSS sanitizer 必须绑定 HTML 输出语义

决定:

- Python XSS 规则只把明确来源的 HTML sanitizer 视为可消除 HTML 输出风险，例如 `html.escape`、`markupsafe.escape`、`bleach.clean`。
- URL quoting、RCE/path sanitizer、数值/字符串转换、任意同名 `.escape()` 不能自动消除 XSS finding。
- 响应构造器如 `HttpResponse(...)` 和 `make_response(...)` 属于直接输出 sink，需要检查其参数。

原因:

- sanitizer 是否有效取决于漏洞类型和输出上下文；URL 编码或业务方法名不能证明 HTML response 安全。
- Django/Flask 响应构造器是常见直接输出路径，漏掉它会造成真实 XSS 假阴性。

影响:

- 后续扩展 sanitizer 时必须标明适用漏洞类型和上下文，不得只按函数名或方法名泛化。
- XSS 相关 FP 修复应优先添加明确 HTML sanitizer fixture，而不是扩大 sanitizer 名称集合。

## 2026-04-28 - 扫描失败必须显式成为 partial result

决定:

- ProjectScanner、IncrementalScanner、CLI 和报告生成器统一暴露 `partial`、`error_count`、`errors`。
- analyzer failure 不得在 RuleEngine 中被吞掉并返回空列表；必须抛出并进入扫描错误路径。
- 有扫描错误时 CLI 返回退出码 `2`，即使设置了 `--no-fail-on-findings`。
- 失败扫描结果不得缓存为 clean/empty result。

原因:

- SAST 的“0 findings”只有在扫描完整成功时才可信；文件读取、解析器或 analyzer 失败时展示 clean 会造成假阴性。
- CI 和 SARIF 消费方需要机器可读状态区分 clean、findings、partial scan。

影响:

- 报告消费者需要读取 summary 中的 `partial/error_count`，SARIF 消费方可检查 invocation notifications。
- 后续新增 analyzer 或扫描路径必须把失败接入同一套 partial scan stats，不得局部吞异常。

## 2026-04-28 - 增量扫描不得把“不知道变更集”当作干净

决定:

- 非 Git 项目运行 incremental scan 时，回退为扫描项目发现到的所有源码文件。
- Git incremental scan 必须包含未跟踪源码文件。

原因:

- 安全扫描器不能把“无法从 Git diff 判断变更”或“新文件尚未加入 Git”展示为 0 findings。
- 新建漏洞文件是 PR/本地开发中的常见风险来源，必须纳入 incremental 扫描。

影响:

- 非 Git 项目的 incremental 模式会比之前更慢，但结果语义更诚实。
- 后续 diff-only / incremental 优化应继续优先保证不漏扫新增源码文件。

## 2026-04-28 - Workspace Scan 以文件发现为准

决定:

- LSP `aegis/requestScanWorkspace` 通过 workspace root 发现源码文件，不再只遍历已打开文档。
- workspace root 在 LSP initialize 时始终记录，不依赖 experimental cross-file analysis 是否启用。

原因:

- “Scan Workspace” 的用户语义是扫描工作区文件；只扫描已打开文档会产生假覆盖。
- 扩展进度条依赖 scan progress 结束通知，失败路径也必须能结束。

影响:

- 未打开文件也会收到 publishDiagnostics。
- 后续 workspace scan 相关改动应复用项目文件发现语义，避免 LSP/CLI 覆盖范围继续分叉。

## 2026-04-28 - AI 修复必须由用户显式触发

决定:

- LSP CodeAction 阶段只能返回惰性 `aegisAI.previewFix` command，不得实例化或调用 AI provider。
- 真正的 AI provider 调用只允许在用户选择 preview/apply 修复流程后，通过 `aegis/generateFix` 发生。
- 扫描完成后不得后台预缓存 AI 修复结果。

原因:

- VS Code 可能为展示 lightbulb 自动请求 CodeAction；如果此时调用 AI，会在用户未明确同意时把代码上下文发给 provider。
- AI 修复属于潜在代码外发和代码替换路径，必须保留显式动作、预览和 stale apply 校验。

影响:

- CodeAction 菜单仍能展示 AI preview 入口，但展示菜单本身不触发网络/AI 请求。
- 后续新增 AI 相关 CodeAction 必须遵守同样的惰性触发模式。

## 2026-04-28 - VS Code 本地文件和后端启动边界收紧

决定:

- Baseline entry 中的文件路径在 TreeView open 和删除后 rescan 前都必须 normalize，并确认仍位于 workspace 内。
- `aegisAI.pythonPath`、`aegisAI.serverModule`、`aegisAI.serverCwd` 作为后端启动敏感配置，只按 application/global/default 读取，不接受 workspace 覆盖。
- untrusted workspace 下禁用基于 workspace folders 的 backend discovery。

原因:

- `.aegis-baseline.json` 是工作区文件，不能让其中的 `..` 或绝对路径驱动扩展打开/扫描工作区外文件。
- 工作区设置可被仓库提交，如果直接控制 Python 可执行文件、模块或 cwd，会把“打开项目”变成潜在本地执行入口。

影响:

- 本地开发如需自定义 backend，应在用户级设置或开发环境中配置，而不是依赖仓库内 `.vscode/settings.json`。
- 后续新增任何从工作区文件读取路径并打开/扫描的 UI 入口，都必须复用 workspace containment 检查。

## 2026-04-26 - 建立 memory bank 作为 AI 编程入口

决定:

- 在根目录创建 `memory-bank/`，作为后续 AI 编程的第一阅读入口。
- 新增 `AGENTS.md` 并更新 `.cursorrules`，让 Codex / Cursor 类工具在编码前读取 memory bank。

原因:

- 项目已有大量规划和进度文档，但分散在 `docs/planning`、`docs/superpowers`、README、源码中。
- AI agent 如果直接读源码，容易忽略当前阶段目标、历史指标和不能触碰的 benchmark target。
- Memory bank 用摘要层降低启动成本，同时保留指向权威文档的路径。

影响:

- 未来代码改动后，需要同步维护 `activeContext.md`、`progress.md` 或 `decisionLog.md`。
- 旧路线图不再单独作为最新状态来源，必须结合最新 report 和源码。

## 2026-04-26 - 真实靶场目录视为只读

决定:

- `aegis-ai-core/real_world_targets/*` 作为 benchmark 输入，默认只读。
- 后续 AI agent 不应格式化、修复、重命名或清理这些目录。

原因:

- 修改靶场源码会污染 benchmark 指标。
- 当前工作树中多个 target 目录是未跟踪状态，不能把它们误当成待清理垃圾。

## 2026-04-26 - 规则改动采用 RED -> GREEN 流程

决定:

- 每个漏洞规则修复必须先有失败用例或明确 benchmark root cause。
- 优先在 `tests/rules/<vuln>/<true_positive|false_positive>/` 增加最小 fixture。

原因:

- 项目主要风险不是“代码写不出来”，而是修一个 FN 又制造 FP，或修一个语言破坏另一个语言。
- fixture 驱动能让后续 AI agent 继续安全迭代。

## 2026-04-26 - AST/Taint 为主，Regex 为辅助

决定:

- 规则主路径优先依赖 AST、taint graph、source/sink registry。
- Regex supplemental finding 只能用于补洞，并且必须和 AST 结果去重。

原因:

- 项目定位强调 AST + taint，不应退化为 regex-only scanner。
- Round 9 已经证明 regex duplicate 会明显抬高 FP。

## 2026-04-26 - 清理已完成规划和进度文档

决定:

- 删除旧测试计划、技术深度计划、已完成执行计划和阶段/轮次 progress reports。
- 保留仍含未完成长期事项的规划文档，例如 `CRITICAL_REVIEW_AND_ROADMAP.md`、`NEXT_OPTIMIZATION_DIRECTIONS.md`、`OPTIMIZATION_ROADMAP.md`、`PROMOTION_STRATEGY.md`。
- 把已删除文档中的关键进度和指标保留在 `memory-bank/progress.md`。

原因:

- 已完成文档继续保留会误导后续 AI agent，把旧版本目标当成当前目标。
- Memory bank 已承担当前状态入口职责，历史执行日志不再需要作为启动必读材料。
