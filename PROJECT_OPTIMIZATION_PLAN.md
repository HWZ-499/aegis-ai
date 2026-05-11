# Aegis AI Project Optimization Plan

生成日期: 2026-04-28

依据: `docs/technical/CODE_REVIEW_FINDINGS.md`、`memory-bank/*`、当前源码与配置文件审查结果。

## 1. 项目当前状态

Aegis AI 当前是一个 local-first SAST 工具，包含 Python 核心扫描引擎和 VS Code/Cursor 扩展两部分。

- Core: `aegis-ai-core`，Python `>=3.10`，当前版本 `1.4.0`。
- Extension: `aegis-vscode`，TypeScript + `vscode-languageclient`，当前版本 `0.6.0`。
- 已支持语言: JavaScript、TypeScript、Python、PHP、Java、Go。
- 已有能力: AST 规则、taint graph、source/sink registry、LSP diagnostics、CLI、SARIF/HTML/JSON 报告、baseline/suppression、增量扫描、AI 修复、RAG 修复建议、VS Code TreeView/Webview。
- 审查覆盖: `aegis-ai-core/src` 和 `aegis-vscode/src` 下 `.py`、`.ts`、`.yaml`、`.yml`，共 131 个核心源文件已完成代码质量阶段检查。
- 当前审查记录: 已记录 117 个问题，其中 P1 50 个、P2 57 个、P3 10 个。

当前项目已经具备完整产品雏形，但安全扫描器最关键的可信度还不稳定: 多处扫描失败会被当作“无发现”，taint/sanitizer 语义存在系统性漏报风险，VS Code 扩展存在若干本地安全边界问题。

## 2. 核心问题总结

| 类别 | 主要问题 | 影响 |
|------|----------|------|
| 扫描可信度 | LSP、ProjectScanner、RuleEngine、多语言 analyzer、DSL engine 多处把异常转换为空 findings | 用户无法区分“代码安全”和“扫描失败” |
| Taint 与 sanitizer | sanitizer 不区分漏洞类型、作用域和真实语义；路径规范化、类型转换、strip_tags 等被过度信任 | 安全扫描器会漏掉真实漏洞 |
| 多语言解析 | TypeScript 多处按 JavaScript 解析；Java/PHP/Go analyzer 异常被吞；worker daemon 只处理 Python/JS | 支持语言名义完整，但结果不一致 |
| 规则正确性 | SQLi、NoSQL、XSS、RCE、路径穿越、反序列化、开放重定向、硬编码凭证规则都有明确 FN/FP | Recall/Precision 指标不稳定，真实项目结果难信任 |
| VS Code 扩展 | Webview inline handler 注入、AI fix range 错误、stale apply、baseline path escape、workspace 配置可影响后端启动 | IDE 侧存在本地执行、文件访问和错误应用风险 |
| AI/RAG | CodeAction 提前调用 AI、AI cache key 缺上下文、RAG timeout 不真正释放、修复建议含危险 API | 代码可能提前外发，修复建议可能不安全 |
| 工程化 | 缓存失效不完整、并行扫描未并行、baseline 损坏被隐藏、安全 lint 全局忽略、测试和 benchmark 覆盖不足 | 维护成本高，CI 难以防回归 |
| 文档与开源 | README/实际行为需要同步，开源包装缺少清晰的风险边界、演示和质量报告 | 对外可信度不足，不利于开源和简历展示 |

## 3. 优化目标

1. 可信扫描: 任何解析、规则、taint、文件读取、LSP 扫描失败都必须可见，不得伪装成 clean result。
2. 规则正确: 优先修复会造成漏报的 P1 问题，再处理高频误报和体验问题。
3. 行为一致: CLI、LSP、VS Code 扩展、daemon 共用核心扫描语义，避免不同入口结果漂移。
4. 安全默认: Webview、baseline、workspace 配置、AI 调用、Docker 部署默认收紧边界。
5. 可回归: 每个规则行为修复都用最小 TP/FP fixture 做 RED -> GREEN。
6. 可发布: README、安装说明、截图、benchmark 报告、SECURITY/CONTRIBUTING 文档与实际项目一致。

## 4. 优化优先级

| 优先级 | 范围 | 原则 |
|--------|------|------|
| P0 | 操作性风险 | 本地真实 API Key、可能导致代码执行或代码外发的入口，先处理再进入大规模修复 |
| P1 | 必须修复 | 会造成假干净结果、真实漏洞漏报、Webview 注入、非预期 AI 调用、路径越界的缺陷 |
| P2 | 工程化优化 | 缓存、并行、baseline、依赖追踪、测试、CI、文档一致性 |
| P3 | 包装与长期建设 | 开源展示、简历包装、演示材料、长期 benchmark 覆盖 |

## 5. 第一阶段：必须修复的问题

目标: 先恢复安全扫描器的基本可信度。此阶段完成前，不建议对外强调“生产可用”。

| ID | 任务 | 对应问题 | 验收标准 |
|----|------|----------|----------|
| M1 | 处理本地真实密钥 | `aegis-ai-core/.env` 中存在真实 `DEEPSEEK_API_KEY` 和 `NVD_API_KEY` | 真实密钥已轮换或废弃；工作区只保留 `.env.example`；后续扫描和文档不输出真实值 |
| M2 | 扫描失败显式上报 | LSP timeout、ProjectScanner 文件读取失败、RuleEngine analyzer 异常、多语言 analyzer parse/taint 异常、Python SyntaxError、DSL 规则加载失败 | CLI/LSP 输出中能区分 `clean`、`partial`、`failed`；异常有日志和文件路径；相关单元测试覆盖失败路径 |
| M3 | 修正 LSP 工作区扫描语义 | Workspace scan 只扫描已打开文档，progress 可挂起 | 工作区扫描按文件发现逻辑扫描未打开文件；失败/超时能结束 progress；有 VS Code 或 LSP 测试覆盖 |
| M4 | 修正增量扫描语义 | 非 Git 项目扫描为空；untracked 文件漏扫 | 非 Git `--incremental` 回退为全量扫描或明确报错；Git 下包含 untracked source；测试覆盖两种场景 |
| M5 | 修正 taint/sanitizer 核心语义 | sanitizer 只按变量名、忽略漏洞类型、路径规范化被当成路径穿越净化器、DataFlowTracker 通用转换被当成 sanitizer | sanitizer 必须包含 category/scope/file/range；路径规范化不再单独消除路径穿越；新增跨作用域和跨漏洞类型回归测试 |
| M6 | 修正 TypeScript 解析路径 | JavaScriptAnalyzer、legacy multi-language、cross-file、benchmark 多处把 TS 当 JS | `.ts/.tsx` 使用 TypeScript grammar 或明确降级策略；新增 TS-only syntax fixture；CLI/LSP/benchmark 行为一致 |
| M7 | 修复 P1 漏报规则 | RCE alias/template、SQL dynamic prepare/params、Path traversal 多参数、NoSQL tainted dict/args、XSS constructors/sanitizer、Deserialization alias/allowed_classes、hardcoded credential fields/declarators | 每个修复至少有 1 个 TP fixture；`python -m pytest -q tests/rules/test_all_rules.py -k <rule>` 通过；不增加已知 FP |
| M8 | 修复 VS Code Webview 注入 | Taint path webview inline handler 使用 HTML escaping 拼 JS string | 不再把 finding 字段拼入 inline JS；改用 data attribute + message passing 或 `JSON.stringify` 安全序列化；Webview 注入测试通过 |
| M9 | 修复 AI fix 应用安全性 | range 计算错误，preview 后文档变化仍应用 | range 使用 VS Code `Range` 正确边界；apply 前校验 document version 或原始文本 hash； stale preview 时拒绝应用并提示 |
| M10 | 禁止 CodeAction 阶段提前调用 AI | CodeAction provider 在展示 lightbulb 时调用 AI | CodeAction 只返回惰性 command；只有用户显式选择 AI fix 才调用 provider；测试确认 codeAction 请求不会触发 AI 请求 |
| M11 | 修复 AI/RAG 安全问题 | AI cache key 缺上下文、RAG timeout 不释放、XSS 建议含 `bypassSecurityTrustHtml` | cache key 包含文件、位置、语言、代码上下文 hash；RAG timeout 不阻塞扫描主流程；移除危险 Angular API 建议 |
| M12 | 收紧 baseline 路径处理 | Baseline tree、删除后 rescan 可访问工作区外路径 | normalize 后验证路径仍在 workspace 内；包含 `..` 的 baseline 条目被拒绝并提示；测试覆盖打开和 rescan 两条路径 |
| M13 | 收紧 VS Code 后端启动配置 | 工作区配置可控制 `pythonPath/serverModule/serverCwd` | 在 untrusted workspace 禁用或要求确认；敏感配置限制为 user/global scope；恶意 `.vscode/settings.json` 不会静默执行任意 Python |

第一阶段完成标志:

- 所有 P1 findings 已有修复 PR 或明确降级理由。
- CLI 和 LSP 不再把 scanner failure 发布为 0 findings。
- VS Code 扩展不再存在已确认的 Webview 注入、路径越界和提前 AI 调用问题。

## 6. 第二阶段：工程化优化

目标: 降低维护成本，建立稳定回归体系，让后续规则优化不会互相破坏。

| ID | 任务 | 对应问题 | 验收标准 |
|----|------|----------|----------|
| E1 | 建立统一扫描结果模型 | 当前失败、部分成功、空 findings 混在一起 | Core 暴露 `ScanResult` 或等价结构，包含 findings、errors、warnings、partial 标记；CLI/LSP 共用 |
| E2 | 统一 analyzer 错误处理 | Python/JS/Java/Go/PHP analyzer 各自吞异常 | 所有 analyzer 通过公共 error collector 上报；规则崩溃不会隐藏为 clean |
| E3 | 收敛 legacy 路径 | `security_rules.py`、deprecated AST analyzer、multi_language_ast 仍影响扫描 | 列出调用点；默认路径不依赖 deprecated scanner；保留兼容层必须有明确开关和测试 |
| E4 | 改善缓存正确性 | cache key 漏 analyzer/DSL/registry/config；baseline corrupt 变空；AI cache 缺上下文 | 缓存 key 覆盖规则、registry、DSL、配置版本；损坏缓存/baseline 报错；测试覆盖缓存失效 |
| E5 | 修复并行扫描实现 | `use_parallel` 分支实际串行 | 并行模式使用 executor；加入性能测试或至少 spy 测试证明并发分发；错误可聚合返回 |
| E6 | 完善依赖与跨文件分析 | Python relative import、export hash 200 行限制、TS cross-file parsing 缺陷 | 相对导入按包目录解析；export hash 覆盖完整 public API；TS import/export fixture 通过 |
| E7 | 改进 suppression 语义 | `aegis-ignore` 字符串字面量也能 suppression | Inline suppressor 只接受注释中的标记；字符串中的标记不会抑制 finding；测试覆盖 |
| E8 | 扩展 benchmark 覆盖 | 内置 benchmark 偏 JS，TP case 缺 source，PHP/Java/Go 缺覆盖 | 每种支持语言至少有 SQLi/XSS/RCE/Path/Deserialization 中的代表 TP/TN；benchmark case 明确 source -> sink |
| E9 | 补齐规则测试 | 大量规则问题目前只有审查记录 | 每个修复项配套 `tests/rules/<vuln>/<true_positive|false_positive>/` fixture；CI 默认运行规则测试 |
| E10 | 收紧 lint/type gate | 安全 lint 全局忽略，类型约束仍宽 | 安全 lint 例外改为 per-file 或带注释白名单；新增代码不允许扩大 `Any`；CI gate 固定 |
| E11 | 整理 worker daemon | daemon 端口不可发现、支持语言假干净 | `--port 0` 输出机器可读端口；daemon 支持与主 scanner 相同语言；非支持语言明确错误 |

第二阶段完成标志:

- `python -m pytest tests/`、`ruff check src tests`、`ruff format --check src tests`、`python scripts/typecheck_gate.py --group ci` 通过。
- `cd aegis-vscode && npm run check` 通过。
- 新增或修复的规则都有 TP/FP fixture。

## 7. 第三阶段：安全增强

目标: 让工具自身符合安全工具的基本防护标准，减少 IDE、本地扫描、AI 调用、容器部署的攻击面。

| ID | 任务 | 对应问题 | 验收标准 |
|----|------|----------|----------|
| S1 | 建立密钥处理规范 | 本地 `.env` 存真实 key，环境变量前缀说明与实现不一致 | `.env.example` 只含占位符；README 明确环境变量；`AEGIS_` 前缀与无前缀行为一致并有测试 |
| S2 | Docker 安全加固 | 镜像以 root 运行，compose 缺少额外限制 | Dockerfile 创建非 root 用户并 `USER` 切换；compose 设置只读根文件系统或最小权限；扫描仍可运行 |
| S3 | Webview 安全基线 | Taint webview 曾启用脚本并拼接 finding data；report webview 要继续防 XSS | 所有 Webview 对 finding/report 数据做结构化序列化；CSP 禁止不必要脚本；新增 webview escaping 测试 |
| S4 | AI 调用隐私边界 | CodeAction 提前 AI、AI provider 默认开启、cache/context 风险 | AI 请求必须由显式用户动作触发；Output channel 记录 provider 但不记录代码/密钥；配置说明包含代码外发风险 |
| S5 | Workspace trust 策略 | 工作区配置可影响后端启动 | VS Code untrusted workspace 下不启动工作区可控 backend；敏感配置变更需用户确认或仅用户级配置生效 |
| S6 | 文件系统边界 | baseline 路径、扫描命令可能访问工作区外文件 | 所有 UI 入口传入路径都 normalize + workspace containment check；越界路径拒绝并记录 |
| S7 | 依赖与供应链 | 依赖范围较宽，打包脚本与 runtime cache stamp 已发现 stale 风险 | 发布前锁定可复现依赖或生成 lock；bundled backend stamp 包含内容 hash；发布包验证不含 `.env`、reports、targets |
| S8 | 安全 CI | 安全 lint 全局忽略、self scan 不应隐藏失败 | CI 中 scanner 自扫失败不能被无条件吞掉；SARIF/HTML 生成失败显式失败或标记 degraded；artifact 不含敏感文件 |

第三阶段完成标志:

- 扩展通过 workspace trust 场景测试。
- Docker 镜像以非 root 运行。
- 发布产物检查确认不包含 `.env`、benchmark targets、reports、cache。
- AI 调用链有明确用户动作、日志和隐私说明。

## 8. 第四阶段：文档与开源包装

目标: 让项目适合开源展示和简历展示，文档不夸大能力，指标可复现。

| ID | 任务 | 对应问题 | 验收标准 |
|----|------|----------|----------|
| D1 | README 与实际能力对齐 | README、历史规划、当前实现存在能力和风险差距 | README 明确当前版本、支持语言、已知限制、AI 隐私边界、质量指标来源 |
| D2 | 新手运行路径 | 本地运行、扩展打包、CLI 使用需要更直接 | 提供 “5 分钟本地运行” 步骤；Core/Extension/Docker 三条路径都能按文档跑通 |
| D3 | 检测质量报告 | benchmark 覆盖和 case 质量不足 | 新增或更新 `docs/technical/DETECTION_QUALITY.md`，列出 target、版本、TP/FP/FN/TN、Recall、Precision、F1、执行命令 |
| D4 | 修复策略文档 | AI 修复、baseline、suppression 易被误解为修复 | 文档明确 baseline/ignore 不是修复；AI fix 需要 preview、apply、rescan；提供安全使用建议 |
| D5 | 开源治理文件 | 开源包装需要清晰贡献和安全披露 | `SECURITY.md`、`CONTRIBUTING.md`、issue templates、PR checklist 存在并与质量门禁一致 |
| D6 | 示例项目和截图 | 缺少截图、GIF、示例数据说明 | 增加 VS Code diagnostics、Findings Tree、AI fix preview、SARIF/HTML report 截图或 GIF；示例不含真实密钥 |
| D7 | 简历项目包装 | 当前亮点分散，问题未沉淀成工程叙事 | 新增一页项目亮点: local-first、AST+taint、多语言、LSP、benchmark、CI、安全边界；不夸大未修复能力 |
| D8 | 发布前 checklist | VSIX/PyPI/Docker 发布前缺少统一检查 | 发布 checklist 覆盖测试、lint、typecheck、npm check、package content audit、secret scan、benchmark smoke |

第四阶段完成标志:

- 从空环境按 README 能完成 CLI 扫描和 VS Code extension 本地运行。
- 文档中所有路径存在，命令可执行，截图/报告与当前 UI 一致。
- 对外展示指标可追溯到具体 target 和命令。

## 9. 总体验收标准

项目优化完成不以“代码改完”为准，而以以下结果为准:

| 维度 | 验收标准 |
|------|----------|
| 扫描可信度 | 任一核心入口出现解析/规则/taint/文件读取错误时，CLI/LSP/VS Code 都能显示错误或 degraded 状态 |
| 安全规则 | P1 漏报类 finding 均有对应 TP fixture；P2 误报类 finding 均有对应 FP fixture |
| 扩展安全 | Webview 不拼接可执行字符串；baseline 和 rescan 路径不能越过 workspace；AI 只在显式请求后调用 |
| AI/RAG | AI cache 与文件上下文绑定；RAG 超时不会阻塞扫描；修复建议不包含已知危险 API |
| 工程质量 | Core 测试、ruff、format、type gate 通过；Extension `npm run check` 通过 |
| 部署安全 | Docker 非 root；发布包不含 `.env`、reports、benchmark targets、cache |
| 文档开源 | README、SECURITY、CONTRIBUTING、检测质量报告、截图/演示全部与当前实现一致 |
| 简历展示 | 能清楚说明问题、架构、指标、工程门禁和真实安全边界，不依赖无法复现的口头描述 |

## 10. 建议执行顺序

1. 先处理 M1、M8、M10、M13: 立即降低密钥、Webview、AI 外发、workspace 执行风险。
2. 再处理 M2、M3、M4: 让 scanner 不再把失败伪装成 clean。
3. 接着处理 M5、M6、M7: 修复核心规则正确性，按漏洞类型逐组 RED -> GREEN。
4. 进入 E1-E11: 统一模型、缓存、并行、测试、CI 和 legacy 收口。
5. 完成 S1-S8: 加固部署、打包、Webview、workspace trust、AI 隐私。
6. 最后做 D1-D8: 对外文档、演示、开源治理和简历包装。
