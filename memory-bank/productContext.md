# Product Context

最后更新: 2026-04-26

## 目标用户

- 日常使用 VS Code / Cursor 的开发者，希望在编码时即时发现安全问题。
- 安全工程师或 AppSec 团队，希望把 SAST 规则、基准测试和 AI 修复接入开发流程。
- 开源项目维护者，希望在 PR 或本地开发阶段减少新增漏洞。

## 主要使用场景

- 打开受支持语言文件，保存或编辑后自动扫描并显示 diagnostics。
- 在命令面板主动扫描当前文件或工作区。
- 在 Findings TreeView 中查看漏洞列表、严重等级和路径。
- 使用 Code Action 预览或应用 AI 修复。
- 对已知可接受风险使用 `.aegis-baseline.json` 或 `aegis-ignore` 抑制。
- 在 CI 中输出 JSON / HTML / SARIF，用于报告、PR 评论或审计。

## 产品原则

- 安全工具必须诚实。如果扫描失败，应让用户看到错误，而不是安静地显示“无问题”。
- 修复与抑制必须清楚区分。Baseline、ignore comment 不是修复代码。
- AI 修复默认应保守，保留预览、置信度、复扫和撤销路径。
- 对外展示的漏洞数据都应视为不可信输入，Webview 和报告必须防 XSS。
- 默认体验应轻量、低摩擦；高级配置放到可选项。

## 用户体验底线

- 扩展启动和扫描失败要有 Output channel 日志。
- Status Bar 应能反映 ready / scanning / issue count / error 等状态。
- 大文件、依赖目录、构建产物、vendor 目录应默认跳过或可配置排除。
- Findings 不应重复刷屏；同一漏洞类型的近行重复应合并或去重。
- 规则误报修复必须用真实 FP fixture 锁住，避免下一轮回归。

## 对外表述

项目对外应强调:

- Local-first SAST。
- AST + taint graph，而不是单纯 regex。
- 多语言覆盖。
- IDE 实时反馈。
- AI-assisted fixes，而不是不可控自动修改。
- 用真实靶场和真实项目持续量化质量。
