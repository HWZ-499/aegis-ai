# Project Brief

最后更新: 2026-04-26

## 项目定位

Aegis AI 是一个 local-first 的实时 SAST 安全扫描工具，面向 VS Code / Cursor 用户，在开发时发现 SQL 注入、NoSQL 注入、XSS、RCE、路径穿越、反序列化、SSRF、开放重定向、硬编码凭证等漏洞，并提供 AI 辅助修复。

项目由两部分组成:

- `aegis-ai-core/`: Python 核心扫描引擎、LSP server、CLI、规则系统、污点分析、AI 修复。
- `aegis-vscode/`: VS Code / Cursor 扩展，负责编辑器集成、诊断展示、命令、TreeView、修复预览和后端启动。

## 核心目标

- 在 IDE 内提供低延迟实时诊断，保存或变更代码后快速反馈安全问题。
- 通过 Tree-sitter AST、污点图和规则引擎降低 regex-only 扫描的误报与漏报。
- 支持 JS/TS、Python、PHP、Java、Go 的多语言漏洞检测。
- 提供 baseline、inline suppression、增量扫描，让用户能把注意力放在新增风险上。
- 通过 DeepSeek / OpenAI / Ollama / custom provider 提供框架感知的 AI 修复建议。
- 用真实项目和靶场指标持续驱动改进，而不是只依赖小样本规则测试。

## 当前范围

已覆盖:

- Python core package `aegis-ai-core` 版本 `1.4.0`。
- VS Code 扩展 `aegis-ai-security` 版本 `0.6.0`。
- CLI: `aegis-scan`。
- LSP: `aegis-lsp` / `src.lsp`。
- 规则测试: `aegis-ai-core/tests/rules/`。
- 真实靶场和项目基准: NodeGoat、DVWA、Django、Flask、Express、body-parser、Java/Go demo targets。

## 非目标

- 不做云端强绑定。默认保持本地优先，AI provider 可选。
- 不把 AI 修复当作无条件自动提交的可信结果。高风险修复应可预览、可回滚、可复扫。
- 不以简单 regex 堆叠替代 AST / taint 的主路径。Regex 只能作为补洞和辅助层。
- 不修改真实靶场源码来提升指标。

## 成功标准

- 真实项目基准指标可复现，报告清晰记录 TP / FP / FN / TN、Recall、Precision、F1。
- 新规则或规则修复必须先有 RED -> GREEN 的 TP/FP 回归用例。
- Python 质量门禁通过: pytest、ruff、类型检查门禁。
- TypeScript 扩展改动通过 `npm run check`，必要时通过扩展测试。
- 用户在 IDE 中能区分“没有问题”和“扫描失败”。
