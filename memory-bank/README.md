# Aegis AI Memory Bank

最后更新: 2026-04-26

这个目录是 Aegis AI 后续 AI 编程的项目记忆入口。任何 AI agent 在开始修改代码前，都必须先阅读这里的核心文档，再进入源码。

## 必读顺序

1. `memory-bank/README.md` - 入口、规则、文档地图。
2. `memory-bank/activeContext.md` - 当前工作重点、最新上下文、短期优先级。
3. `memory-bank/progress.md` - 已完成内容、指标、未完成风险。
4. `memory-bank/projectbrief.md` - 项目目标、范围、成功标准。
5. `memory-bank/systemPatterns.md` - 架构、模块边界、实现模式。
6. `memory-bank/techContext.md` - 技术栈、命令、质量门禁。
7. `memory-bank/decisionLog.md` - 长期决策与原因。

当任务涉及产品体验、路线图或对外文档时，同时阅读:

- `memory-bank/productContext.md`
- `docs/planning/CRITICAL_REVIEW_AND_ROADMAP.md`
- `memory-bank/progress.md` 中保留的最新指标摘要

## 文档职责

| 文件 | 作用 |
|------|------|
| `projectbrief.md` | 项目定位、核心目标、非目标、成功标准 |
| `productContext.md` | 用户画像、使用场景、产品体验原则 |
| `systemPatterns.md` | 架构图、模块分层、代码组织和设计约束 |
| `techContext.md` | 技术栈、环境、常用命令、质量门禁 |
| `activeContext.md` | 当前状态、短期重点、最近工作上下文 |
| `progress.md` | 阶段进展、指标、风险和下一步 |
| `decisionLog.md` | 已确认的工程决策，避免重复争论 |
| `ai-workflow.md` | 每次 AI 编程前、中、后的操作流程 |

## 信息优先级

当文档之间出现冲突时，按以下顺序判断:

1. 当前源码和测试结果。
2. `memory-bank/activeContext.md` 与 `memory-bank/progress.md`。
3. 根目录 `README.md`、`CONTRIBUTING.md`、`SECURITY.md`。
4. `docs/planning/` 中仍保留的长期计划。

旧路线图中可能保留历史版本号和未完成的长期事项。遇到冲突时，优先相信 memory bank 和当前源码。

## 文档清理记录

2026-04-26 已删除已完成或已被 memory bank 覆盖的历史计划/进度文档，包括旧测试计划、技术深度计划、Marketplace bundled backend 执行计划、扫描能力优化执行计划和阶段/轮次 progress reports。后续项目状态以本目录为入口。

## 维护规则

- 每次完成实质性代码改动后，更新 `activeContext.md` 的当前状态。
- 若影响指标、测试覆盖、路线图或风险，更新 `progress.md`。
- 若做出长期架构、产品或流程决策，更新 `decisionLog.md`。
- 不要把大段临时调试日志写入 memory bank，只记录能帮助下一次 AI 编程继续推进的信息。
- 不要修改 `aegis-ai-core/real_world_targets/*`，它们是基准靶场输入，应视为只读。
