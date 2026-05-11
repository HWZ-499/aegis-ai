# AI Coding Workflow

最后更新: 2026-04-26

## 编码前

每次开始 coding 前，AI agent 必须先读取:

1. `memory-bank/README.md`
2. `memory-bank/activeContext.md`
3. `memory-bank/progress.md`
4. `memory-bank/projectbrief.md`
5. `memory-bank/systemPatterns.md`
6. `memory-bank/techContext.md`
7. `memory-bank/decisionLog.md`

然后根据任务类型读取相关源码、测试和 docs:

- 规则修复: 对应 `src/analysis/rules/<vuln>/`、`tests/rules/<vuln>/`、`rule_engine.py`、taint registry。
- LSP 修复: `src/lsp/server.py`、相关 LSP tests、扩展调用点。
- 扩展修复: `aegis-vscode/src/`、`package.json`、`npm run check`。
- benchmark / roadmap: `memory-bank/progress.md` 与仍保留的 `docs/planning/CRITICAL_REVIEW_AND_ROADMAP.md`。

## 编码中

- 先确认现有行为，避免凭印象修改。
- 对规则行为先写 TP/FP fixture，再实现。
- 不修改 `real_world_targets`。
- 不重构无关模块。
- 不清理用户未跟踪目录，除非用户明确要求。
- 对安全相关输出做 hostile data 假设。

## 编码后

按改动范围运行验证:

- 规则改动: targeted `tests/rules/test_all_rules.py -k ...`，然后 full rules suite。
- Core shared path: `python -m pytest tests/`，`ruff check src tests`，类型门禁。
- Extension 改动: `npm run check`，必要时 `npm test`。
- Benchmark 相关: 记录 before / after 指标。

然后更新 memory bank:

- 更新 `activeContext.md`: 当前状态和下一步。
- 更新 `progress.md`: 新指标、完成项、风险。
- 更新 `decisionLog.md`: 长期决策。
