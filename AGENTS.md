# Agent Instructions

These instructions apply to the whole repository.

## Mandatory Memory Bank Protocol

Before making code changes, read the memory bank in this order:

1. `memory-bank/README.md`
2. `memory-bank/activeContext.md`
3. `memory-bank/progress.md`
4. `memory-bank/projectbrief.md`
5. `memory-bank/systemPatterns.md`
6. `memory-bank/techContext.md`
7. `memory-bank/decisionLog.md`

For product, planning, benchmark, or documentation tasks, also read `memory-bank/productContext.md` and any still-relevant long-term plans under `docs/planning/`.

## Working Rules

- Treat `aegis-ai-core/real_world_targets/*` as read-only benchmark input.
- Do not clean up or reset untracked benchmark target directories unless explicitly asked.
- Prefer AST and taint-analysis fixes over regex-only changes.
- For rule behavior changes, use RED -> GREEN with focused TP/FP fixtures under `aegis-ai-core/tests/rules/`.
- Keep LSP and CLI behavior aligned through shared core logic.
- After meaningful code or planning changes, update the relevant memory-bank document.

## Quality Gates

- Python core: `cd aegis-ai-core && python -m pytest tests/`
- Python lint/format: `cd aegis-ai-core && ruff check src tests && ruff format --check src tests`
- Python type gate: `cd aegis-ai-core && python scripts/typecheck_gate.py --group ci`
- VS Code extension: `cd aegis-vscode && npm run check`
