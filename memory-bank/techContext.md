# Technical Context

最后更新: 2026-04-26

## 环境和版本

- Python: `>=3.10`。
- Core package: `aegis-ai-core` `1.4.0`。
- VS Code extension: `aegis-ai-security` `0.6.1`。
- TypeScript: `^5.3.0`。
- VS Code engine: `^1.75.0`。
- 主要 Python 依赖: `pydantic`, `pydantic-settings`, `python-dotenv`, `tree-sitter==0.21.3`, `tree-sitter-languages`, `pygls`, `lsprotocol`, `pyyaml`。
- 可选 AI/RAG 依赖: `openai`, `chromadb`, `sentence-transformers`, `scikit-learn`。

## 目录要点

| 路径 | 说明 |
|------|------|
| `aegis-ai-core/src/analysis/` | 静态分析、规则引擎、AST、taint、DSL |
| `aegis-ai-core/src/scanner/` | CLI、project scanner、baseline、AI analyzer、report |
| `aegis-ai-core/src/lsp/` | pygls LSP server |
| `aegis-ai-core/tests/` | pytest 测试 |
| `aegis-ai-core/tests/rules/` | TP/FP fixture 驱动的规则测试 |
| `aegis-vscode/src/` | VS Code extension TypeScript 源码 |
| `docs/planning/` | 长期规划和历史路线图 |
| `docs/superpowers/` | 少量保留的规格文档；已完成的阶段计划和进度报告已清理 |
| `memory-bank/` | AI 编程前必须读取的项目记忆 |

## Core 开发命令

```powershell
cd aegis-ai-core
pip install -e .[dev]
```

默认回归:

```powershell
cd aegis-ai-core
python -m pytest tests/
```

规则专项:

```powershell
cd aegis-ai-core
python -m pytest -q tests/rules/test_all_rules.py
python -m pytest -q tests/rules/test_all_rules.py -k "SQL_INJECTION and php"
```

质量门禁:

```powershell
cd aegis-ai-core
ruff check src tests
ruff format --check src tests
python scripts/typecheck_gate.py --group ci
```

CLI 扫描:

```powershell
cd aegis-ai-core
python -m src.scanner.cli <target-path> --format json
python -m src.scanner.cli <target-path> --format html --output report.html
python -m src.scanner.cli . --incremental --format json
```

## VS Code extension 命令

```powershell
cd aegis-vscode
npm run check
npm test
npm run bundle
npm run package
```

## 编码规则

- Python 函数新增或重写时应带类型标注。
- 生产路径不要使用 `print()`，使用 logger。
- 不硬编码密钥，使用环境变量或配置。
- 对用户输入、API 响应、finding details、Webview HTML 做边界校验或转义。
- TypeScript 不引入 `any`，优先定义接口。
- 修改规则必须同时考虑 TP 和 FP。
- 修改扩展后至少运行 `npm run check`。

## 已知约束

- `tree-sitter==0.21.3` 可能有 `FutureWarning`，当前入口已过滤。
- `.venv/`, `node_modules/`, `.vscode-test/`, `out/`, `dist/`, benchmark target 目录不应纳入常规代码搜索和修改。
- `real_world_targets` 目录可能含外部项目源码，不要把它当成 Aegis 源码重构。
