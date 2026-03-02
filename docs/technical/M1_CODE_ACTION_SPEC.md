# M1 Code Action 规格与实现拆解（TDD P0）

IDE 内「获取修复建议」与「应用建议」闭环。本文给出接口约定与实现步骤，供下一迭代实现。

---

## 1. 目标

- 用户在 IDE 中看到 Aegis 的 Diagnostic（波浪线）时，能通过 **Code Action**：
  - **获取修复建议**：展示 RAG/内置的修复说明与参考链接；
  - **应用建议**（可选）：插入示例代码或替换为安全写法。

---

## 2. LSP 侧接口

### 2.1 能力声明

- 在 `initialize` 的 `result.capabilities` 中声明：
  - `codeActionProvider: true` 或 `CodeActionOptions`（如 `resolveProvider: true` 若用懒解析）。

### 2.2 请求

- **textDocument/codeAction**（或 **codeAction/resolve**）：
  - 入参：`TextDocumentIdentifier`、`Range`、`CodeActionContext`（含当前文档的 `diagnostics[]`）。
  - 只对 **context.diagnostics** 中 `source === "Aegis AI"` 的 diagnostic 提供 Code Action；其它忽略。

### 2.3 返回

- 返回 `CodeAction[]`，每项至少包含：
  - `title`: 展示文案，如「获取修复建议（Aegis）」或「应用参数化查询示例」；
  - `kind`: 建议 `CodeActionKind.QuickFix`；
  - `diagnostics`: 关联的 diagnostic（用于定位）；
  - （可选）`edit`: `WorkspaceEdit`，对当前文档做文本插入/替换，实现「应用建议」；
  - （可选）`command`: 若用 command 触发后续逻辑（如调 AI），可在此指定。

---

## 3. 数据流

1. 用户对某行 Diagnostic 触发 Quick Fix / Code Action 菜单。
2. IDE 发送 `textDocument/codeAction`，带上该文档的 range 与 context.diagnostics。
3. Server 根据 diagnostic 的 `code`（如 `NOSQL_INJECTION`）与 `range`：
   - 从 **BUILTIN_REMEDIATION**（或 RAG）取修复建议文案与参考链接；
   - 构造 1～2 个 Code Action：一个「仅展示建议」、一个「应用示例」（若可行）。
4. IDE 展示菜单；用户选择「获取修复建议」则展示说明（或打开侧栏），选择「应用示例」则执行 `edit`。

---

## 4. 实现拆解（aegis-ai-core）

| 步骤 | 内容 | 说明 |
|------|------|------|
| 4.1 | 在 `server.py` 中注册 `code_action` 处理器 | ✅ 使用 pygls 的 `@server.feature(TEXT_DOCUMENT_CODE_ACTION, CodeActionOptions)`，从 context 中过滤 `source == "Aegis AI"` 的 diagnostic。 |
| 4.2 | 实现 `_get_remediation_for_rule(rule_id: str)` | ✅ 复用 `scanner/rag_enhancer.BUILTIN_REMEDIATION`，返回 { description, remediation[], references[], cwe }。 |
| 4.3 | 构造「插入修复建议」Code Action | ✅ 提供一项 Quick Fix：**「Aegis: 插入修复建议注释（{rule_id}）」**，对当前文档在 diagnostic 所在行首插入多行注释（描述 + 建议 + 参考链接）。 |
| 4.4 | （可选）构造「应用示例」Code Action | ✅ 若规则有 `suggested_code`，增加 Quick Fix「Aegis: 应用示例代码（{rule_id}）」；在诊断行首插入 `suggested_code` 片段。 |
| 4.5 | 单测 | ✅ `TestCodeActionRemediation` 覆盖 `_get_remediation_for_rule` 与 `_remediation_to_comment_text`。 |
| 4.6 | 悬停展示建议修复代码 | ✅ `BUILTIN_REMEDIATION` 支持可选 `suggested_code`；`finding_to_diagnostic` 将「修复建议」与「建议修复代码」一并写入 Diagnostic.message，悬停即可见。 |

---

## 5. 扩展侧（aegis-vscode，可选）

- 若 Code Action 的「展示建议」用 command 实现：在扩展里注册 command，收到后打开 Webview 或侧栏面板展示 RAG/内置建议。
- 若仅用 LSP 的 `edit`：无需扩展改动，IDE 会直接应用 `WorkspaceEdit`。

---

## 6. 参考

- TDD 7.3.1（AI 修复同步、初期用上下文锚点）；
- TDD 12.1 / 12.2（P0、M1）；
- `aegis-ai-core/src/scanner/rag_enhancer.py`：`BUILTIN_REMEDIATION` 结构。
