# M2 didChange 实时诊断规格

IDE 内**编辑时**（不限于保存）也能更新安全诊断，并控制性能与限流。

---

## 1. 目标

- 用户在编辑 JS/TS/Python 时，**输入停止一段时间后**自动更新该文件的 Diagnostic，无需每次保存。
- 同一文档不重复排队：新一次变更会取消上一次未执行的验证（限流）。

---

## 2. 实现（aegis-ai-core/src/lsp/server.py）

| 项 | 说明 |
|----|------|
| **didChange** | 注册 `TEXT_DOCUMENT_DID_CHANGE`；收到变更后不立即扫描，而是启动/重置防抖定时器。 |
| **防抖** | 定时器 0.4 秒（`DEBOUNCE_SECONDS`）；到期后从 `workspace.get_text_document(uri)` 取当前内容并调用 `_validate_document`。 |
| **限流** | 同一 URI 仅保留**最新一次**待执行验证：新 didChange 或 didOpen/didSave 会 `_cancel_pending_validation(uri)` 取消该 URI 的未执行 Timer。 |
| **didOpen/didSave** | 在调用 `_validate_document` 前先 `_cancel_pending_validation(uri)`，避免防抖任务与打开/保存重复执行。 |

---

## 3. 参考

- TDD 12.2 里程碑 M2；
- `server.py` 中 `DEBOUNCE_SECONDS`、`_pending_validation`、`_cancel_pending_validation`、`_debounced_validate`。
