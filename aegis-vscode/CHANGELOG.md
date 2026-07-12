# Aegis AI Security Scanner changelog

## 0.6.7

- Promotes the extension from Marketplace Preview to the stable channel.
- Bundles the local Aegis backend and bootstraps it in a managed Python 3.10–3.12
  environment.
- Shows scan failures, workspace progress, baseline findings, taint paths, and
  AI remediation actions in the editor.
- Rejects unsupported Python runtimes before environment creation and verifies
  the bundled-backend fingerprint before reuse.
- Uses the component-scoped release tag `vscode-v0.6.7` for VSIX packaging.
- Excludes local test/type/lint caches and rejects forbidden content before a
  VSIX artifact is uploaded.

Marketplace publication and wider distribution remain tracked under O9.
