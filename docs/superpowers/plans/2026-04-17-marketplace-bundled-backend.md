# Marketplace Bundled Backend Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the VS Code Marketplace extension usable after installation without cloning the Aegis monorepo.

**Architecture:** Package a generated copy of `aegis-ai-core` into the extension and bootstrap it into a VS Code-managed Python virtual environment on first run. Keep `aegisAI.serverCwd` as a developer override, but default Marketplace users to the bundled backend.

**Tech Stack:** VS Code extension TypeScript, Node `child_process`, Python `venv`/`pip`, pygls LSP server, `vsce` packaging.

---

### Task 1: Package The Python Backend

**Files:**
- Create: `aegis-vscode/scripts/prepare-bundled-backend.js`
- Modify: `aegis-vscode/package.json`
- Modify: `aegis-vscode/.vscodeignore`
- Modify: `.gitignore`

- [ ] Add a Node script that copies `../aegis-ai-core/src` and `../aegis-ai-core/pyproject.toml` into `aegis-vscode/resources/aegis-ai-core`.
- [ ] Exclude caches, tests, pyc files, local target downloads, and other generated artifacts.
- [ ] Run the script before `vscode:prepublish` and before `vsce package`.
- [ ] Ensure generated backend resources are ignored by git but included in `.vsix`.

### Task 2: Bootstrap Runtime Backend

**Files:**
- Create: `aegis-vscode/src/backendBootstrap.ts`
- Modify: `aegis-vscode/src/extension.ts`
- Modify: `aegis-vscode/src/pythonProbe.ts`
- Test: `aegis-vscode/src/test/suite/backendBootstrap.test.ts`
- Test: `aegis-vscode/src/test/suite/pythonProbe.test.ts`

- [ ] Add version parsing for `Python X.Y.Z`.
- [ ] Require Python `>=3.10`.
- [ ] Detect bundled backend at `resources/aegis-ai-core`.
- [ ] Create a venv under `context.globalStorageUri.fsPath`.
- [ ] Install the bundled backend into that venv with `python -m pip install <backendPath>`.
- [ ] Reuse the venv when a stamp file says the installed backend matches the bundled backend version.
- [ ] Start LSP from the venv Python when bundled backend is available.
- [ ] Fall back to developer `serverCwd` or sibling monorepo lookup when no bundled backend exists.

### Task 3: User-Facing Failure Handling

**Files:**
- Modify: `aegis-vscode/src/extension.ts`
- Test: `aegis-vscode/src/test/suite/backendBootstrap.test.ts`

- [ ] Show a clear error when Python is missing.
- [ ] Show a clear error when Python is below 3.10.
- [ ] Show install progress while creating the backend environment.
- [ ] Log exact bootstrap commands and failures to the Aegis output channel.

### Task 4: Marketplace Documentation

**Files:**
- Modify: `aegis-vscode/README.md`
- Modify: `aegis-vscode/package.json`

- [ ] Replace the old “clone Python engine” installation steps.
- [ ] Document Python 3.10+ as a Marketplace requirement.
- [ ] Explain that Aegis installs its backend into a VS Code-managed environment on first run.
- [ ] Keep manual `serverCwd` documentation under advanced/development settings.

### Task 5: Verification And Packaging

**Commands:**
- `npm run check`
- `npm test`
- `npm run prepare-backend`
- `npx vsce package --no-dependencies`
- Inspect generated `.vsix` for `extension/resources/aegis-ai-core/src/lsp/__main__.py`

- [ ] TypeScript compiles.
- [ ] Extension tests pass.
- [ ] Generated `.vsix` includes core source.
- [ ] Generated `.vsix` excludes caches, pyc, tests, real-world targets, and local artifacts.
