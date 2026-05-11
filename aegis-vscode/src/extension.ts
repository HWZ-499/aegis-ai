/**
 * @fileoverview Aegis AI Security Scanner — VSCode/Cursor Extension entry point
 *
 * Responsibilities:
 * - Launch Python LSP Server process (stdio communication)
 * - Create LanguageClient to connect to LSP Server
 * - Status Bar real-time scan status (Ready / Scanning / N issues / Safe)
 * - Graceful shutdown on deactivate
 */

import {
  workspace,
  ExtensionContext,
  ExtensionMode,
  window,
  commands,
  StatusBarItem,
  StatusBarAlignment,
  languages,
  DiagnosticSeverity,
  Uri,
  Disposable,
  ProgressLocation,
  WorkspaceEdit,
  Range,
  ConfigurationTarget,
  Diagnostic,
  TextDocument,
  WorkspaceConfiguration,
} from "vscode";
import { FindingsTreeProvider } from "./findingsTreeProvider";
import { getAiConfigurationError } from "./aiPreflight";
import { GenerateFixResponse, getGenerateFixFailure, isGenerateFixSuccess } from "./aiFixResult";
import {
  BaselineEntryNode,
  BaselineTreeProvider,
  removeBaselineEntryFromDisk,
  resolveBaselineEntryPath,
} from "./baselineTreeProvider";
import { findAegisCommentBlock } from "./commentCommands";
import { showReport } from "./reportWebview";
import { FixPreviewProvider } from "./fixPreviewProvider";
import { showTaintPathPanel, disposeTaintPathPanel, TaintPathData } from "./taintPathWebview";
import { ensureBackendLaunch } from "./backendBootstrap";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  RevealOutputChannelOn,
} from "vscode-languageclient/node";

// ─── Custom LSP notification types ─────────────────────────────────────────

/** Python server sends `aegis/scanStart` when a file scan begins */
const NOTIFICATION_SCAN_START = "aegis/scanStart";
/** Python server sends `aegis/scanEnd` when scan completes (with result summary) */
const NOTIFICATION_SCAN_END = "aegis/scanEnd";
/** Python server sends `aegis/scanError` on scan failure */
const NOTIFICATION_SCAN_ERROR = "aegis/scanError";
/** Workspace scan progress notification */
const NOTIFICATION_SCAN_PROGRESS = "aegis/scanProgress";

// ─── Global state ────────────────────────────────────────────────────────────

/** @type {LanguageClient | undefined} Global LSP client instance */
let client: LanguageClient | undefined;

/** @type {StatusBarItem | undefined} Status Bar item instance */
let statusBar: StatusBarItem | undefined;

/** @type {Disposable | undefined} Diagnostics change listener */
let diagnosticsListener: Disposable | undefined;

/** Workspace scan progress reporter and completion callback */
let workspaceProgressReporter: { report: (p: { message?: string; increment?: number }) => void } | null = null;
let workspaceScanResolve: (() => void) | null = null;

interface PreviewFixCommandArgs {
  uri?: string;
  rule_id?: string;
  start_line?: number;
  end_line?: number;
  message?: string;
}

// ─── Status Bar state enum ─────────────────────────────────────────────────

/** Status Bar display states */
type AegisStatus = "ready" | "scanning" | "issues" | "safe" | "disconnected" | "error";

function getGlobalConfigurationValue<T>(
  config: WorkspaceConfiguration,
  key: string,
  defaultValue: T,
): T {
  const inspected = config.inspect<T>(key);
  return inspected?.globalValue ?? inspected?.defaultValue ?? defaultValue;
}

function getDiagnosticRuleId(diagnostic: Diagnostic): string {
  if (typeof diagnostic.code === "string") {
    return diagnostic.code;
  }
  return (diagnostic.code as { value?: string } | undefined)?.value ?? "UNKNOWN";
}

function buildLineReplacementRange(
  document: TextDocument,
  startLineZeroBased: number,
  endLineExclusive: number,
): Range {
  const lastLine = Math.max(0, document.lineCount - 1);
  const startLine = Math.min(Math.max(0, startLineZeroBased), lastLine);
  const safeEndExclusive = Math.min(Math.max(endLineExclusive, startLine + 1), document.lineCount);
  if (safeEndExclusive >= document.lineCount) {
    return new Range(startLine, 0, lastLine, document.lineAt(lastLine).text.length);
  }
  return new Range(startLine, 0, safeEndExclusive, 0);
}

function codeForLineReplacement(
  fixedCode: string,
  endLineExclusive: number,
  document: TextDocument,
): string {
  if (endLineExclusive < document.lineCount && !fixedCode.endsWith("\n")) {
    return `${fixedCode}\n`;
  }
  return fixedCode;
}

/**
 * Update Status Bar display.
 *
 * @param {AegisStatus} status - Current status
 * @param {number} [issueCount] - Issue count (only used for `issues` status)
 */
function updateStatusBar(status: AegisStatus, issueCount?: number): void {
  if (!statusBar) return;

  switch (status) {
    case "ready":
      statusBar.text = "$(shield) Aegis: Ready";
      statusBar.tooltip = "Aegis AI security scanner ready — auto-scans on save";
      statusBar.backgroundColor = undefined;
      break;
    case "scanning":
      statusBar.text = "$(loading~spin) Aegis: Scanning";
      statusBar.tooltip = "Aegis AI is analyzing the current file…";
      statusBar.backgroundColor = undefined;
      break;
    case "issues":
      statusBar.text = `$(warning) Aegis: ${issueCount ?? 0} issue${(issueCount ?? 0) === 1 ? "" : "s"}`;
      statusBar.tooltip = `Aegis AI found ${issueCount ?? 0} security issue${(issueCount ?? 0) === 1 ? "" : "s"} — click to view`;
      statusBar.command = "workbench.action.problems.focus";
      statusBar.backgroundColor = undefined;
      break;
    case "safe":
      statusBar.text = "$(check) Aegis: Safe";
      statusBar.tooltip = "Aegis AI found no security issues in this file";
      statusBar.backgroundColor = undefined;
      break;
    case "disconnected":
      statusBar.text = "$(plug) Aegis: Disconnected";
      statusBar.tooltip = "Aegis AI LSP Server not connected — click to configure";
      statusBar.command = "workbench.action.openSettings";
      statusBar.backgroundColor = undefined;
      break;
    case "error":
      statusBar.text = "$(error) Aegis: Error";
      statusBar.tooltip = "Aegis AI scan error — click to view logs";
      statusBar.command = "aegisAI.showOutput";
      statusBar.backgroundColor = undefined;
      break;
  }
}

/**
 * Refresh Status Bar based on Aegis diagnostics for the active file.
 * Shows "Safe" when 0 diagnostics, otherwise "N issues".
 */
function refreshStatusBarFromDiagnostics(): void {
  const activeEditor = window.activeTextEditor;
  if (!activeEditor) {
    updateStatusBar("ready");
    return;
  }

  const uri: Uri = activeEditor.document.uri;
  const allDiags = languages.getDiagnostics(uri);
  // Only count diagnostics from Aegis AI source
  const aegisDiags = allDiags.filter(
    (d) =>
      d.source === "Aegis AI" &&
      (d.severity === DiagnosticSeverity.Error ||
        d.severity === DiagnosticSeverity.Warning)
  );

  if (aegisDiags.length === 0) {
    updateStatusBar("safe");
  } else {
    updateStatusBar("issues", aegisDiags.length);
  }
}

/**
 * Called when the extension is activated.
 *
 * @param {ExtensionContext} context - VS Code extension context
 */
export async function activate(context: ExtensionContext): Promise<void> {
  const config = workspace.getConfiguration("aegisAI");

  // Check if extension is enabled
  if (!config.get<boolean>("enabled", true)) {
    return;
  }

  const pythonPath = getGlobalConfigurationValue(config, "pythonPath", "python");
  const serverModule = getGlobalConfigurationValue(config, "serverModule", "src.lsp");
  const explicitCwd = getGlobalConfigurationValue(config, "serverCwd", "").trim();

  const outputChannel = window.createOutputChannel("Aegis AI Security Scanner");
  outputChannel.appendLine("[Aegis] Extension activated, starting LSP Server…");
  if (!workspace.isTrusted) {
    outputChannel.appendLine(
      "[Aegis] Workspace is untrusted. Workspace-controlled backend discovery is disabled.",
    );
  }

  // ── Status Bar initialization ──────────────────────────────────────────
  statusBar = window.createStatusBarItem(StatusBarAlignment.Left, 100);
  statusBar.text = "$(sync~spin) Aegis: Connecting…";
  statusBar.tooltip = "Aegis AI is connecting to LSP Server";
  statusBar.show();
  context.subscriptions.push(statusBar);

  // Aegis Findings TreeView (sidebar panel)
  const findingsProvider = new FindingsTreeProvider();
  const treeView = window.createTreeView("aegisFindings", {
    treeDataProvider: findingsProvider,
    showCollapseAll: true,
  });
  context.subscriptions.push(treeView);

  const workspaceRoot = workspace.workspaceFolders?.[0]?.uri.fsPath;
  const baselineProvider = new BaselineTreeProvider(workspaceRoot);
  const baselineTreeView = window.createTreeView("aegisBaseline", {
    treeDataProvider: baselineProvider,
    showCollapseAll: true,
  });
  context.subscriptions.push(baselineTreeView);

  const updateBaselineViewMessage = (): void => {
    const showSuppressed = workspace.getConfiguration("aegisAI").get<boolean>("showSuppressedFindings", false);
    baselineTreeView.message = showSuppressed
      ? "Suppressed findings from .aegis-baseline.json"
      : "Suppressed findings are hidden. Run \"Aegis: Toggle Suppressed Findings\" to inspect them.";
  };
  updateBaselineViewMessage();

  // ── O2: Fix Preview Provider (aegis-fix: URI scheme for diff preview) ──
  const fixPreviewProvider = new FixPreviewProvider();
  context.subscriptions.push(
    workspace.registerTextDocumentContentProvider("aegis-fix", fixPreviewProvider)
  );

  // Register commands (showOutput is always available; scan commands need client)
  context.subscriptions.push(
    commands.registerCommand("aegisAI.showOutput", () => {
      outputChannel.show();
    }),
    commands.registerCommand("aegisAI.showReport", () => {
      showReport();
    }),
    commands.registerCommand("aegisAI.refreshBaseline", () => {
      baselineProvider.refresh();
    }),
    commands.registerCommand("aegisAI.toggleSuppressedFindings", async () => {
      const current = workspace.getConfiguration("aegisAI").get<boolean>("showSuppressedFindings", false);
      await workspace.getConfiguration("aegisAI").update(
        "showSuppressedFindings",
        !current,
        ConfigurationTarget.Workspace
      );
      updateBaselineViewMessage();
      baselineProvider.refresh();
    }),
    commands.registerCommand("aegisAI.removeBaselineEntry", async (node?: BaselineEntryNode) => {
      const activeRoot = workspace.workspaceFolders?.[0]?.uri.fsPath;
      if (!node?.entry || !activeRoot) {
        window.showWarningMessage("Aegis: No baseline entry selected.");
        return;
      }

      const removed = removeBaselineEntryFromDisk(activeRoot, node.entry.fingerprint);
      if (!removed) {
        window.showWarningMessage("Aegis: Could not remove the selected baseline entry.");
        return;
      }

      baselineProvider.refresh();
      outputChannel.appendLine(
        `[Aegis] Removed baseline entry ${node.entry.rule_id} ${node.entry.file_path}:${node.entry.line}`
      );
      window.showInformationMessage(
        `Aegis: Removed baseline entry for ${node.entry.rule_id} at ${node.entry.file_path}:${node.entry.line}`
      );
      const targetPath = resolveBaselineEntryPath(activeRoot, node.entry.file_path);
      if (!targetPath) {
        outputChannel.appendLine(
          `[Aegis] Refusing to rescan baseline entry outside workspace: ${node.entry.file_path}`,
        );
        window.showWarningMessage("Aegis: Baseline entry path is outside the workspace; rescan skipped.");
        return;
      }
      await commands.executeCommand("aegisAI.scanCurrentFile", Uri.file(targetPath));
    }),
    commands.registerCommand("aegisAI.removeRemediationComments", async () => {
      const editor = window.activeTextEditor;
      if (!editor) {
        window.showInformationMessage("Aegis: No active editor.");
        return;
      }

      const source = editor.document.getText();
      const block = findAegisCommentBlock(source, editor.selection.active.line);
      if (!block) {
        window.showInformationMessage("Aegis: No inserted remediation comment block at the cursor.");
        return;
      }

      const lineCount = editor.document.lineCount;
      const deleteRange = block.endLineExclusive < lineCount
        ? new Range(block.startLine, 0, block.endLineExclusive, 0)
        : new Range(
            block.startLine,
            0,
            Math.max(0, lineCount - 1),
            editor.document.lineAt(Math.max(0, lineCount - 1)).text.length
          );

      const edit = new WorkspaceEdit();
      edit.delete(editor.document.uri, deleteRange);
      await workspace.applyEdit(edit);
      outputChannel.appendLine(
        `[Aegis] Removed remediation comments at L${block.startLine + 1}-${block.endLineExclusive}`
      );
    })
  );
  context.subscriptions.push(
    commands.registerCommand("aegisAI.scanCurrentFile", (resourceUri?: Uri) => {
      // Support both editor context and explorer context menu
      const uri = resourceUri?.toString() ?? window.activeTextEditor?.document.uri.toString();
      if (!uri) return;
      if (!client) {
        outputChannel.appendLine("[Aegis] Not connected. Please wait for LSP to connect.");
        outputChannel.show();
        return;
      }
      client.sendNotification("aegis/requestScan", { uri });
      outputChannel.appendLine(`[Aegis] Manual scan triggered: ${uri}`);
    }),
    commands.registerCommand("aegisAI.scanWorkspace", () => {
      if (!client) {
        outputChannel.appendLine("[Aegis] Not connected. Please wait for LSP to connect.");
        outputChannel.show();
        return;
      }
      outputChannel.appendLine("[Aegis] Manual workspace scan triggered");
      window.withProgress(
        {
          title: "Aegis: Scanning Workspace",
          location: ProgressLocation.Notification,
          cancellable: false,
        },
        (progress) => {
          workspaceProgressReporter = progress;
          return new Promise<void>((resolve) => {
            workspaceScanResolve = resolve;
            client!.sendNotification("aegis/requestScanWorkspace", {});
          });
        }
      ).then(() => {
        workspaceProgressReporter = null;
        workspaceScanResolve = null;
      });
    })
  );

  const baselineWatcher = workspace.createFileSystemWatcher("**/.aegis-baseline.json");
  baselineWatcher.onDidCreate(() => baselineProvider.refresh());
  baselineWatcher.onDidChange(() => baselineProvider.refresh());
  baselineWatcher.onDidDelete(() => baselineProvider.refresh());
  context.subscriptions.push(baselineWatcher);

  // ── O2: Preview AI Fix — Diff Editor command ──────────────────────────
  context.subscriptions.push(
    commands.registerCommand("aegisAI.previewFix", async (args?: PreviewFixCommandArgs) => {
      if (!client) {
        window.showWarningMessage("Aegis: LSP not connected.");
        return;
      }

      let editor = window.activeTextEditor;
      const requestedUri = args?.uri ? Uri.parse(args.uri) : editor?.document.uri;
      if (!requestedUri) {
        window.showWarningMessage("Aegis: No active editor.");
        return;
      }

      if (!editor || editor.document.uri.toString() !== requestedUri.toString()) {
        const document = await workspace.openTextDocument(requestedUri);
        editor = await window.showTextDocument(document);
      }

      const runtimeConfig = workspace.getConfiguration("aegisAI");
      const aiProvider = runtimeConfig.get<string>("ai.provider", "deepseek");
      const aiEnabled = runtimeConfig.get<boolean>("ai.enabled", true);
      const aiConfigError = getAiConfigurationError(aiProvider, process.env, aiEnabled);
      if (aiConfigError) {
        window.showWarningMessage(`Aegis: ${aiConfigError}`);
        return;
      }

      // Find the requested Aegis diagnostic, or fall back to the cursor position.
      const allDiags = languages.getDiagnostics(editor.document.uri);
      const requestedRuleId = args?.rule_id;
      const requestedLine = args?.start_line;
      const aegisDiag = requestedLine
        ? allDiags.find(
            (d) =>
              d.source === "Aegis AI" &&
              d.range.start.line === requestedLine - 1 &&
              (!requestedRuleId || getDiagnosticRuleId(d) === requestedRuleId),
          )
        : allDiags.find(
            (d) =>
              d.source === "Aegis AI" &&
              d.range.contains(editor.selection.active),
          );
      if (!aegisDiag) {
        window.showInformationMessage("Aegis: No finding at cursor position.");
        return;
      }

      const ruleId = requestedRuleId ?? getDiagnosticRuleId(aegisDiag);
      const requestStartLine = args?.start_line ?? aegisDiag.range.start.line + 1;
      const requestEndLine = args?.end_line ?? aegisDiag.range.end.line + 1;
      const requestMessage = args?.message ?? aegisDiag.message.substring(0, 500);
      const targetDocument = editor.document;
      const originalSource = targetDocument.getText();
      const originalVersion = targetDocument.version;

      // Request AI fix from LSP server
      const result = await window.withProgress(
        { location: ProgressLocation.Notification, title: "Aegis: Generating AI fix…" },
        async () => {
          try {
            return await client!.sendRequest<GenerateFixResponse>("aegis/generateFix", {
              uri: targetDocument.uri.toString(),
              rule_id: ruleId,
              start_line: requestStartLine,
              end_line: requestEndLine,
              message: requestMessage,
            });
          } catch (e) {
            outputChannel.appendLine(`[Aegis] generateFix request failed: ${e}`);
            return null;
          }
        }
      );

      const fixFailure = getGenerateFixFailure(result);
      if (fixFailure) {
        if (fixFailure.level === "error") {
          window.showErrorMessage(fixFailure.message);
        } else if (fixFailure.level === "warning") {
          window.showWarningMessage(fixFailure.message);
        } else {
          window.showInformationMessage(fixFailure.message);
        }
        return;
      }
      if (!isGenerateFixSuccess(result)) {
        window.showInformationMessage("Aegis: AI reviewed this finding but did not return a safe replacement.");
        return;
      }

      // Build the full fixed version of the file
      const lines = originalSource.split("\n");
      const fixedCode = result.fixed_code.replace(/\r\n/g, "\n");
      const fixStart = Math.min(
        Math.max(0, lines.length - 1),
        Math.max(0, (result.start_line || requestStartLine) - 1),
      );
      const fixEnd = Math.min(
        lines.length,
        Math.max(fixStart + 1, result.end_line || requestEndLine),
      );
      const fixedLines = [
        ...lines.slice(0, fixStart),
        ...fixedCode.split("\n"),
        ...lines.slice(fixEnd),
      ];
      const fixedSource = fixedLines.join("\n");

      // Register fixed content in preview provider
      const fixId = `${editor.document.uri.toString()}#${ruleId}#${aegisDiag.range.start.line}`;
      const previewUri = fixPreviewProvider.setFix(fixId, { fixedSource });

      // Open diff editor
      const confidenceLabel = `${Math.round(result.confidence * 100)}%`;
      const reviewTag = result.requires_review ? " ⚠ Review" : "";
      await commands.executeCommand(
        "vscode.diff",
        targetDocument.uri,
        previewUri,
        `AI Fix Preview (${ruleId} ${confidenceLabel}${reviewTag})`,
        { preview: true }
      );

      // Offer to apply
      const action = await window.showInformationMessage(
        `Aegis AI Fix (${confidenceLabel} confidence${reviewTag}): Apply this fix?`,
        "Apply Fix",
        "Dismiss"
      );

      if (action === "Apply Fix") {
        if (targetDocument.version !== originalVersion || targetDocument.getText() !== originalSource) {
          window.showWarningMessage("Aegis: Document changed after the preview was generated. Re-run the fix preview.");
          outputChannel.appendLine("[Aegis] Refused stale AI fix because the document changed after preview.");
          fixPreviewProvider.removeFix(fixId);
          return;
        }
        const edit = new WorkspaceEdit();
        const replaceRange = buildLineReplacementRange(targetDocument, fixStart, fixEnd);
        edit.replace(targetDocument.uri, replaceRange, codeForLineReplacement(fixedCode, fixEnd, targetDocument));
        await workspace.applyEdit(edit);
        outputChannel.appendLine(`[Aegis] Applied AI fix for ${ruleId} at L${fixStart + 1}-${fixEnd}`);
      }

      // Clean up preview
      fixPreviewProvider.removeFix(fixId);
    })
  );

  // ── O3: Taint Path Decorations ─────────────────────────────────────────
  const sourceDecoration = window.createTextEditorDecorationType({
    backgroundColor: "rgba(76, 175, 80, 0.15)",
    isWholeLine: true,
    overviewRulerColor: "#4caf50",
    overviewRulerLane: 2,
  });
  const sinkDecoration = window.createTextEditorDecorationType({
    backgroundColor: "rgba(244, 67, 54, 0.15)",
    isWholeLine: true,
    overviewRulerColor: "#f44336",
    overviewRulerLane: 2,
  });
  const propagationDecoration = window.createTextEditorDecorationType({
    backgroundColor: "rgba(33, 150, 243, 0.08)",
    isWholeLine: true,
  });
  context.subscriptions.push(sourceDecoration, sinkDecoration, propagationDecoration);

  /** Clear all taint path decorations from the active editor. */
  function clearTaintDecorations(): void {
    const editor = window.activeTextEditor;
    if (!editor) return;
    editor.setDecorations(sourceDecoration, []);
    editor.setDecorations(sinkDecoration, []);
    editor.setDecorations(propagationDecoration, []);
  }

  // ── O3: Show Taint Path command ────────────────────────────────────────
  context.subscriptions.push(
    commands.registerCommand("aegisAI.showTaintPath", async (arg?: { uri: string; line: number; ruleId: string }) => {
      if (!client) {
        window.showWarningMessage("Aegis: LSP not connected.");
        return;
      }

      let uri: string;
      let line: number;
      let ruleId: string;

      if (arg && arg.uri && arg.line && arg.ruleId) {
        // Called from TreeView context menu
        uri = arg.uri;
        line = arg.line;
        ruleId = arg.ruleId;
      } else {
        // Called from editor — use diagnostic at cursor
        const editor = window.activeTextEditor;
        if (!editor) {
          window.showWarningMessage("Aegis: No active editor.");
          return;
        }
        const cursorPos = editor.selection.active;
        const allDiags = languages.getDiagnostics(editor.document.uri);
        const aegisDiag = allDiags.find(
          (d) => d.source === "Aegis AI" && d.range.contains(cursorPos)
        );
        if (!aegisDiag) {
          window.showInformationMessage("Aegis: No finding at cursor position.");
          return;
        }
        uri = editor.document.uri.toString();
        line = aegisDiag.range.start.line + 1;
        ruleId =
          typeof aegisDiag.code === "string"
            ? aegisDiag.code
            : (aegisDiag.code as { value: string })?.value ?? "UNKNOWN";
      }

      // Request taint path from LSP
      const result = await window.withProgress(
        { location: ProgressLocation.Notification, title: "Aegis: Loading taint path…" },
        async () => {
          try {
            return await client!.sendRequest<TaintPathData | null>("aegis/getTaintPath", {
              uri,
              line,
              ruleId,
            });
          } catch (e) {
            outputChannel.appendLine(`[Aegis] getTaintPath failed: ${e}`);
            return null;
          }
        }
      );

      if (!result || !result.taintPath?.nodes?.length) {
        window.showInformationMessage("Aegis: No taint path available for this finding.");
        return;
      }

      // Show Webview
      showTaintPathPanel(context.extensionUri, result);

      // Apply editor decorations
      clearTaintDecorations();
      const editor = window.activeTextEditor;
      if (editor) {
        const sourceRanges: Range[] = [];
        const sinkRanges: Range[] = [];
        const propRanges: Range[] = [];
        for (const node of result.taintPath.nodes) {
          const nodeLine = Math.max(0, node.line - 1);
          const range = new Range(nodeLine, 0, nodeLine, 0);
          const nt = node.nodeType.toUpperCase();
          if (nt === "SOURCE") {
            sourceRanges.push(range);
          } else if (nt === "SINK") {
            sinkRanges.push(range);
          } else {
            propRanges.push(range);
          }
        }
        editor.setDecorations(sourceDecoration, sourceRanges);
        editor.setDecorations(sinkDecoration, sinkRanges);
        editor.setDecorations(propagationDecoration, propRanges);
      }
    })
  );

  // Clear taint decorations when editor changes
  context.subscriptions.push(
    window.onDidChangeActiveTextEditor(() => clearTaintDecorations())
  );

  // Dispose taint path panel on deactivation
  context.subscriptions.push({ dispose: () => disposeTaintPathPanel() });

  // aegis-ai-core directory: LSP Server needs to run in aegis-ai-core.
  let backendLaunch;
  try {
    backendLaunch = await window.withProgress(
      {
        location: ProgressLocation.Notification,
        title: "Aegis: Preparing Python backend",
        cancellable: false,
      },
      async () =>
        ensureBackendLaunch({
          explicitCwd,
          extensionPath: context.extensionPath,
          globalStoragePath: context.globalStorageUri.fsPath,
          preferBundledBackend: context.extensionMode === ExtensionMode.Production || !workspace.isTrusted,
          pythonPath,
          serverModule,
          workspaceFolders: workspace.isTrusted
            ? workspace.workspaceFolders?.map((folder) => folder.uri.fsPath) ?? []
            : [],
        }),
    );
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    outputChannel.appendLine(`[Aegis] Backend startup failed: ${message}`);
    outputChannel.show();
    window.showErrorMessage(`Aegis: ${message}`);
    updateStatusBar("disconnected");
    return;
  }

  for (const message of backendLaunch.logMessages) {
    outputChannel.appendLine(message);
  }
  const cwd = backendLaunch.cwd;

  outputChannel.appendLine(`[Aegis] Backend source: ${backendLaunch.source}`);
  outputChannel.appendLine(`[Aegis] Python: ${backendLaunch.pythonPath}, Module: ${serverModule}`);

  if (!cwd) {
    outputChannel.appendLine(
      "[Aegis] Cannot start: backend directory not found. Reinstall Aegis, or set aegisAI.serverCwd in settings."
    );
    outputChannel.show();
    updateStatusBar("disconnected");
    return;
  }

  /**
   * Server startup config: launch Python process via stdio.
   * Command: python -m src.lsp
   */
  const serverOptions: ServerOptions = {
    command: backendLaunch.pythonPath,
    args: backendLaunch.args,
    options: {
      cwd: cwd,
      env: {
        ...process.env,
        AI_PROVIDER: config.get<string>("ai.provider", "deepseek"),
      },
    },
  };

  /**
   * Client config: document selectors and initialization options.
   * Passes user settings to LSP Server via initializationOptions.
   */
  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: "file", language: "javascript" },
      { scheme: "file", language: "typescript" },
      { scheme: "file", language: "javascriptreact" },
      { scheme: "file", language: "typescriptreact" },
      { scheme: "file", language: "python" },
      { scheme: "file", language: "php" },
      { scheme: "file", language: "java" },
      { scheme: "file", language: "go" },
    ],
    outputChannel: outputChannel,
    revealOutputChannelOn: RevealOutputChannelOn.Error,
    initializationOptions: {
      severity_minimum: config.get<string>("severity.minimum", "Low"),
      exclude_patterns:
        config.get<string[]>("scan.exclude")
        ?? config.get<string[]>("excludePatterns", []),
      disabled_rules: config.get<string[]>("disabledRules", []),
      ai_enabled: config.get<boolean>("ai.enabled", true),
      ai_provider: config.get<string>("ai.provider", "deepseek"),
      scan_on_save: config.get<boolean>("scanOnSave", true),
      scan_on_change: config.get<boolean>("scanOnChange", true),
      experimental_cross_file: config.get<boolean>("experimental.crossFileAnalysis", false),
    },
    synchronize: {
      fileEvents: workspace.createFileSystemWatcher(
        "**/*.{js,jsx,ts,tsx,py,php,phtml,java,go}"
      ),
    },
  };

  // Create LanguageClient and start
  client = new LanguageClient(
    "aegisAI",
    "Aegis AI Security Scanner",
    serverOptions,
    clientOptions
  );

  client.start().then(
    () => {
      outputChannel.appendLine("[Aegis] LSP Server connected.");
      updateStatusBar("ready");

      window.showInformationMessage("Aegis AI Security Scanner is now active.");

      // ── Listen for custom LSP notification: scan start ───────────────────────────────
      client!.onNotification(NOTIFICATION_SCAN_START, () => {
        updateStatusBar("scanning");
      });

      // ── Listen for custom LSP notification: scan end ─────────────────────────────────
      client!.onNotification(
        NOTIFICATION_SCAN_END,
        (params: { issueCount?: number }) => {
          if (typeof params?.issueCount === "number") {
            if (params.issueCount > 0) {
              updateStatusBar("issues", params.issueCount);
            } else {
              updateStatusBar("safe");
            }
          } else {
            // Fallback: infer from diagnostics if no notification params
            refreshStatusBarFromDiagnostics();
          }
        }
      );

      // ── Listen for custom LSP notification: scan error ───────────────────────────
      client!.onNotification(
        NOTIFICATION_SCAN_ERROR,
        (params: { uri?: string; message?: string }) => {
          updateStatusBar("error");
          outputChannel.appendLine(
            `[Aegis] Scan error: ${params?.message ?? "unknown"} (${params?.uri ?? ""})`
          );
        }
      );

      // ── Listen for custom LSP notification: workspace scan progress ──────────────
      client!.onNotification(
        NOTIFICATION_SCAN_PROGRESS,
        (params: { current?: number; total?: number; uri?: string }) => {
          const cur = params?.current ?? 0;
          const tot = params?.total ?? 0;
          if (workspaceProgressReporter && tot > 0) {
            workspaceProgressReporter.report({
              message: `Scanning ${cur}/${tot}`,
              increment: tot > 0 ? (100 / tot) : 0,
            });
          }
          if (cur === tot && workspaceScanResolve) {
            workspaceScanResolve();
          }
        }
      );

      // ── Refresh status bar when active editor changes ──────────────────────
      context.subscriptions.push(
        window.onDidChangeActiveTextEditor(() => {
          refreshStatusBarFromDiagnostics();
        })
      );

      // ── Update status bar when diagnostics change ──────────────────────
      // (fallback: ensures correct state even if server doesn't send custom notifications)
      diagnosticsListener = languages.onDidChangeDiagnostics(
        (e: { uris: readonly Uri[] }) => {
          const activeUri = window.activeTextEditor?.document.uri;
          if (
            activeUri &&
            e.uris.some((u) => u.toString() === activeUri.toString())
          ) {
            // Delay 200ms to read latest diagnostics (avoid stale snapshot)
            setTimeout(refreshStatusBarFromDiagnostics, 200);
          }
        }
      );
      context.subscriptions.push(diagnosticsListener);

      context.subscriptions.push(
        workspace.onDidChangeConfiguration((event) => {
          if (event.affectsConfiguration("aegisAI.showSuppressedFindings")) {
            updateBaselineViewMessage();
            baselineProvider.refresh();
          }
        })
      );
    },
    (error: unknown) => {
      const msg = error instanceof Error ? error.message : String(error);
      updateStatusBar("disconnected");
      outputChannel.appendLine(`[Aegis] LSP Server failed to start: ${msg}`);

      // Provide actionable buttons to help user resolve the issue
      window
        .showErrorMessage(
          `Aegis AI: LSP Server failed to start. ${msg}`,
          "Configure Python Path",
          "View Logs"
        )
        .then((action) => {
          if (action === "Configure Python Path") {
            commands.executeCommand(
              "workbench.action.openSettings",
              "aegisAI.pythonPath"
            );
          } else if (action === "View Logs") {
            outputChannel.show();
          }
        });
    }
  );

  context.subscriptions.push({
    dispose: () => {
      if (client) {
        client.stop();
      }
    },
  });
}

/**
 * Called when the extension is deactivated.
 *
 * @returns {Thenable<void> | undefined} Promise to stop the LSP client
 */
export function deactivate(): Thenable<void> | undefined {
  if (!client) {
    return undefined;
  }
  return client.stop();
}
