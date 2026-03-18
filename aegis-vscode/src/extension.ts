/**
 * @fileoverview Aegis AI Security Scanner — VSCode/Cursor Extension entry point
 *
 * Responsibilities:
 * - Launch Python LSP Server process (stdio communication)
 * - Create LanguageClient to connect to LSP Server
 * - Status Bar real-time scan status (Ready / Scanning / N issues / Safe)
 * - Graceful shutdown on deactivate
 */

import * as path from "path";
import * as fs from "fs";
import { execFileSync } from "child_process";
import {
  workspace,
  ExtensionContext,
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
} from "vscode";
import { FindingsTreeProvider } from "./findingsTreeProvider";
import { showReport } from "./reportWebview";
import { FixPreviewProvider } from "./fixPreviewProvider";
import { showTaintPathPanel, disposeTaintPathPanel, TaintPathData } from "./taintPathWebview";
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

// ─── Status Bar state enum ─────────────────────────────────────────────────

/** Status Bar display states */
type AegisStatus = "ready" | "scanning" | "issues" | "safe" | "disconnected" | "error";

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
export function activate(context: ExtensionContext): void {
  const config = workspace.getConfiguration("aegisAI");

  // Check if extension is enabled
  if (!config.get<boolean>("enabled", true)) {
    return;
  }

  const pythonPath = config.get<string>("pythonPath", "python");
  const serverModule = config.get<string>("serverModule", "src.lsp");
  const explicitCwd = config.get<string>("serverCwd", "").trim();

  const outputChannel = window.createOutputChannel("Aegis AI Security Scanner");
  outputChannel.appendLine("[Aegis] Extension activated, starting LSP Server…");

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

  // ── O2: Preview AI Fix — Diff Editor command ──────────────────────────
  context.subscriptions.push(
    commands.registerCommand("aegisAI.previewFix", async () => {
      const editor = window.activeTextEditor;
      if (!editor || !client) {
        window.showWarningMessage("Aegis: No active editor or LSP not connected.");
        return;
      }

      // Find the first Aegis diagnostic at the cursor position
      const cursorPos = editor.selection.active;
      const allDiags = languages.getDiagnostics(editor.document.uri);
      const aegisDiag = allDiags.find(
        (d) =>
          d.source === "Aegis AI" &&
          d.range.contains(cursorPos)
      );
      if (!aegisDiag) {
        window.showInformationMessage("Aegis: No finding at cursor position.");
        return;
      }

      const ruleId =
        typeof aegisDiag.code === "string"
          ? aegisDiag.code
          : (aegisDiag.code as { value: string })?.value ?? "UNKNOWN";

      // Request AI fix from LSP server
      const result = await window.withProgress(
        { location: ProgressLocation.Notification, title: "Aegis: Generating AI fix…" },
        async () => {
          try {
            return await client!.sendRequest<{
              uri: string;
              rule_id: string;
              fixed_code: string;
              confidence: number;
              fix_suggestion: string;
              start_line: number;
              end_line: number;
              requires_review: boolean;
            } | null>("aegis/generateFix", {
              uri: editor.document.uri.toString(),
              rule_id: ruleId,
              start_line: aegisDiag.range.start.line + 1,
              end_line: aegisDiag.range.end.line + 1,
              message: aegisDiag.message.substring(0, 500),
            });
          } catch (e) {
            outputChannel.appendLine(`[Aegis] generateFix request failed: ${e}`);
            return null;
          }
        }
      );

      if (!result || !result.fixed_code) {
        window.showInformationMessage(
          "Aegis: AI could not generate a fix for this finding. (Check AI provider config)"
        );
        return;
      }

      // Build the full fixed version of the file
      const originalSource = editor.document.getText();
      const lines = originalSource.split("\n");
      const fixStart = Math.max(0, (result.start_line || aegisDiag.range.start.line + 1) - 1);
      const fixEnd = Math.min(lines.length, result.end_line || aegisDiag.range.end.line + 1);
      const fixedLines = [
        ...lines.slice(0, fixStart),
        ...result.fixed_code.split("\n"),
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
        editor.document.uri,
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
        const edit = new WorkspaceEdit();
        const replaceRange = new Range(
          fixStart, 0,
          fixEnd, lines[fixEnd - 1]?.length ?? 0
        );
        edit.replace(editor.document.uri, replaceRange, result.fixed_code);
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

  // ── Validate Python interpreter ────────────────────────────────────────
  try {
    const pyVersion = execFileSync(pythonPath, ["--version"], {
      encoding: "utf-8",
      timeout: 5000,
    }).trim();
    outputChannel.appendLine(`[Aegis] ${pyVersion} found`);
  } catch {
    updateStatusBar("disconnected");
    outputChannel.appendLine(
      `[Aegis] Python not found at "${pythonPath}". Please install Python 3.9+ and set aegisAI.pythonPath in settings.`
    );
    outputChannel.show();
    window
      .showErrorMessage(
        `Aegis AI: Python not found at "${pythonPath}". Install Python 3.9+ or configure the path.`,
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
    return;
  }

  // aegis-ai-core directory: LSP Server needs to run in aegis-ai-core
  let cwd: string | undefined;
  if (explicitCwd) {
    cwd = path.isAbsolute(explicitCwd)
      ? explicitCwd
      : path.resolve(
          workspace.workspaceFolders?.[0]?.uri.fsPath ?? "",
          explicitCwd
        );
    if (!fs.existsSync(cwd)) {
      outputChannel.appendLine(
        `[Aegis] serverCwd does not exist, falling back to auto-detect: ${cwd}`
      );
      cwd = undefined;
    } else {
      outputChannel.appendLine(`[Aegis] Using configured serverCwd: ${cwd}`);
    }
  }
  if (
    cwd === undefined &&
    workspace.workspaceFolders &&
    workspace.workspaceFolders.length > 0
  ) {
    const rootPath = workspace.workspaceFolders[0].uri.fsPath;
    const rootName = path.basename(rootPath);
    if (rootName === "aegis-ai-core") {
      cwd = rootPath;
    } else {
      cwd = path.join(rootPath, "aegis-ai-core");
    }
    if (!fs.existsSync(cwd)) {
      outputChannel.appendLine(
        `[Aegis] Auto-detected directory does not exist, LSP may not start: ${cwd}`
      );
    } else {
      outputChannel.appendLine(`[Aegis] Using working directory: ${cwd}`);
    }
  }
  // Fallback: try sibling aegis-ai-core of the extension directory
  if (cwd === undefined || !fs.existsSync(cwd)) {
    const extDir = context.extensionPath;
    const siblingCwd = path.join(path.dirname(extDir), "aegis-ai-core");
    if (fs.existsSync(siblingCwd)) {
      cwd = siblingCwd;
      outputChannel.appendLine(`[Aegis] Using sibling directory: ${cwd}`);
    } else if (cwd === undefined) {
      outputChannel.appendLine(
        "[Aegis] No workspace open and aegis-ai-core not found. Please open a folder containing aegis-ai-core."
      );
    }
  }

  outputChannel.appendLine(`[Aegis] Python: ${pythonPath}, Module: ${serverModule}`);

  if (!cwd || !fs.existsSync(cwd)) {
    outputChannel.appendLine(
      "[Aegis] Cannot start: aegis-ai-core directory not found. Please open aegis-ai or aegis-ai-core folder (File → Open Folder), or set aegisAI.serverCwd in settings."
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
    command: pythonPath,
    args: ["-m", serverModule],
    options: {
      cwd: cwd,
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
      exclude_patterns: config.get<string[]>("excludePatterns", []),
      disabled_rules: config.get<string[]>("disabledRules", []),
      ai_enabled: config.get<boolean>("ai.enabled", true),
      ai_provider: config.get<string>("ai.provider", "deepseek"),
      scan_on_save: config.get<boolean>("scanOnSave", true),
      scan_on_change: config.get<boolean>("scanOnChange", true),
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
