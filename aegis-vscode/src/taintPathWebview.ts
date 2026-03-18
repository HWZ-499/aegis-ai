/**
 * @fileoverview O3 — Taint Path Webview Panel
 *
 * Renders an interactive dataflow visualization (source → transforms → sink)
 * inside a VS Code Webview. Each node is clickable to jump to its code location.
 */

import * as vscode from "vscode";

/** Single step in the taint path (matches LSP TaintPath node shape). */
export interface TaintStep {
  nodeType: string; // SOURCE | VARIABLE | SINK | SANITIZER | PARAMETER | ...
  name: string;
  filePath: string;
  line: number;
  column: number;
  codeSnippet: string;
}

/** Edge between taint steps. */
export interface TaintEdge {
  edgeType: string; // ASSIGNMENT | PROPAGATION | PARAMETER_PASS | ...
  line: number;
  description: string;
}

/** Full taint path payload from aegis/getTaintPath. */
export interface TaintPathData {
  vulnType: string;
  severity: string;
  taintPath: {
    nodes: TaintStep[];
    edges: TaintEdge[];
    pathLength: number;
    isSanitized: boolean;
    riskLevel: string;
    confidence: number;
  };
}

let currentPanel: vscode.WebviewPanel | undefined;

/**
 * Show or reuse the Taint Path Webview panel.
 */
export function showTaintPathPanel(
  extensionUri: vscode.Uri,
  data: TaintPathData
): void {
  const column = vscode.ViewColumn.Beside;

  if (currentPanel) {
    currentPanel.reveal(column);
    currentPanel.webview.html = buildHtml(currentPanel.webview, data);
    return;
  }

  currentPanel = vscode.window.createWebviewPanel(
    "aegisTaintPath",
    `Taint Path: ${data.vulnType}`,
    column,
    { enableScripts: true, retainContextWhenHidden: false }
  );

  currentPanel.webview.html = buildHtml(currentPanel.webview, data);

  currentPanel.webview.onDidReceiveMessage(async (msg) => {
    if (msg.command === "jumpToCode" && msg.filePath && msg.line) {
      try {
        const uri = vscode.Uri.file(msg.filePath);
        const doc = await vscode.workspace.openTextDocument(uri);
        const editor = await vscode.window.showTextDocument(doc, vscode.ViewColumn.One);
        const pos = new vscode.Position(Math.max(0, msg.line - 1), 0);
        editor.selection = new vscode.Selection(pos, pos);
        editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
      } catch {
        // File may not exist locally
      }
    }
  });

  currentPanel.onDidDispose(() => {
    currentPanel = undefined;
  });
}

/**
 * Dispose the current taint path panel if open.
 */
export function disposeTaintPathPanel(): void {
  currentPanel?.dispose();
  currentPanel = undefined;
}

function getNonce(): string {
  let text = "";
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 32; i++) {
    text += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return text;
}

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function buildHtml(
  _webview: vscode.Webview,
  data: TaintPathData
): string {
  const nonce = getNonce();
  const nodes = data.taintPath?.nodes ?? [];
  const edges = data.taintPath?.edges ?? [];
  const severity = data.severity ?? "Medium";
  const vulnType = data.vulnType ?? "Unknown";

  const severityColor: Record<string, string> = {
    Critical: "#f44336",
    High: "#ff9800",
    Medium: "#ffeb3b",
    Low: "#8bc34a",
  };
  const sevColor = severityColor[severity] ?? "#888";

  const nodesHtml = nodes
    .map((step, i) => {
      const cls = step.nodeType.toLowerCase();
      const badge = step.nodeType;
      const edgeHtml =
        i < nodes.length - 1
          ? `<div class="taint-edge"><span class="arrow">&#8595;</span><span class="edge-label">${esc(edges[i]?.edgeType ?? "PROPAGATION")}</span></div>`
          : "";
      return `
      <div class="taint-node ${cls}" onclick="jumpTo('${esc(step.filePath)}', ${step.line})">
        <span class="badge">${esc(badge)}</span>
        <div class="node-body">
          <code class="node-name">${esc(step.name)}</code>
          <span class="node-loc">${esc(step.filePath.split(/[/\\\\]/).pop() ?? "")}:${step.line}</span>
          ${step.codeSnippet ? `<pre class="snippet">${esc(step.codeSnippet)}</pre>` : ""}
        </div>
      </div>
      ${edgeHtml}`;
    })
    .join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
  <style>
    :root { --bg: #1e1e2e; --fg: #cdd6f4; --border: #45475a; }
    body { background: var(--bg); color: var(--fg); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; padding: 16px; margin: 0; }
    h2 { margin: 0 0 4px 0; font-size: 16px; }
    .meta { font-size: 12px; color: #888; margin-bottom: 16px; }
    .meta .sev { color: ${sevColor}; font-weight: 600; }
    .taint-node {
      border-radius: 8px; padding: 10px 14px; margin: 4px 0;
      cursor: pointer; display: flex; align-items: flex-start; gap: 10px;
      border-left: 4px solid #666; transition: background 0.15s;
    }
    .taint-node:hover { filter: brightness(1.15); }
    .taint-node.source  { border-left-color: #4caf50; background: rgba(76,175,80,0.08); }
    .taint-node.sink    { border-left-color: #f44336; background: rgba(244,67,54,0.08); }
    .taint-node.variable, .taint-node.parameter, .taint-node.return_value, .taint-node.property, .taint-node.call_arg {
      border-left-color: #2196f3; background: rgba(33,150,243,0.06);
    }
    .taint-node.sanitizer { border-left-color: #9e9e9e; background: rgba(158,158,158,0.08); }
    .badge {
      font-size: 10px; font-weight: 700; padding: 2px 6px; border-radius: 4px;
      background: rgba(255,255,255,0.07); white-space: nowrap; min-width: 60px; text-align: center;
    }
    .node-body { flex: 1; min-width: 0; }
    .node-name { font-size: 13px; word-break: break-all; }
    .node-loc { display: block; font-size: 11px; color: #888; margin-top: 2px; }
    .snippet { font-size: 11px; color: #a6adc8; margin: 4px 0 0 0; padding: 4px 8px; background: rgba(0,0,0,0.2); border-radius: 4px; overflow-x: auto; }
    .taint-edge { text-align: center; color: #666; font-size: 12px; padding: 2px 0; }
    .arrow { font-size: 16px; display: block; line-height: 1; }
    .edge-label { font-size: 10px; }
    .sanitized-banner { background: rgba(158,158,158,0.12); border: 1px solid #666; border-radius: 6px; padding: 8px 12px; margin-bottom: 12px; font-size: 12px; }
  </style>
</head>
<body>
  <h2>Data Flow Path</h2>
  <div class="meta">
    <span class="sev">${esc(severity)}</span> &middot; ${esc(vulnType)} &middot; ${nodes.length} steps
  </div>
  ${data.taintPath?.isSanitized ? '<div class="sanitized-banner">&#9888; Path includes a sanitizer — may be a false positive.</div>' : ""}
  <div id="path-container">
    ${nodesHtml}
  </div>
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    function jumpTo(filePath, line) {
      vscode.postMessage({ command: 'jumpToCode', filePath, line });
    }
  </script>
</body>
</html>`;
}
