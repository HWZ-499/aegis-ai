/**
 * @fileoverview Webview panel: display Aegis scan HTML report within the IDE
 *
 * Supports: finding the latest scan-report.html in workspace, or user file selection.
 */

import * as path from "path";
import * as fs from "fs";
import {
  window,
  workspace,
  ViewColumn,
  Uri,
  WebviewPanel,
} from "vscode";

/** Currently open Webview panel (singleton reuse) */
let reportPanel: WebviewPanel | undefined;

/**
 * Find the latest scan-report.html in workspace folders.
 * @returns Absolute path to newest report file, or undefined if not found
 */
function findLatestScanReport(): string | undefined {
  const folders = workspace.workspaceFolders;
  if (!folders || folders.length === 0) return undefined;

  let latestPath: string | undefined;
  let latestMtime = 0;

  for (const folder of folders) {
    const reportPath = path.join(folder.uri.fsPath, "scan-report.html");
    try {
      const stat = fs.statSync(reportPath);
      if (stat.mtimeMs > latestMtime) {
        latestMtime = stat.mtimeMs;
        latestPath = reportPath;
      }
    } catch {
      // File not found or unreadable, skip
    }
    // Also check aegis-ai-core subdirectory
    const coreReportPath = path.join(
      folder.uri.fsPath,
      "aegis-ai-core",
      "scan-report.html"
    );
    try {
      const stat = fs.statSync(coreReportPath);
      if (stat.mtimeMs > latestMtime) {
        latestMtime = stat.mtimeMs;
        latestPath = coreReportPath;
      }
    } catch {
      // ignore
    }
  }
  return latestPath;
}

/**
 * Convert local HTML file content for safe display in Webview.
 * Injects Content Security Policy.
 */
function getHtmlForWebview(panel: WebviewPanel, filePath: string): string {
  const dir = path.dirname(filePath);
  let html = fs.readFileSync(filePath, "utf-8");

  // Inject Content Security Policy to prevent XSS
  const csp = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${panel.webview.cspSource} 'unsafe-inline'; img-src ${panel.webview.cspSource} data: https:; font-src ${panel.webview.cspSource}; script-src 'none';">`;

  // Inject CSP into <head> if it exists, otherwise prepend to HTML
  if (html.includes("<head>")) {
    html = html.replace("<head>", `<head>\n${csp}`);
  } else if (html.includes("<HEAD>")) {
    html = html.replace("<HEAD>", `<HEAD>\n${csp}`);
  } else {
    html = csp + "\n" + html;
  }

  return html;
}

/**
 * Open or focus the report Webview panel; reuses existing panel and refreshes content.
 * @param htmlFilePath - Absolute path to the HTML file to display
 */
function showReportInPanel(htmlFilePath: string): void {
  if (reportPanel) {
    reportPanel.reveal(ViewColumn.One);
    reportPanel.webview.html = getHtmlForWebview(reportPanel, htmlFilePath);
    return;
  }

  reportPanel = window.createWebviewPanel(
    "aegisReport",
    "Aegis Scan Report",
    ViewColumn.One,
    {
      enableScripts: false,
      localResourceRoots: [Uri.file(path.dirname(htmlFilePath))],
    }
  );
  reportPanel.webview.html = getHtmlForWebview(reportPanel, htmlFilePath);
  reportPanel.onDidDispose(() => {
    reportPanel = undefined;
  });
}

/**
 * Show report flow: find latest scan-report.html, or open file picker.
 * @returns No-op if user cancels or no file selected
 */
export async function showReport(): Promise<void> {
  const latest = findLatestScanReport();
  if (latest) {
    showReportInPanel(latest);
    return;
  }

  const picked = await window.showOpenDialog({
    title: "Select Aegis Scan Report (HTML)",
    filters: { "HTML Files": ["html"] },
    canSelectMany: false,
  });
  if (picked && picked.length > 0) {
    showReportInPanel(picked[0].fsPath);
  } else {
    window.showInformationMessage(
      "No scan-report.html found. Run 'aegis-scan --format html --output scan-report.html' to generate a report, or use Aegis: Scan Workspace."
    );
  }
}

