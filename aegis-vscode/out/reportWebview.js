"use strict";
/**
 * @fileoverview Webview panel: display Aegis scan HTML report within the IDE
 *
 * Supports: finding the latest scan-report.html in workspace, or user file selection.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.showReport = showReport;
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
const vscode_1 = require("vscode");
/** Currently open Webview panel (singleton reuse) */
let reportPanel;
/**
 * Find the latest scan-report.html in workspace folders.
 * @returns Absolute path to newest report file, or undefined if not found
 */
function findLatestScanReport() {
    const folders = vscode_1.workspace.workspaceFolders;
    if (!folders || folders.length === 0)
        return undefined;
    let latestPath;
    let latestMtime = 0;
    for (const folder of folders) {
        const reportPath = path.join(folder.uri.fsPath, "scan-report.html");
        try {
            const stat = fs.statSync(reportPath);
            if (stat.mtimeMs > latestMtime) {
                latestMtime = stat.mtimeMs;
                latestPath = reportPath;
            }
        }
        catch {
            // File not found or unreadable, skip
        }
        // Also check aegis-ai-core subdirectory
        const coreReportPath = path.join(folder.uri.fsPath, "aegis-ai-core", "scan-report.html");
        try {
            const stat = fs.statSync(coreReportPath);
            if (stat.mtimeMs > latestMtime) {
                latestMtime = stat.mtimeMs;
                latestPath = coreReportPath;
            }
        }
        catch {
            // ignore
        }
    }
    return latestPath;
}
/**
 * Convert local HTML file content for safe display in Webview.
 * Injects Content Security Policy.
 */
function getHtmlForWebview(panel, filePath) {
    const dir = path.dirname(filePath);
    let html = fs.readFileSync(filePath, "utf-8");
    // Inject Content Security Policy to prevent XSS
    const csp = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${panel.webview.cspSource} 'unsafe-inline'; img-src ${panel.webview.cspSource} data: https:; font-src ${panel.webview.cspSource}; script-src 'none';">`;
    // Inject CSP into <head> if it exists, otherwise prepend to HTML
    if (html.includes("<head>")) {
        html = html.replace("<head>", `<head>\n${csp}`);
    }
    else if (html.includes("<HEAD>")) {
        html = html.replace("<HEAD>", `<HEAD>\n${csp}`);
    }
    else {
        html = csp + "\n" + html;
    }
    return html;
}
/**
 * Open or focus the report Webview panel; reuses existing panel and refreshes content.
 * @param htmlFilePath - Absolute path to the HTML file to display
 */
function showReportInPanel(htmlFilePath) {
    if (reportPanel) {
        reportPanel.reveal(vscode_1.ViewColumn.One);
        reportPanel.webview.html = getHtmlForWebview(reportPanel, htmlFilePath);
        return;
    }
    reportPanel = vscode_1.window.createWebviewPanel("aegisReport", "Aegis Scan Report", vscode_1.ViewColumn.One, {
        enableScripts: false,
        localResourceRoots: [vscode_1.Uri.file(path.dirname(htmlFilePath))],
    });
    reportPanel.webview.html = getHtmlForWebview(reportPanel, htmlFilePath);
    reportPanel.onDidDispose(() => {
        reportPanel = undefined;
    });
}
/**
 * Show report flow: find latest scan-report.html, or open file picker.
 * @returns No-op if user cancels or no file selected
 */
async function showReport() {
    const latest = findLatestScanReport();
    if (latest) {
        showReportInPanel(latest);
        return;
    }
    const picked = await vscode_1.window.showOpenDialog({
        title: "Select Aegis Scan Report (HTML)",
        filters: { "HTML Files": ["html"] },
        canSelectMany: false,
    });
    if (picked && picked.length > 0) {
        showReportInPanel(picked[0].fsPath);
    }
    else {
        vscode_1.window.showInformationMessage("No scan-report.html found. Run 'aegis-scan --format html --output scan-report.html' to generate a report, or use Aegis: Scan Workspace.");
    }
}
//# sourceMappingURL=reportWebview.js.map