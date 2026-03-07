"use strict";
/**
 * @fileoverview Webview 面板：在 IDE 内展示 Aegis 扫描 HTML 报告
 *
 * 支持：查找工作区内最新 scan-report.html，或由用户选择 HTML 文件。
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
/** 当前已打开的 Webview 面板（单例复用） */
let reportPanel;
/**
 * 在工作区内查找 scan-report.html，返回按 mtime 最新的一个路径。
 * @returns 最新报告文件的绝对路径，未找到则 undefined
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
            // 文件不存在或不可读，忽略
        }
        // 也检查 aegis-ai-core 子目录
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
 * 将本地 HTML 文件内容转换为可在 Webview 中安全加载的形式。
 * 替换 src/href 为 webview 可访问的 URI。
 */
function getHtmlForWebview(panel, filePath) {
    const uri = vscode_1.Uri.file(filePath);
    const dir = path.dirname(filePath);
    let html = fs.readFileSync(filePath, "utf-8");
    // 若 HTML 内引用相对路径资源，可在此做替换；当前仅展示单文件 HTML
    // 简单场景下直接返回内容即可
    const baseUri = panel.webview.asWebviewUri(vscode_1.Uri.file(dir));
    // 将相对路径的 src="xxx" 转为 webview 可访问的绝对 URI（可选，按需实现）
    return html;
}
/**
 * 打开或聚焦报告 Webview；若已有面板则复用并刷新内容。
 * @param htmlFilePath - 要展示的 HTML 文件绝对路径
 */
function showReportInPanel(htmlFilePath) {
    if (reportPanel) {
        reportPanel.reveal(vscode_1.ViewColumn.One);
        reportPanel.webview.html = getHtmlForWebview(reportPanel, htmlFilePath);
        return;
    }
    reportPanel = vscode_1.window.createWebviewPanel("aegisReport", "Aegis 扫描报告", vscode_1.ViewColumn.One, {
        enableScripts: true,
        localResourceRoots: [vscode_1.Uri.file(path.dirname(htmlFilePath))],
    });
    reportPanel.webview.html = getHtmlForWebview(reportPanel, htmlFilePath);
    reportPanel.onDidDispose(() => {
        reportPanel = undefined;
    });
}
/**
 * 执行「显示报告」流程：先查找最新 scan-report.html，若无则弹出文件选择。
 * @returns 若用户取消或未选文件则无操作
 */
async function showReport() {
    const latest = findLatestScanReport();
    if (latest) {
        showReportInPanel(latest);
        return;
    }
    const picked = await vscode_1.window.showOpenDialog({
        title: "选择 Aegis 扫描报告 (HTML)",
        filters: { "HTML 文件": ["html"] },
        canSelectMany: false,
    });
    if (picked && picked.length > 0) {
        showReportInPanel(picked[0].fsPath);
    }
    else {
        vscode_1.window.showInformationMessage("未找到 scan-report.html。请先运行 aegis-scan --format html --output scan-report.html 生成报告。");
    }
}
//# sourceMappingURL=reportWebview.js.map