/**
 * @fileoverview Webview 面板：在 IDE 内展示 Aegis 扫描 HTML 报告
 *
 * 支持：查找工作区内最新 scan-report.html，或由用户选择 HTML 文件。
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

/** 当前已打开的 Webview 面板（单例复用） */
let reportPanel: WebviewPanel | undefined;

/**
 * 在工作区内查找 scan-report.html，返回按 mtime 最新的一个路径。
 * @returns 最新报告文件的绝对路径，未找到则 undefined
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
      // 文件不存在或不可读，忽略
    }
    // 也检查 aegis-ai-core 子目录
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
 * 将本地 HTML 文件内容转换为可在 Webview 中安全加载的形式。
 * 替换 src/href 为 webview 可访问的 URI。
 */
function getHtmlForWebview(panel: WebviewPanel, filePath: string): string {
  const dir = path.dirname(filePath);
  let html = fs.readFileSync(filePath, "utf-8");

  // 注入 Content Security Policy，防止 XSS
  const csp = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${panel.webview.cspSource} 'unsafe-inline'; img-src ${panel.webview.cspSource} data: https:; font-src ${panel.webview.cspSource}; script-src 'none';">`;

  // 插入 CSP 到 <head> 中（若存在），否则前置到 HTML 开头
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
 * 打开或聚焦报告 Webview；若已有面板则复用并刷新内容。
 * @param htmlFilePath - 要展示的 HTML 文件绝对路径
 */
function showReportInPanel(htmlFilePath: string): void {
  if (reportPanel) {
    reportPanel.reveal(ViewColumn.One);
    reportPanel.webview.html = getHtmlForWebview(reportPanel, htmlFilePath);
    return;
  }

  reportPanel = window.createWebviewPanel(
    "aegisReport",
    "Aegis 扫描报告",
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
 * 执行「显示报告」流程：先查找最新 scan-report.html，若无则弹出文件选择。
 * @returns 若用户取消或未选文件则无操作
 */
export async function showReport(): Promise<void> {
  const latest = findLatestScanReport();
  if (latest) {
    showReportInPanel(latest);
    return;
  }

  const picked = await window.showOpenDialog({
    title: "选择 Aegis 扫描报告 (HTML)",
    filters: { "HTML 文件": ["html"] },
    canSelectMany: false,
  });
  if (picked && picked.length > 0) {
    showReportInPanel(picked[0].fsPath);
  } else {
    window.showInformationMessage(
      "未找到 scan-report.html。请先运行 aegis-scan --format html --output scan-report.html 生成报告。"
    );
  }
}

