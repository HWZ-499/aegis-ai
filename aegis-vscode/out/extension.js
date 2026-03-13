"use strict";
/**
 * @fileoverview Aegis AI Security Scanner — VSCode/Cursor Extension 入口
 *
 * 职责：
 * - 启动 Python LSP Server 进程（通过 stdio 通信）
 * - 创建 LanguageClient 连接 LSP Server
 * - Status Bar 实时显示扫描状态（就绪 / 扫描中 / N 个问题 / 安全）
 * - 在 deactivate 时优雅关闭
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
exports.activate = activate;
exports.deactivate = deactivate;
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
const vscode_1 = require("vscode");
const findingsTreeProvider_1 = require("./findingsTreeProvider");
const reportWebview_1 = require("./reportWebview");
const node_1 = require("vscode-languageclient/node");
// ─── 自定义 LSP 通知类型（Python 服务端需对应发送） ─────────────────────────
/** Python 端发送 `aegis/scanStart` 通知，表示开始扫描当前文件 */
const NOTIFICATION_SCAN_START = "aegis/scanStart";
/** Python 端发送 `aegis/scanEnd` 通知，表示扫描完成（含结果摘要） */
const NOTIFICATION_SCAN_END = "aegis/scanEnd";
/** Python 端发送 `aegis/scanError` 通知，表示扫描出错 */
const NOTIFICATION_SCAN_ERROR = "aegis/scanError";
/** P5-4：工作区扫描进度 */
const NOTIFICATION_SCAN_PROGRESS = "aegis/scanProgress";
// ─── 全局状态 ────────────────────────────────────────────────────────────────
/** @type {LanguageClient | undefined} 全局 LSP 客户端实例 */
let client;
/** @type {StatusBarItem | undefined} Status Bar 图标实例 */
let statusBar;
/** @type {Disposable | undefined} 诊断变化监听器 */
let diagnosticsListener;
/** P5-4：工作区扫描进度条与结束回调 */
let workspaceProgressReporter = null;
let workspaceScanResolve = null;
/**
 * 更新 Status Bar 显示内容。
 *
 * @param {AegisStatus} status - 当前状态
 * @param {number} [issueCount] - 问题数量（仅 `issues` 状态下使用）
 */
function updateStatusBar(status, issueCount) {
    if (!statusBar)
        return;
    switch (status) {
        case "ready":
            statusBar.text = "$(shield) Aegis: 就绪";
            statusBar.tooltip = "Aegis AI 安全扫描就绪，保存文件时自动扫描";
            statusBar.backgroundColor = undefined;
            break;
        case "scanning":
            statusBar.text = "$(loading~spin) Aegis: 扫描中";
            statusBar.tooltip = "Aegis AI 正在分析当前文件…";
            statusBar.backgroundColor = undefined;
            break;
        case "issues":
            statusBar.text = `$(error) Aegis: ${issueCount ?? 0} 个问题`;
            statusBar.tooltip = `Aegis AI 发现 ${issueCount ?? 0} 个安全问题，点击查看诊断面板`;
            statusBar.command = "workbench.action.problems.focus";
            statusBar.backgroundColor = undefined;
            break;
        case "safe":
            statusBar.text = "$(check) Aegis: 安全";
            statusBar.tooltip = "Aegis AI 未在当前文件中发现安全问题";
            statusBar.backgroundColor = undefined;
            break;
        case "disconnected":
            statusBar.text = "$(warning) Aegis: 未连接";
            statusBar.tooltip = "Aegis AI LSP Server 未连接，请检查配置";
            statusBar.command = "workbench.action.openSettings";
            statusBar.backgroundColor = undefined;
            break;
        case "error":
            statusBar.text = "$(error) Aegis: 扫描错误";
            statusBar.tooltip = "Aegis AI 扫描出错，点击查看日志";
            statusBar.command = "aegisAI.showOutput";
            statusBar.backgroundColor = undefined;
            break;
    }
}
/**
 * 根据当前活跃文件的 Aegis 诊断数量更新 Status Bar。
 * 无活跃文件或诊断为 0 时显示「安全」，否则显示「N 个问题」。
 */
function refreshStatusBarFromDiagnostics() {
    const activeEditor = vscode_1.window.activeTextEditor;
    if (!activeEditor) {
        updateStatusBar("ready");
        return;
    }
    const uri = activeEditor.document.uri;
    const allDiags = vscode_1.languages.getDiagnostics(uri);
    // 只统计 Aegis AI 来源的诊断（source 字段匹配）
    const aegisDiags = allDiags.filter((d) => d.source === "Aegis AI" &&
        (d.severity === vscode_1.DiagnosticSeverity.Error ||
            d.severity === vscode_1.DiagnosticSeverity.Warning));
    if (aegisDiags.length === 0) {
        updateStatusBar("safe");
    }
    else {
        updateStatusBar("issues", aegisDiags.length);
    }
}
/**
 * 扩展激活时调用。
 *
 * @param {ExtensionContext} context - VSCode 扩展上下文
 */
function activate(context) {
    const config = vscode_1.workspace.getConfiguration("aegisAI");
    // 检查是否启用
    if (!config.get("enabled", true)) {
        return;
    }
    const pythonPath = config.get("pythonPath", "python");
    const serverModule = config.get("serverModule", "src.lsp");
    const explicitCwd = config.get("serverCwd", "").trim();
    const outputChannel = vscode_1.window.createOutputChannel("Aegis AI Security Scanner");
    outputChannel.appendLine("[Aegis] 扩展已激活，正在启动 LSP Server…");
    // ── Status Bar 初始化（最高优先级，始终可见）────────────────────────────
    statusBar = vscode_1.window.createStatusBarItem(vscode_1.StatusBarAlignment.Left, 100);
    statusBar.text = "$(sync~spin) Aegis: 连接中…";
    statusBar.tooltip = "Aegis AI 正在连接 LSP Server";
    statusBar.show();
    context.subscriptions.push(statusBar);
    // Aegis Findings TreeView（侧边栏「Aegis Security」面板）
    const findingsProvider = new findingsTreeProvider_1.FindingsTreeProvider();
    const treeView = vscode_1.window.createTreeView("aegisFindings", {
        treeDataProvider: findingsProvider,
        showCollapseAll: true,
    });
    context.subscriptions.push(treeView);
    // P1-2：注册命令（showOutput 不依赖 client；扫描命令在 client 就绪后可用）
    context.subscriptions.push(vscode_1.commands.registerCommand("aegisAI.showOutput", () => {
        outputChannel.show();
    }), vscode_1.commands.registerCommand("aegisAI.showReport", () => {
        (0, reportWebview_1.showReport)();
    }));
    context.subscriptions.push(vscode_1.commands.registerCommand("aegisAI.scanCurrentFile", (resourceUri) => {
        // Support both editor context and explorer context menu
        const uri = resourceUri?.toString() ?? vscode_1.window.activeTextEditor?.document.uri.toString();
        if (!uri)
            return;
        if (!client) {
            outputChannel.appendLine("[Aegis] 未连接，无法扫描。请等待 LSP 连接后再试。");
            outputChannel.show();
            return;
        }
        client.sendNotification("aegis/requestScan", { uri });
        outputChannel.appendLine(`[Aegis] 手动触发扫描: ${uri}`);
    }), vscode_1.commands.registerCommand("aegisAI.scanWorkspace", () => {
        if (!client) {
            outputChannel.appendLine("[Aegis] 未连接，无法扫描。请等待 LSP 连接后再试。");
            outputChannel.show();
            return;
        }
        outputChannel.appendLine("[Aegis] 手动触发工作区扫描");
        vscode_1.window.withProgress({
            title: "Aegis: 扫描工作区",
            location: vscode_1.ProgressLocation.Notification,
            cancellable: false,
        }, (progress) => {
            workspaceProgressReporter = progress;
            return new Promise((resolve) => {
                workspaceScanResolve = resolve;
                client.sendNotification("aegis/requestScanWorkspace", {});
            });
        }).then(() => {
            workspaceProgressReporter = null;
            workspaceScanResolve = null;
        });
    }));
    // aegis-ai-core 目录：LSP Server 需在 aegis-ai-core 下执行 python -m src.lsp
    let cwd;
    if (explicitCwd) {
        cwd = path.isAbsolute(explicitCwd)
            ? explicitCwd
            : path.resolve(vscode_1.workspace.workspaceFolders?.[0]?.uri.fsPath ?? "", explicitCwd);
        if (!fs.existsSync(cwd)) {
            outputChannel.appendLine(`[Aegis] serverCwd 不存在，将回退自动推断: ${cwd}`);
            cwd = undefined;
        }
        else {
            outputChannel.appendLine(`[Aegis] 使用配置的 serverCwd: ${cwd}`);
        }
    }
    if (cwd === undefined &&
        vscode_1.workspace.workspaceFolders &&
        vscode_1.workspace.workspaceFolders.length > 0) {
        const rootPath = vscode_1.workspace.workspaceFolders[0].uri.fsPath;
        const rootName = path.basename(rootPath);
        if (rootName === "aegis-ai-core") {
            cwd = rootPath;
        }
        else {
            cwd = path.join(rootPath, "aegis-ai-core");
        }
        if (!fs.existsSync(cwd)) {
            outputChannel.appendLine(`[Aegis] 自动推断的目录不存在，LSP 可能无法启动: ${cwd}`);
        }
        else {
            outputChannel.appendLine(`[Aegis] 使用工作目录: ${cwd}`);
        }
    }
    // 无工作区或目录无效时：尝试扩展所在目录的兄弟 aegis-ai-core（开发/单文件场景）
    if (cwd === undefined || !fs.existsSync(cwd)) {
        const extDir = context.extensionPath;
        const siblingCwd = path.join(path.dirname(extDir), "aegis-ai-core");
        if (fs.existsSync(siblingCwd)) {
            cwd = siblingCwd;
            outputChannel.appendLine(`[Aegis] 使用扩展同级目录: ${cwd}`);
        }
        else if (cwd === undefined) {
            outputChannel.appendLine("[Aegis] 未打开工作区且未找到 aegis-ai-core，请打开包含 aegis-ai-core 的文件夹。");
        }
    }
    outputChannel.appendLine(`[Aegis] Python: ${pythonPath}, 模块: ${serverModule}`);
    if (!cwd || !fs.existsSync(cwd)) {
        outputChannel.appendLine("[Aegis] 无法启动：未找到有效的 aegis-ai-core 目录。请用「文件 → 打开文件夹」打开 aegis-ai 或 aegis-ai-core，或在设置中填写 aegisAI.serverCwd。");
        outputChannel.show();
        updateStatusBar("disconnected");
        return;
    }
    /**
     * Server 启动配置：通过 stdio 启动 Python 进程。
     * 命令: python -m src.lsp
     */
    const serverOptions = {
        command: pythonPath,
        args: ["-m", serverModule],
        options: {
            cwd: cwd,
        },
    };
    /**
     * 客户端配置：指定监听的文档类型，并将 LSP 日志输出到我们的通道。
     * 通过 initializationOptions 将用户配置传递给 LSP Server。
     */
    const clientOptions = {
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
        revealOutputChannelOn: node_1.RevealOutputChannelOn.Error,
        initializationOptions: {
            severity_minimum: config.get("severity.minimum", "Low"),
            exclude_patterns: config.get("excludePatterns", []),
            disabled_rules: config.get("disabledRules", []),
            ai_enabled: config.get("ai.enabled", true),
            ai_provider: config.get("ai.provider", "deepseek"),
            scan_on_save: config.get("scanOnSave", true),
            scan_on_change: config.get("scanOnChange", true),
        },
        synchronize: {
            fileEvents: vscode_1.workspace.createFileSystemWatcher("**/*.{js,jsx,ts,tsx,py,php,phtml,java,go}"),
        },
    };
    // 创建 LanguageClient 并启动
    client = new node_1.LanguageClient("aegisAI", "Aegis AI Security Scanner", serverOptions, clientOptions);
    client.start().then(() => {
        outputChannel.appendLine("[Aegis] LSP Server 已连接。");
        updateStatusBar("ready");
        vscode_1.window.showInformationMessage("Aegis AI Security Scanner is now active.");
        // ── 监听 LSP 自定义通知：扫描开始 ─────────────────────────────────
        client.onNotification(NOTIFICATION_SCAN_START, () => {
            updateStatusBar("scanning");
        });
        // ── 监听 LSP 自定义通知：扫描结束 ─────────────────────────────────
        client.onNotification(NOTIFICATION_SCAN_END, (params) => {
            if (typeof params?.issueCount === "number") {
                if (params.issueCount > 0) {
                    updateStatusBar("issues", params.issueCount);
                }
                else {
                    updateStatusBar("safe");
                }
            }
            else {
                // 无通知参数时从诊断集合推断
                refreshStatusBarFromDiagnostics();
            }
        });
        // ── 监听 LSP 自定义通知：扫描错误（P1-1）────────────────────────────
        client.onNotification(NOTIFICATION_SCAN_ERROR, (params) => {
            updateStatusBar("error");
            outputChannel.appendLine(`[Aegis] 扫描错误: ${params?.message ?? "unknown"} (${params?.uri ?? ""})`);
        });
        // ── 监听 LSP 自定义通知：工作区扫描进度（P5-4）──────────────────────
        client.onNotification(NOTIFICATION_SCAN_PROGRESS, (params) => {
            const cur = params?.current ?? 0;
            const tot = params?.total ?? 0;
            if (workspaceProgressReporter && tot > 0) {
                workspaceProgressReporter.report({
                    message: `正在扫描 ${cur}/${tot}`,
                    increment: tot > 0 ? (100 / tot) : 0,
                });
            }
            if (cur === tot && workspaceScanResolve) {
                workspaceScanResolve();
            }
        });
        // ── 监听活跃编辑器切换：切换文件时刷新状态栏 ──────────────────────
        context.subscriptions.push(vscode_1.window.onDidChangeActiveTextEditor(() => {
            refreshStatusBarFromDiagnostics();
        }));
        // ── 监听诊断变化：LSP 发布新诊断后刷新状态栏 ──────────────────────
        // （兜底：即使服务端未发送自定义通知也能正确更新）
        diagnosticsListener = vscode_1.languages.onDidChangeDiagnostics((e) => {
            const activeUri = vscode_1.window.activeTextEditor?.document.uri;
            if (activeUri &&
                e.uris.some((u) => u.toString() === activeUri.toString())) {
                // 扫描完成后延迟 200ms 读取最新诊断（避免读到旧快照）
                setTimeout(refreshStatusBarFromDiagnostics, 200);
            }
        });
        context.subscriptions.push(diagnosticsListener);
    }, (error) => {
        const msg = error instanceof Error ? error.message : String(error);
        updateStatusBar("disconnected");
        outputChannel.appendLine(`[Aegis] LSP Server 启动失败: ${msg}`);
        // 提供操作按钮引导用户解决配置问题
        vscode_1.window
            .showErrorMessage(`Aegis AI LSP 启动失败: ${msg}`, "配置 Python 路径", "查看日志")
            .then((action) => {
            if (action === "配置 Python 路径") {
                vscode_1.commands.executeCommand("workbench.action.openSettings", "aegisAI.pythonPath");
            }
            else if (action === "查看日志") {
                outputChannel.show();
            }
        });
    });
    context.subscriptions.push({
        dispose: () => {
            if (client) {
                client.stop();
            }
        },
    });
}
/**
 * 扩展停用时调用。
 *
 * @returns {Thenable<void> | undefined} 停止 LSP 客户端的 Promise
 */
function deactivate() {
    if (!client) {
        return undefined;
    }
    return client.stop();
}
//# sourceMappingURL=extension.js.map