/**
 * @fileoverview Aegis AI Security Scanner — VSCode/Cursor Extension 入口
 *
 * 职责：
 * - 启动 Python LSP Server 进程（通过 stdio 通信）
 * - 创建 LanguageClient 连接 LSP Server
 * - Status Bar 实时显示扫描状态（就绪 / 扫描中 / N 个问题 / 安全）
 * - 在 deactivate 时优雅关闭
 */

import * as path from "path";
import * as fs from "fs";
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
} from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  RevealOutputChannelOn,
} from "vscode-languageclient/node";

// ─── 自定义 LSP 通知类型（Python 服务端需对应发送） ─────────────────────────

/** Python 端发送 `aegis/scanStart` 通知，表示开始扫描当前文件 */
const NOTIFICATION_SCAN_START = "aegis/scanStart";
/** Python 端发送 `aegis/scanEnd` 通知，表示扫描完成（含结果摘要） */
const NOTIFICATION_SCAN_END = "aegis/scanEnd";

// ─── 全局状态 ────────────────────────────────────────────────────────────────

/** @type {LanguageClient | undefined} 全局 LSP 客户端实例 */
let client: LanguageClient | undefined;

/** @type {StatusBarItem | undefined} Status Bar 图标实例 */
let statusBar: StatusBarItem | undefined;

/** @type {Disposable | undefined} 诊断变化监听器 */
let diagnosticsListener: Disposable | undefined;

// ─── Status Bar 状态枚举 ────────────────────────────────────────────────────

/** Status Bar 展示的四种状态 */
type AegisStatus = "ready" | "scanning" | "issues" | "safe" | "disconnected";

/**
 * 更新 Status Bar 显示内容。
 *
 * @param {AegisStatus} status - 当前状态
 * @param {number} [issueCount] - 问题数量（仅 `issues` 状态下使用）
 */
function updateStatusBar(status: AegisStatus, issueCount?: number): void {
  if (!statusBar) return;

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
  }
}

/**
 * 根据当前活跃文件的 Aegis 诊断数量更新 Status Bar。
 * 无活跃文件或诊断为 0 时显示「安全」，否则显示「N 个问题」。
 */
function refreshStatusBarFromDiagnostics(): void {
  const activeEditor = window.activeTextEditor;
  if (!activeEditor) {
    updateStatusBar("ready");
    return;
  }

  const uri: Uri = activeEditor.document.uri;
  const allDiags = languages.getDiagnostics(uri);
  // 只统计 Aegis AI 来源的诊断（source 字段匹配）
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
 * 扩展激活时调用。
 *
 * @param {ExtensionContext} context - VSCode 扩展上下文
 */
export function activate(context: ExtensionContext): void {
  const config = workspace.getConfiguration("aegisAI");

  // 检查是否启用
  if (!config.get<boolean>("enabled", true)) {
    return;
  }

  const pythonPath = config.get<string>("pythonPath", "python");
  const serverModule = config.get<string>("serverModule", "src.lsp");
  const explicitCwd = config.get<string>("serverCwd", "").trim();

  const outputChannel = window.createOutputChannel("Aegis AI Security Scanner");
  outputChannel.appendLine("[Aegis] 扩展已激活，正在启动 LSP Server…");

  // ── Status Bar 初始化（最高优先级，始终可见）────────────────────────────
  statusBar = window.createStatusBarItem(StatusBarAlignment.Left, 100);
  statusBar.text = "$(sync~spin) Aegis: 连接中…";
  statusBar.tooltip = "Aegis AI 正在连接 LSP Server";
  statusBar.show();
  context.subscriptions.push(statusBar);

  // aegis-ai-core 目录：LSP Server 需在 aegis-ai-core 下执行 python -m src.lsp
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
        `[Aegis] serverCwd 不存在，将回退自动推断: ${cwd}`
      );
      cwd = undefined;
    } else {
      outputChannel.appendLine(`[Aegis] 使用配置的 serverCwd: ${cwd}`);
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
        `[Aegis] 自动推断的目录不存在，LSP 可能无法启动: ${cwd}`
      );
    } else {
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
    } else if (cwd === undefined) {
      outputChannel.appendLine(
        "[Aegis] 未打开工作区且未找到 aegis-ai-core，请打开包含 aegis-ai-core 的文件夹。"
      );
    }
  }

  outputChannel.appendLine(`[Aegis] Python: ${pythonPath}, 模块: ${serverModule}`);

  if (!cwd || !fs.existsSync(cwd)) {
    outputChannel.appendLine(
      "[Aegis] 无法启动：未找到有效的 aegis-ai-core 目录。请用「文件 → 打开文件夹」打开 aegis-ai 或 aegis-ai-core，或在设置中填写 aegisAI.serverCwd。"
    );
    outputChannel.show();
    updateStatusBar("disconnected");
    return;
  }

  /**
   * Server 启动配置：通过 stdio 启动 Python 进程。
   * 命令: python -m src.lsp
   */
  const serverOptions: ServerOptions = {
    command: pythonPath,
    args: ["-m", serverModule],
    options: {
      cwd: cwd,
    },
  };

  /**
   * 客户端配置：指定监听的文档类型，并将 LSP 日志输出到我们的通道。
   */
  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: "file", language: "javascript" },
      { scheme: "file", language: "typescript" },
      { scheme: "file", language: "javascriptreact" },
      { scheme: "file", language: "typescriptreact" },
      { scheme: "file", language: "python" },
      { scheme: "file", language: "php" },
    ],
    outputChannel: outputChannel,
    revealOutputChannelOn: RevealOutputChannelOn.Error,
    synchronize: {
      fileEvents: workspace.createFileSystemWatcher(
        "**/*.{js,jsx,ts,tsx,py,php,phtml}"
      ),
    },
  };

  // 创建 LanguageClient 并启动
  client = new LanguageClient(
    "aegisAI",
    "Aegis AI Security Scanner",
    serverOptions,
    clientOptions
  );

  client.start().then(
    () => {
      outputChannel.appendLine("[Aegis] LSP Server 已连接。");
      updateStatusBar("ready");

      window.showInformationMessage("Aegis AI Security Scanner is now active.");

      // ── 监听 LSP 自定义通知：扫描开始 ─────────────────────────────────
      client!.onNotification(NOTIFICATION_SCAN_START, () => {
        updateStatusBar("scanning");
      });

      // ── 监听 LSP 自定义通知：扫描结束 ─────────────────────────────────
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
            // 无通知参数时从诊断集合推断
            refreshStatusBarFromDiagnostics();
          }
        }
      );

      // ── 监听活跃编辑器切换：切换文件时刷新状态栏 ──────────────────────
      context.subscriptions.push(
        window.onDidChangeActiveTextEditor(() => {
          refreshStatusBarFromDiagnostics();
        })
      );

      // ── 监听诊断变化：LSP 发布新诊断后刷新状态栏 ──────────────────────
      // （兜底：即使服务端未发送自定义通知也能正确更新）
      diagnosticsListener = languages.onDidChangeDiagnostics(
        (e: { uris: readonly Uri[] }) => {
          const activeUri = window.activeTextEditor?.document.uri;
          if (
            activeUri &&
            e.uris.some((u) => u.toString() === activeUri.toString())
          ) {
            // 扫描完成后延迟 200ms 读取最新诊断（避免读到旧快照）
            setTimeout(refreshStatusBarFromDiagnostics, 200);
          }
        }
      );
      context.subscriptions.push(diagnosticsListener);
    },
    (error: unknown) => {
      const msg = error instanceof Error ? error.message : String(error);
      updateStatusBar("disconnected");
      outputChannel.appendLine(`[Aegis] LSP Server 启动失败: ${msg}`);

      // 提供操作按钮引导用户解决配置问题
      window
        .showErrorMessage(
          `Aegis AI LSP 启动失败: ${msg}`,
          "配置 Python 路径",
          "查看日志"
        )
        .then((action) => {
          if (action === "配置 Python 路径") {
            commands.executeCommand(
              "workbench.action.openSettings",
              "aegisAI.pythonPath"
            );
          } else if (action === "查看日志") {
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
 * 扩展停用时调用。
 *
 * @returns {Thenable<void> | undefined} 停止 LSP 客户端的 Promise
 */
export function deactivate(): Thenable<void> | undefined {
  if (!client) {
    return undefined;
  }
  return client.stop();
}
