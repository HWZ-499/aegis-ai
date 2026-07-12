/**
 * @fileoverview TreeView data provider for Aegis Security findings.
 * Groups diagnostics from the "Aegis AI" source by category (type) and file.
 */

import {
  TreeDataProvider,
  TreeItem,
  TreeItemCollapsibleState,
  Diagnostic,
  DiagnosticSeverity,
  Disposable,
  Event,
  EventEmitter,
  ThemeIcon,
  Uri,
  languages,
  window,
} from "vscode";

export const AEGIS_SOURCE = "Aegis AI";

export function getAegisDiagnostics(diagnostics: readonly Diagnostic[]): Diagnostic[] {
  return diagnostics.filter((diagnostic) => diagnostic.source === AEGIS_SOURCE);
}

export function severityLabel(severity: number): string {
  switch (severity) {
    case DiagnosticSeverity.Error:
      return "Critical / High";
    case DiagnosticSeverity.Warning:
      return "Medium";
    case DiagnosticSeverity.Information:
      return "Low";
    case DiagnosticSeverity.Hint:
      return "Info";
    default:
      return "Unknown";
  }
}

interface FindingSortKey {
  severity: number;
  line: number;
  message: string;
}

export function compareFindingPriority(left: FindingSortKey, right: FindingSortKey): number {
  return left.severity - right.severity
    || left.line - right.line
    || left.message.localeCompare(right.message);
}

/** Group key: vuln type or "Other" */
interface GroupNode {
  kind: "group";
  label: string;
  type: string;
  severity: number;
}

/** File under a group */
interface FileNode {
  kind: "file";
  uri: Uri;
  type: string;
  count: number;
  severity: number;
}

/** Single finding (line) */
interface FindingNode {
  kind: "finding";
  uri: Uri;
  line: number;
  message: string;
  severity: number;
  ruleId: string;
  hasTaintPath: boolean;
}

type TreeNode = GroupNode | FileNode | FindingNode;

export function summarizeFindingMessage(message: string): string {
  for (const rawLine of message.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line) {
      return line;
    }
  }
  return message.trim();
}

function isGroupNode(n: TreeNode): n is GroupNode {
  return n.kind === "group";
}
function isFileNode(n: TreeNode): n is FileNode {
  return n.kind === "file";
}

/**
 * TreeDataProvider that lists Aegis AI diagnostics grouped by type and file.
 */
export class FindingsTreeProvider implements TreeDataProvider<TreeNode>, Disposable {
  private _onDidChangeTreeData = new EventEmitter<TreeNode | undefined | void>();
  readonly onDidChangeTreeData: Event<TreeNode | undefined | void> = this._onDidChangeTreeData.event;
  private readonly subscriptions: Disposable[];

  constructor() {
    this.subscriptions = [
      languages.onDidChangeDiagnostics(() => this._onDidChangeTreeData.fire()),
      window.onDidChangeActiveTextEditor(() => this._onDidChangeTreeData.fire()),
    ];
  }

  dispose(): void {
    for (const subscription of this.subscriptions) {
      subscription.dispose();
    }
    this._onDidChangeTreeData.dispose();
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: TreeNode): TreeItem {
    if (isGroupNode(element)) {
      const item = new TreeItem(element.label, TreeItemCollapsibleState.Expanded);
      item.contextValue = "aegisGroup";
      item.description = severityLabel(element.severity);
      item.iconPath = severityIcon(element.severity);
      return item;
    }
    if (isFileNode(element)) {
      const item = new TreeItem(element.uri.fsPath.split(/[/\\]/).pop() ?? element.uri.fsPath, TreeItemCollapsibleState.Expanded);
      item.resourceUri = element.uri;
      item.description = `${element.count}`;
      item.contextValue = "aegisFile";
      item.tooltip = `${element.uri.fsPath} · ${element.count} finding${element.count === 1 ? "" : "s"}`;
      return item;
    }
    const finding = element as FindingNode;
    const item = new TreeItem(
      `L${finding.line}: ${summarizeFindingMessage(finding.message)}`,
      TreeItemCollapsibleState.None,
    );
    item.resourceUri = finding.uri;
    item.description = severityLabel(finding.severity);
    item.iconPath = severityIcon(finding.severity);
    item.command = {
      command: "vscode.open",
      title: "Go to line",
      arguments: [finding.uri, { selection: { start: { line: finding.line - 1, character: 0 }, end: { line: finding.line - 1, character: 0 } } }],
    };
    item.tooltip = `${severityLabel(finding.severity)} · ${finding.message}`;
    item.contextValue = finding.hasTaintPath ? "aegisFindingWithTaintPath" : "aegisFinding";
    return item;
  }

  getChildren(element?: TreeNode): TreeNode[] {
    const allDiags = languages.getDiagnostics();
    const aegisByType = new Map<string, Map<string, { line: number; message: string; severity: number; ruleId: string; hasTaintPath: boolean }[]>>();

    for (const [uri, diags] of allDiags) {
      const aegis = getAegisDiagnostics(diags);
      if (aegis.length === 0) continue;

      const uriStr = uri.toString();
      for (const d of aegis) {
        const type = typeof d.code === "string" ? d.code : (d.code as { value: string })?.value ?? "Other";
        if (!aegisByType.has(type)) {
          aegisByType.set(type, new Map());
        }
        const byFile = aegisByType.get(type)!;
        if (!byFile.has(uriStr)) byFile.set(uriStr, []);
        const line = d.range.start.line + 1;
        const ruleId = type;
        // O3: check if diagnostic carries taint path data
        const diagData = (d as any).data;
        const hasTaintPath = !!(diagData && diagData.taintPath && diagData.taintPath.nodes && diagData.taintPath.nodes.length > 0);
        byFile.get(uriStr)!.push({ line, message: d.message, severity: d.severity, ruleId, hasTaintPath });
      }
    }

    if (element === undefined) {
      return Array.from(aegisByType.entries())
        .map(([type, byFile]) => {
          const findings = Array.from(byFile.values()).flat();
          return {
            kind: "group" as const,
            label: `${type} (${findings.length})`,
            type,
            severity: Math.min(...findings.map((finding) => finding.severity)),
          };
        })
        .sort((left, right) => left.severity - right.severity || left.type.localeCompare(right.type));
    }

    if (isGroupNode(element)) {
      const byFile = aegisByType.get(element.type);
      if (!byFile) return [];
      return Array.from(byFile.entries())
        .map(([uriStr, findings]) => ({
          kind: "file" as const,
          uri: Uri.parse(uriStr),
          type: element.type,
          count: findings.length,
          severity: Math.min(...findings.map((finding) => finding.severity)),
        }))
        .sort((left, right) => left.severity - right.severity || left.uri.fsPath.localeCompare(right.uri.fsPath));
    }

    if (isFileNode(element)) {
      const byFile = aegisByType.get(element.type);
      if (!byFile) return [];
      const list = byFile.get(element.uri.toString());
      if (!list) return [];
      return [...list]
        .sort(compareFindingPriority)
        .map((f) => ({
          kind: "finding" as const,
          uri: element.uri,
          line: f.line,
          message: f.message,
          severity: f.severity,
          ruleId: f.ruleId,
          hasTaintPath: f.hasTaintPath,
        }));
    }

    return [];
  }
}

function severityIcon(severity: number): ThemeIcon {
  switch (severity) {
    case DiagnosticSeverity.Error:
      return new ThemeIcon("error");
    case DiagnosticSeverity.Warning:
      return new ThemeIcon("warning");
    case DiagnosticSeverity.Information:
      return new ThemeIcon("info");
    default:
      return new ThemeIcon("lightbulb");
  }
}
