/**
 * @fileoverview TreeView data provider for Aegis Security findings.
 * Groups diagnostics from the "Aegis AI" source by category (type) and file.
 */

import {
  TreeDataProvider,
  TreeItem,
  TreeItemCollapsibleState,
  Event,
  EventEmitter,
  Uri,
  languages,
  window,
} from "vscode";

const AEGIS_SOURCE = "Aegis AI";

/** Group key: vuln type or "Other" */
interface GroupNode {
  kind: "group";
  label: string;
  type: string;
}

/** File under a group */
interface FileNode {
  kind: "file";
  uri: Uri;
  type: string;
}

/** Single finding (line) */
interface FindingNode {
  kind: "finding";
  uri: Uri;
  line: number;
  message: string;
  severity: number;
}

type TreeNode = GroupNode | FileNode | FindingNode;

function isGroupNode(n: TreeNode): n is GroupNode {
  return n.kind === "group";
}
function isFileNode(n: TreeNode): n is FileNode {
  return n.kind === "file";
}

/**
 * TreeDataProvider that lists Aegis AI diagnostics grouped by type and file.
 */
export class FindingsTreeProvider implements TreeDataProvider<TreeNode> {
  private _onDidChangeTreeData = new EventEmitter<TreeNode | undefined | void>();
  readonly onDidChangeTreeData: Event<TreeNode | undefined | void> = this._onDidChangeTreeData.event;

  constructor() {
    languages.onDidChangeDiagnostics(() => this._onDidChangeTreeData.fire());
    window.onDidChangeActiveTextEditor(() => this._onDidChangeTreeData.fire());
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: TreeNode): TreeItem {
    if (isGroupNode(element)) {
      const item = new TreeItem(element.label, TreeItemCollapsibleState.Expanded);
      item.contextValue = "aegisGroup";
      return item;
    }
    if (isFileNode(element)) {
      const item = new TreeItem(element.uri.fsPath.split(/[/\\]/).pop() ?? element.uri.fsPath, TreeItemCollapsibleState.Expanded);
      item.resourceUri = element.uri;
      item.contextValue = "aegisFile";
      item.tooltip = element.uri.fsPath;
      return item;
    }
    const finding = element as FindingNode;
    const item = new TreeItem(`L${finding.line}: ${finding.message}`, TreeItemCollapsibleState.None);
    item.resourceUri = finding.uri;
    item.command = {
      command: "vscode.open",
      title: "Go to line",
      arguments: [finding.uri, { selection: { start: { line: finding.line - 1, character: 0 }, end: { line: finding.line - 1, character: 0 } } }],
    };
    item.tooltip = finding.message;
    item.contextValue = "aegisFinding";
    return item;
  }

  getChildren(element?: TreeNode): TreeNode[] {
    const allDiags = languages.getDiagnostics();
    const aegisByType = new Map<string, Map<string, { line: number; message: string; severity: number }[]>>();

    for (const [uri, diags] of allDiags) {
      const aegis = diags.filter((d) => d.source === AEGIS_SOURCE);
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
        byFile.get(uriStr)!.push({ line, message: d.message, severity: d.severity });
      }
    }

    if (element === undefined) {
      return Array.from(aegisByType.entries()).map(([type, byFile]) => ({
        kind: "group" as const,
        label: type,
        type,
      }));
    }

    if (isGroupNode(element)) {
      const byFile = aegisByType.get(element.type);
      if (!byFile) return [];
      return Array.from(byFile.keys()).map((uriStr) => ({
        kind: "file" as const,
        uri: Uri.parse(uriStr),
        type: element.type,
      }));
    }

    if (isFileNode(element)) {
      const byFile = aegisByType.get(element.type);
      if (!byFile) return [];
      const list = byFile.get(element.uri.toString());
      if (!list) return [];
      return list.map((f) => ({
        kind: "finding" as const,
        uri: element.uri,
        line: f.line,
        message: f.message,
        severity: f.severity,
      }));
    }

    return [];
  }
}
