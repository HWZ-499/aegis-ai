"use strict";
/**
 * @fileoverview TreeView data provider for Aegis Security findings.
 * Groups diagnostics from the "Aegis AI" source by category (type) and file.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.FindingsTreeProvider = void 0;
const vscode_1 = require("vscode");
const AEGIS_SOURCE = "Aegis AI";
function isGroupNode(n) {
    return n.kind === "group";
}
function isFileNode(n) {
    return n.kind === "file";
}
/**
 * TreeDataProvider that lists Aegis AI diagnostics grouped by type and file.
 */
class FindingsTreeProvider {
    constructor() {
        this._onDidChangeTreeData = new vscode_1.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
        vscode_1.languages.onDidChangeDiagnostics(() => this._onDidChangeTreeData.fire());
        vscode_1.window.onDidChangeActiveTextEditor(() => this._onDidChangeTreeData.fire());
    }
    refresh() {
        this._onDidChangeTreeData.fire();
    }
    getTreeItem(element) {
        if (isGroupNode(element)) {
            const item = new vscode_1.TreeItem(element.label, vscode_1.TreeItemCollapsibleState.Expanded);
            item.contextValue = "aegisGroup";
            return item;
        }
        if (isFileNode(element)) {
            const item = new vscode_1.TreeItem(element.uri.fsPath.split(/[/\\]/).pop() ?? element.uri.fsPath, vscode_1.TreeItemCollapsibleState.Expanded);
            item.resourceUri = element.uri;
            item.contextValue = "aegisFile";
            item.tooltip = element.uri.fsPath;
            return item;
        }
        const finding = element;
        const item = new vscode_1.TreeItem(`L${finding.line}: ${finding.message}`, vscode_1.TreeItemCollapsibleState.None);
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
    getChildren(element) {
        const allDiags = vscode_1.languages.getDiagnostics();
        const aegisByType = new Map();
        for (const [uri, diags] of allDiags) {
            const aegis = diags.filter((d) => d.source === AEGIS_SOURCE);
            if (aegis.length === 0)
                continue;
            const uriStr = uri.toString();
            for (const d of aegis) {
                const type = typeof d.code === "string" ? d.code : d.code?.value ?? "Other";
                if (!aegisByType.has(type)) {
                    aegisByType.set(type, new Map());
                }
                const byFile = aegisByType.get(type);
                if (!byFile.has(uriStr))
                    byFile.set(uriStr, []);
                const line = d.range.start.line + 1;
                byFile.get(uriStr).push({ line, message: d.message, severity: d.severity });
            }
        }
        if (element === undefined) {
            return Array.from(aegisByType.entries()).map(([type, byFile]) => ({
                kind: "group",
                label: type,
                type,
            }));
        }
        if (isGroupNode(element)) {
            const byFile = aegisByType.get(element.type);
            if (!byFile)
                return [];
            return Array.from(byFile.keys()).map((uriStr) => ({
                kind: "file",
                uri: vscode_1.Uri.parse(uriStr),
                type: element.type,
            }));
        }
        if (isFileNode(element)) {
            const byFile = aegisByType.get(element.type);
            if (!byFile)
                return [];
            const list = byFile.get(element.uri.toString());
            if (!list)
                return [];
            return list.map((f) => ({
                kind: "finding",
                uri: element.uri,
                line: f.line,
                message: f.message,
                severity: f.severity,
            }));
        }
        return [];
    }
}
exports.FindingsTreeProvider = FindingsTreeProvider;
//# sourceMappingURL=findingsTreeProvider.js.map