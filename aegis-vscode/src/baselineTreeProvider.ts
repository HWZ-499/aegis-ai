import * as fs from "fs";
import * as path from "path";
import {
  Event,
  EventEmitter,
  TreeDataProvider,
  TreeItem,
  TreeItemCollapsibleState,
  ThemeIcon,
  Uri,
  workspace,
} from "vscode";

export interface BaselineEntry {
  rule_id: string;
  file_path: string;
  line: number;
  fingerprint: string;
}

interface BaselineWorkspaceNode {
  kind: "workspace";
  workspaceRoot: string;
  count: number;
  invalidEntryCount: number;
  hasError: boolean;
}

interface BaselineFileNode {
  kind: "file";
  workspaceRoot: string;
  filePath: string;
  count: number;
}

interface BaselineRuleNode {
  kind: "rule";
  workspaceRoot: string;
  filePath: string;
  ruleId: string;
  count: number;
}

interface BaselineErrorNode {
  kind: "error";
  message: string;
}

interface BaselineWarningNode {
  kind: "warning";
  message: string;
}

export interface BaselineEntryNode {
  kind: "entry";
  entry: BaselineEntry;
  workspaceRoot: string;
}

type BaselineNode =
  | BaselineWorkspaceNode
  | BaselineFileNode
  | BaselineRuleNode
  | BaselineErrorNode
  | BaselineWarningNode
  | BaselineEntryNode;

export interface BaselineReadStatus {
  entries: BaselineEntry[];
  error?: string;
  invalidEntryCount: number;
}

function normalizeWorkspaceRoots(workspaceRoots: string | readonly string[] | undefined): string[] {
  const roots = typeof workspaceRoots === "string" ? [workspaceRoots] : [...(workspaceRoots ?? [])];
  return [...new Set(roots.filter(Boolean).map((root) => path.resolve(root)))].sort((a, b) => a.localeCompare(b));
}

function isBaselineEntry(item: unknown): item is BaselineEntry {
  if (!item || typeof item !== "object") {
    return false;
  }
  const candidate = item as Partial<BaselineEntry>;
  return typeof candidate.rule_id === "string"
    && candidate.rule_id.trim().length > 0
    && typeof candidate.file_path === "string"
    && candidate.file_path.trim().length > 0
    && typeof candidate.line === "number"
    && Number.isInteger(candidate.line)
    && candidate.line > 0
    && typeof candidate.fingerprint === "string"
    && candidate.fingerprint.trim().length > 0;
}

function sortEntries(entries: BaselineEntry[]): BaselineEntry[] {
  return [...entries].sort((a, b) => {
    const fileCompare = a.file_path.localeCompare(b.file_path);
    if (fileCompare !== 0) {
      return fileCompare;
    }
    if (a.line !== b.line) {
      return a.line - b.line;
    }
    const ruleCompare = a.rule_id.localeCompare(b.rule_id);
    if (ruleCompare !== 0) {
      return ruleCompare;
    }
    return a.fingerprint.localeCompare(b.fingerprint);
  });
}

export function resolveBaselineEntryPath(
  workspaceRoot: string | undefined,
  entryPath: string,
): string | undefined {
  if (!workspaceRoot || !entryPath) {
    return undefined;
  }

  const normalizedEntry = entryPath.replace(/\\/g, "/");
  if (
    path.isAbsolute(normalizedEntry)
    || normalizedEntry.split("/").some((segment) => segment === "..")
  ) {
    return undefined;
  }

  const rootPath = path.resolve(workspaceRoot);
  const targetPath = path.resolve(rootPath, ...normalizedEntry.split("/").filter(Boolean));
  const relative = path.relative(rootPath, targetPath);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    return undefined;
  }

  return targetPath;
}

export function readBaselineEntries(workspaceRoot: string | undefined): BaselineEntry[] {
  return readBaselineEntriesWithStatus(workspaceRoot).entries;
}

export function readBaselineEntriesWithStatus(workspaceRoot: string | undefined): BaselineReadStatus {
  if (!workspaceRoot) {
    return { entries: [], invalidEntryCount: 0 };
  }
  const baselinePath = path.join(workspaceRoot, ".aegis-baseline.json");
  if (!fs.existsSync(baselinePath)) {
    return { entries: [], invalidEntryCount: 0 };
  }

  try {
    const payload = JSON.parse(fs.readFileSync(baselinePath, "utf8"));
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      return {
        entries: [],
        error: `Cannot read baseline ${baselinePath}: root value must be an object.`,
        invalidEntryCount: 0,
      };
    }
    if (
      "findings" in payload
      && !Array.isArray(payload.findings)
    ) {
      return {
        entries: [],
        error: `Cannot read baseline ${baselinePath}: findings must be an array.`,
        invalidEntryCount: 0,
      };
    }
    const findings = Array.isArray(payload?.findings) ? payload.findings : [];
    const entries = findings.filter(isBaselineEntry);
    return {
      entries: sortEntries(entries),
      invalidEntryCount: findings.length - entries.length,
    };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return {
      entries: [],
      error: `Cannot read baseline ${baselinePath}: ${reason}`,
      invalidEntryCount: 0,
    };
  }
}

export function removeBaselineEntryFromDisk(workspaceRoot: string | undefined, fingerprint: string): boolean {
  if (!workspaceRoot) {
    return false;
  }

  const baselinePath = path.join(workspaceRoot, ".aegis-baseline.json");
  if (!fs.existsSync(baselinePath)) {
    return false;
  }

  try {
    const payload = JSON.parse(fs.readFileSync(baselinePath, "utf8"));
    const findings = Array.isArray(payload?.findings) ? payload.findings : [];
    const updated = findings.filter((item: BaselineEntry) => item?.fingerprint !== fingerprint);
    if (updated.length === findings.length) {
      return false;
    }
    const nextPayload = { ...(payload ?? {}), version: payload?.version ?? 1, findings: updated };
    fs.writeFileSync(baselinePath, JSON.stringify(nextPayload, null, 2), "utf8");
    return true;
  } catch {
    return false;
  }
}

export class BaselineTreeProvider implements TreeDataProvider<BaselineNode> {
  private readonly _onDidChangeTreeData = new EventEmitter<BaselineNode | undefined | void>();
  readonly onDidChangeTreeData: Event<BaselineNode | undefined | void> = this._onDidChangeTreeData.event;

  private workspaceRoots: string[];

  constructor(workspaceRoots: string | readonly string[] | undefined) {
    this.workspaceRoots = normalizeWorkspaceRoots(workspaceRoots);
  }

  setWorkspaceRoot(workspaceRoot: string | undefined): void {
    this.setWorkspaceRoots(workspaceRoot);
  }

  setWorkspaceRoots(workspaceRoots: string | readonly string[] | undefined): void {
    this.workspaceRoots = normalizeWorkspaceRoots(workspaceRoots);
    this.refresh();
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: BaselineNode): TreeItem {
    if (element.kind === "workspace") {
      const item = new TreeItem(path.basename(element.workspaceRoot), TreeItemCollapsibleState.Expanded);
      item.contextValue = "aegisBaselineWorkspace";
      item.description = element.hasError
        ? "Cannot read baseline"
        : `${element.count} finding${element.count === 1 ? "" : "s"}`
          + (element.invalidEntryCount ? ` · ${element.invalidEntryCount} invalid` : "");
      item.tooltip = element.workspaceRoot;
      item.iconPath = new ThemeIcon(element.hasError ? "error" : "root-folder");
      return item;
    }

    if (element.kind === "file") {
      const item = new TreeItem(element.filePath, TreeItemCollapsibleState.Expanded);
      item.contextValue = "aegisBaselineFile";
      item.description = `${element.count}`;
      item.tooltip = `${element.filePath} · ${element.count} finding${element.count === 1 ? "" : "s"}`;
      return item;
    }

    if (element.kind === "rule") {
      const item = new TreeItem(element.ruleId, TreeItemCollapsibleState.Expanded);
      item.contextValue = "aegisBaselineRule";
      item.description = `${element.count}`;
      item.tooltip = `${element.filePath} · ${element.ruleId} · ${element.count} finding${element.count === 1 ? "" : "s"}`;
      return item;
    }

    if (element.kind === "error") {
      const item = new TreeItem("Cannot read baseline", TreeItemCollapsibleState.None);
      item.contextValue = "aegisBaselineError";
      item.tooltip = element.message;
      item.iconPath = new ThemeIcon("error");
      return item;
    }

    if (element.kind === "warning") {
      const item = new TreeItem(element.message, TreeItemCollapsibleState.None);
      item.contextValue = "aegisBaselineWarning";
      item.tooltip = element.message;
      item.iconPath = new ThemeIcon("warning");
      return item;
    }

    const item = new TreeItem(
      `L${element.entry.line}: ${element.entry.rule_id}`,
      TreeItemCollapsibleState.None,
    );
    const targetPath = resolveBaselineEntryPath(element.workspaceRoot, element.entry.file_path);
    if (targetPath) {
      item.resourceUri = Uri.file(targetPath);
      item.command = {
        command: "vscode.open",
        title: "Open source location",
        arguments: [
          Uri.file(targetPath),
          {
            selection: {
              start: { line: Math.max(0, element.entry.line - 1), character: 0 },
              end: { line: Math.max(0, element.entry.line - 1), character: 0 },
            },
          },
        ],
      };
      item.contextValue = "aegisBaselineEntry";
    } else {
      item.contextValue = "aegisBaselineEntry";
      item.tooltip = `Invalid baseline path outside workspace: ${element.entry.file_path}`;
      return item;
    }
    item.contextValue = "aegisBaselineEntry";
    item.tooltip = `${element.entry.file_path}:${element.entry.line} (${element.entry.fingerprint})`;
    return item;
  }

  getChildren(element?: BaselineNode): BaselineNode[] {
    const showSuppressed = workspace.getConfiguration("aegisAI").get<boolean>("showSuppressedFindings", false);
    if (!showSuppressed) {
      return [];
    }

    if (!element) {
      if (this.workspaceRoots.length > 1) {
        return this.workspaceRoots.map((workspaceRoot) => {
          const status = readBaselineEntriesWithStatus(workspaceRoot);
          return {
            kind: "workspace" as const,
            workspaceRoot,
            count: status.entries.length,
            invalidEntryCount: status.invalidEntryCount,
            hasError: Boolean(status.error),
          };
        });
      }
      const workspaceRoot = this.workspaceRoots[0];
      return workspaceRoot ? this.getWorkspaceChildren(workspaceRoot) : [];
    }

    if (element.kind === "workspace") {
      return this.getWorkspaceChildren(element.workspaceRoot);
    }

    if (element.kind === "error" || element.kind === "warning" || element.kind === "entry") {
      return [];
    }

    const baselineStatus = readBaselineEntriesWithStatus(element.workspaceRoot);
    if (baselineStatus.error) {
      return [{ kind: "error", message: baselineStatus.error }];
    }
    const entries = baselineStatus.entries;

    if (element.kind === "file") {
      const ruleCounts = new Map<string, number>();
      for (const entry of entries.filter((entry) => entry.file_path === element.filePath)) {
        ruleCounts.set(entry.rule_id, (ruleCounts.get(entry.rule_id) ?? 0) + 1);
      }
      return [...ruleCounts.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([ruleId, count]) => ({
          kind: "rule" as const,
          workspaceRoot: element.workspaceRoot,
          filePath: element.filePath,
          ruleId,
          count,
        }));
    }

    if (element.kind === "rule") {
      return entries
        .filter((entry) => entry.file_path === element.filePath && entry.rule_id === element.ruleId)
        .map((entry) => ({
          kind: "entry" as const,
          entry,
          workspaceRoot: element.workspaceRoot,
        }));
    }

    return [];
  }

  private getWorkspaceChildren(workspaceRoot: string): BaselineNode[] {
    const status = readBaselineEntriesWithStatus(workspaceRoot);
    if (status.error) {
      return [{ kind: "error", message: status.error }];
    }

    const children: BaselineNode[] = [];
    if (status.invalidEntryCount > 0) {
      children.push({
        kind: "warning",
        message: `Ignored ${status.invalidEntryCount} invalid baseline entr${status.invalidEntryCount === 1 ? "y" : "ies"}. Fix or regenerate .aegis-baseline.json.`,
      });
    }

    const fileCounts = new Map<string, number>();
    for (const entry of status.entries) {
      fileCounts.set(entry.file_path, (fileCounts.get(entry.file_path) ?? 0) + 1);
    }
    children.push(
      ...[...fileCounts.entries()].map(([filePath, count]) => ({
        kind: "file" as const,
        workspaceRoot,
        filePath,
        count,
      })),
    );
    return children;
  }
}
