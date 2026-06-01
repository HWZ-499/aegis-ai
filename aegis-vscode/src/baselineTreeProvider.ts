import * as fs from "fs";
import * as path from "path";
import {
  Event,
  EventEmitter,
  TreeDataProvider,
  TreeItem,
  TreeItemCollapsibleState,
  Uri,
  workspace,
} from "vscode";

export interface BaselineEntry {
  rule_id: string;
  file_path: string;
  line: number;
  fingerprint: string;
}

interface BaselineFileNode {
  kind: "file";
  filePath: string;
}

interface BaselineRuleNode {
  kind: "rule";
  filePath: string;
  ruleId: string;
}

interface BaselineErrorNode {
  kind: "error";
  message: string;
}

export interface BaselineEntryNode {
  kind: "entry";
  entry: BaselineEntry;
  workspaceRoot: string;
}

type BaselineNode = BaselineFileNode | BaselineRuleNode | BaselineErrorNode | BaselineEntryNode;

export interface BaselineReadStatus {
  entries: BaselineEntry[];
  error?: string;
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
    return { entries: [] };
  }
  const baselinePath = path.join(workspaceRoot, ".aegis-baseline.json");
  if (!fs.existsSync(baselinePath)) {
    return { entries: [] };
  }

  try {
    const payload = JSON.parse(fs.readFileSync(baselinePath, "utf8"));
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      return {
        entries: [],
        error: `Cannot read baseline ${baselinePath}: root value must be an object.`,
      };
    }
    if (
      "findings" in payload
      && !Array.isArray(payload.findings)
    ) {
      return {
        entries: [],
        error: `Cannot read baseline ${baselinePath}: findings must be an array.`,
      };
    }
    const findings = Array.isArray(payload?.findings) ? payload.findings : [];
    const entries = findings.filter((item: unknown): item is BaselineEntry => {
      if (!item || typeof item !== "object") {
        return false;
      }
      const candidate = item as Partial<BaselineEntry>;
      return typeof candidate.rule_id === "string"
        && typeof candidate.file_path === "string"
        && typeof candidate.line === "number"
        && typeof candidate.fingerprint === "string";
    });
    return { entries: sortEntries(entries) };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return {
      entries: [],
      error: `Cannot read baseline ${baselinePath}: ${reason}`,
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

  constructor(private workspaceRoot: string | undefined) {}

  setWorkspaceRoot(workspaceRoot: string | undefined): void {
    this.workspaceRoot = workspaceRoot;
    this.refresh();
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: BaselineNode): TreeItem {
    if (element.kind === "file") {
      const item = new TreeItem(element.filePath, TreeItemCollapsibleState.Expanded);
      item.contextValue = "aegisBaselineFile";
      item.tooltip = element.filePath;
      return item;
    }

    if (element.kind === "rule") {
      const item = new TreeItem(element.ruleId, TreeItemCollapsibleState.Expanded);
      item.contextValue = "aegisBaselineRule";
      item.tooltip = `${element.filePath} · ${element.ruleId}`;
      return item;
    }

    if (element.kind === "error") {
      const item = new TreeItem("Cannot read baseline", TreeItemCollapsibleState.None);
      item.contextValue = "aegisBaselineError";
      item.tooltip = element.message;
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

    const baselineStatus = readBaselineEntriesWithStatus(this.workspaceRoot);
    if (baselineStatus.error) {
      return [{ kind: "error", message: baselineStatus.error }];
    }

    const entries = baselineStatus.entries;
    if (!this.workspaceRoot || entries.length === 0) {
      return [];
    }

    if (!element) {
      const filePaths = new Set(entries.map((entry) => entry.file_path));
      return [...filePaths].map((filePath) => ({ kind: "file" as const, filePath }));
    }

    if (element.kind === "file") {
      const ruleIds = new Set(
        entries
          .filter((entry) => entry.file_path === element.filePath)
          .map((entry) => entry.rule_id),
      );
      return [...ruleIds].map((ruleId) => ({
        kind: "rule" as const,
        filePath: element.filePath,
        ruleId,
      }));
    }

    if (element.kind === "rule") {
      return entries
        .filter((entry) => entry.file_path === element.filePath && entry.rule_id === element.ruleId)
        .map((entry) => ({
          kind: "entry" as const,
          entry,
          workspaceRoot: this.workspaceRoot!,
        }));
    }

    return [];
  }
}
