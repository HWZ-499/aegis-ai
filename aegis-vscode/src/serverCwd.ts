import * as fs from "fs";
import * as path from "path";

export interface ServerCwdResolutionInput {
  explicitCwd: string;
  workspaceFolders: string[];
  extensionPath: string;
}

export interface ServerCwdResolution {
  cwd: string | undefined;
  logMessages: string[];
}

function directoryExists(candidate: string): boolean {
  try {
    return fs.existsSync(candidate) && fs.statSync(candidate).isDirectory();
  } catch {
    return false;
  }
}

function findCoreFrom(startPath: string): string | undefined {
  let current = path.resolve(startPath);

  while (true) {
    if (path.basename(current) === "aegis-ai-core" && directoryExists(current)) {
      return current;
    }

    const child = path.join(current, "aegis-ai-core");
    if (directoryExists(child)) {
      return child;
    }

    const parent = path.dirname(current);
    if (parent === current) {
      return undefined;
    }
    current = parent;
  }
}

export function resolveServerCwd(input: ServerCwdResolutionInput): ServerCwdResolution {
  const logMessages: string[] = [];
  let cwd: string | undefined;
  const explicitCwd = input.explicitCwd.trim();

  if (explicitCwd) {
    const workspaceRoot = input.workspaceFolders[0] ?? "";
    cwd = path.isAbsolute(explicitCwd)
      ? explicitCwd
      : path.resolve(workspaceRoot, explicitCwd);
    if (directoryExists(cwd)) {
      logMessages.push(`[Aegis] Using configured serverCwd: ${cwd}`);
      return { cwd, logMessages };
    }

    logMessages.push(`[Aegis] serverCwd does not exist, falling back to auto-detect: ${cwd}`);
    cwd = undefined;
  }

  for (const workspaceFolder of input.workspaceFolders) {
    const resolved = findCoreFrom(workspaceFolder);
    if (resolved) {
      logMessages.push(`[Aegis] Using auto-detected aegis-ai-core: ${resolved}`);
      return { cwd: resolved, logMessages };
    }

    const previousCandidate = path.join(workspaceFolder, "aegis-ai-core");
    logMessages.push(`[Aegis] Auto-detected directory does not exist: ${previousCandidate}`);
  }

  const extensionResolved = findCoreFrom(input.extensionPath);
  if (extensionResolved) {
    logMessages.push(`[Aegis] Using extension-relative aegis-ai-core: ${extensionResolved}`);
    return { cwd: extensionResolved, logMessages };
  }

  if (input.workspaceFolders.length === 0) {
    logMessages.push("[Aegis] No workspace open and aegis-ai-core not found.");
  }

  return { cwd: undefined, logMessages };
}
