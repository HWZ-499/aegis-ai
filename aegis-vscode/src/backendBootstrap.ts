import { execFile } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { isPythonVersionSupported, parsePythonVersion } from "./pythonProbe";
import { resolveServerCwd } from "./serverCwd";

export interface ProcessResult {
  stdout: string;
  stderr: string;
}

export type RunProcessLike = (
  file: string,
  args: readonly string[],
  options?: {
    cwd?: string;
    timeout?: number;
  },
) => Promise<ProcessResult>;

export interface BackendLaunch {
  pythonPath: string;
  args: string[];
  cwd: string;
  source: "bundled" | "workspace";
  logMessages: string[];
}

export interface BackendLaunchInput {
  explicitCwd: string;
  extensionPath: string;
  globalStoragePath: string;
  preferBundledBackend: boolean;
  pythonPath: string;
  serverModule: string;
  workspaceFolders: string[];
  runProcess?: RunProcessLike;
}

interface BackendStamp {
  backendPath?: string;
  backendFingerprint?: string;
  backendVersion: string;
  bootstrapVersion: number;
}

interface BackendManifest {
  fingerprint?: string;
  manifestVersion?: number;
}

const BOOTSTRAP_VERSION = 1;
const BACKEND_TIMEOUT_MS = 10 * 60 * 1000;
const BACKEND_MANIFEST_NAME = "backend-manifest.json";

function defaultRunProcess(
  file: string,
  args: readonly string[],
  options: { cwd?: string; timeout?: number } = {},
): Promise<ProcessResult> {
  return new Promise((resolve, reject) => {
    execFile(
      file,
      [...args],
      {
        cwd: options.cwd,
        encoding: "utf8",
        timeout: options.timeout ?? BACKEND_TIMEOUT_MS,
      },
      (error, stdout, stderr) => {
        if (error) {
          reject(error);
          return;
        }
        resolve({ stdout: stdout ?? "", stderr: stderr ?? "" });
      },
    );
  });
}

function fileExists(candidate: string): boolean {
  try {
    return fs.existsSync(candidate) && fs.statSync(candidate).isFile();
  } catch {
    return false;
  }
}

function directoryExists(candidate: string): boolean {
  try {
    return fs.existsSync(candidate) && fs.statSync(candidate).isDirectory();
  } catch {
    return false;
  }
}

export function getBundledBackendPath(extensionPath: string): string | undefined {
  const backendPath = path.join(extensionPath, "resources", "aegis-ai-core");
  if (
    fileExists(path.join(backendPath, "pyproject.toml")) &&
    fileExists(path.join(backendPath, "src", "lsp", "__main__.py"))
  ) {
    return backendPath;
  }
  return undefined;
}

function getBackendStateDir(globalStoragePath: string): string {
  return path.join(globalStoragePath, "python-backend");
}

export function getManagedBackendPath(globalStoragePath: string): string {
  return path.join(getBackendStateDir(globalStoragePath), "bundled-backend");
}

export function getVenvPythonPath(globalStoragePath: string): string {
  const venvDir = path.join(getBackendStateDir(globalStoragePath), ".venv");
  return os.platform() === "win32"
    ? path.join(venvDir, "Scripts", "python.exe")
    : path.join(venvDir, "bin", "python");
}

function getStampPath(globalStoragePath: string): string {
  return path.join(getBackendStateDir(globalStoragePath), "install-stamp.json");
}

function shouldSkipManagedCopy(sourcePath: string): boolean {
  const name = path.basename(sourcePath);
  if (
    name === "__pycache__" ||
    name === ".aegis-cache" ||
    name === "build" ||
    name.endsWith(".egg-info")
  ) {
    return true;
  }
  return [".pyc", ".pyo", ".pyd"].includes(path.extname(name));
}

function copyDirectory(sourcePath: string, targetPath: string): void {
  if (shouldSkipManagedCopy(sourcePath)) {
    return;
  }

  const stat = fs.statSync(sourcePath);
  if (stat.isDirectory()) {
    fs.mkdirSync(targetPath, { recursive: true });
    for (const entry of fs.readdirSync(sourcePath)) {
      copyDirectory(path.join(sourcePath, entry), path.join(targetPath, entry));
    }
    return;
  }

  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.copyFileSync(sourcePath, targetPath);
}

function stageBundledBackend(sourceBackendPath: string, managedBackendPath: string): void {
  fs.rmSync(managedBackendPath, { recursive: true, force: true });
  fs.mkdirSync(managedBackendPath, { recursive: true });
  copyDirectory(sourceBackendPath, managedBackendPath);
}

function readBackendVersion(backendPath: string): string {
  const pyproject = fs.readFileSync(path.join(backendPath, "pyproject.toml"), "utf8");
  const match = pyproject.match(/^version\s*=\s*"([^"]+)"/m);
  return match?.[1] ?? "unknown";
}

function readBackendManifest(backendPath: string): BackendManifest | undefined {
  const manifestPath = path.join(backendPath, BACKEND_MANIFEST_NAME);
  if (!fileExists(manifestPath)) {
    return undefined;
  }
  try {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as BackendManifest;
    if (manifest.manifestVersion === 1 && manifest.fingerprint) {
      return manifest;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function buildExpectedStamp(backendPath: string): BackendStamp {
  const stamp: BackendStamp = {
    backendVersion: readBackendVersion(backendPath),
    bootstrapVersion: BOOTSTRAP_VERSION,
  };
  const manifest = readBackendManifest(backendPath);
  if (manifest?.fingerprint) {
    return {
      ...stamp,
      backendFingerprint: manifest.fingerprint,
    };
  }
  return {
    ...stamp,
    backendPath,
  };
}

function isStampCurrent(stampPath: string, expected: BackendStamp): boolean {
  if (!fileExists(stampPath)) {
    return false;
  }
  try {
    const actual = JSON.parse(fs.readFileSync(stampPath, "utf8")) as Partial<BackendStamp>;
    if (actual.backendVersion !== expected.backendVersion || actual.bootstrapVersion !== expected.bootstrapVersion) {
      return false;
    }
    if (expected.backendFingerprint) {
      return actual.backendFingerprint === expected.backendFingerprint;
    }
    return actual.backendPath === expected.backendPath;
  } catch {
    return false;
  }
}

async function assertSupportedPython(
  pythonPath: string,
  runProcess: RunProcessLike,
  logMessages: string[],
): Promise<void> {
  const startedAt = Date.now();
  const result = await runProcess(pythonPath, ["--version"], { timeout: 5000 });
  const versionOutput = (result.stdout || result.stderr).trim();
  if (!isPythonVersionSupported(versionOutput)) {
    const parsed = parsePythonVersion(versionOutput);
    const detected = parsed ? parsed.raw : versionOutput || "unknown";
    throw new Error(`Python 3.10 or newer is required for Aegis. Detected: ${detected}.`);
  }
  logMessages.push(`[Aegis] ${versionOutput} found (${Date.now() - startedAt}ms)`);
}

async function bootstrapBundledBackend(input: {
  backendPath: string;
  globalStoragePath: string;
  pythonPath: string;
  runProcess: RunProcessLike;
  serverModule: string;
}): Promise<BackendLaunch> {
  const logMessages: string[] = [];
  await assertSupportedPython(input.pythonPath, input.runProcess, logMessages);

  const backendStateDir = getBackendStateDir(input.globalStoragePath);
  const managedBackendPath = getManagedBackendPath(input.globalStoragePath);
  const venvPython = getVenvPythonPath(input.globalStoragePath);
  const stampPath = getStampPath(input.globalStoragePath);
  const stampStartedAt = Date.now();
  const expectedStamp = buildExpectedStamp(input.backendPath);
  logMessages.push(`[Aegis] Backend stamp check completed (${Date.now() - stampStartedAt}ms)`);
  fs.mkdirSync(backendStateDir, { recursive: true });

  if (fileExists(venvPython) && directoryExists(managedBackendPath) && isStampCurrent(stampPath, expectedStamp)) {
    logMessages.push(`[Aegis] Using existing bundled backend environment: ${venvPython}`);
  } else {
    const venvDir = path.dirname(path.dirname(venvPython));
    const stageStartedAt = Date.now();
    stageBundledBackend(input.backendPath, managedBackendPath);
    logMessages.push(`[Aegis] Bundled backend staged (${Date.now() - stageStartedAt}ms)`);
    logMessages.push(`[Aegis] Creating bundled backend environment: ${venvDir}`);
    const venvStartedAt = Date.now();
    await input.runProcess(input.pythonPath, ["-m", "venv", venvDir], { timeout: BACKEND_TIMEOUT_MS });
    logMessages.push(`[Aegis] Python venv created (${Date.now() - venvStartedAt}ms)`);
    const pipUpgradeStartedAt = Date.now();
    await input.runProcess(venvPython, ["-m", "pip", "install", "--upgrade", "pip"], {
      timeout: BACKEND_TIMEOUT_MS,
    });
    logMessages.push(`[Aegis] pip upgraded (${Date.now() - pipUpgradeStartedAt}ms)`);
    const installStartedAt = Date.now();
    await input.runProcess(venvPython, ["-m", "pip", "install", managedBackendPath], {
      cwd: managedBackendPath,
      timeout: BACKEND_TIMEOUT_MS,
    });
    logMessages.push(`[Aegis] Bundled backend pip install completed (${Date.now() - installStartedAt}ms)`);
    fs.writeFileSync(stampPath, JSON.stringify(expectedStamp, null, 2), "utf8");
    logMessages.push(`[Aegis] Bundled backend installed from ${input.backendPath}`);
  }

  return {
    pythonPath: venvPython,
    args: ["-m", input.serverModule],
    cwd: managedBackendPath,
    source: "bundled",
    logMessages,
  };
}

async function createWorkspaceLaunch(input: BackendLaunchInput, runProcess: RunProcessLike): Promise<BackendLaunch | undefined> {
  const cwdResolution = resolveServerCwd({
    explicitCwd: input.explicitCwd,
    workspaceFolders: input.workspaceFolders,
    extensionPath: input.extensionPath,
  });
  if (!cwdResolution.cwd || !directoryExists(cwdResolution.cwd)) {
    return undefined;
  }

  const logMessages = [...cwdResolution.logMessages];
  await assertSupportedPython(input.pythonPath, runProcess, logMessages);
  return {
    pythonPath: input.pythonPath,
    args: ["-m", input.serverModule],
    cwd: cwdResolution.cwd,
    source: "workspace",
    logMessages,
  };
}

export async function ensureBackendLaunch(input: BackendLaunchInput): Promise<BackendLaunch> {
  const runProcess = input.runProcess ?? defaultRunProcess;
  const bundledBackendPath = getBundledBackendPath(input.extensionPath);

  if (input.explicitCwd) {
    const workspaceLaunch = await createWorkspaceLaunch(input, runProcess);
    if (workspaceLaunch) {
      return workspaceLaunch;
    }
  }

  if (input.preferBundledBackend && bundledBackendPath) {
    return bootstrapBundledBackend({
      backendPath: bundledBackendPath,
      globalStoragePath: input.globalStoragePath,
      pythonPath: input.pythonPath,
      runProcess,
      serverModule: input.serverModule,
    });
  }

  const workspaceLaunch = await createWorkspaceLaunch(input, runProcess);
  if (workspaceLaunch) {
    return workspaceLaunch;
  }

  if (bundledBackendPath) {
    return bootstrapBundledBackend({
      backendPath: bundledBackendPath,
      globalStoragePath: input.globalStoragePath,
      pythonPath: input.pythonPath,
      runProcess,
      serverModule: input.serverModule,
    });
  }

  throw new Error(
    "Aegis backend not found. Reinstall the extension, or set aegisAI.serverCwd to an aegis-ai-core directory.",
  );
}
