import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import {
  ensureBackendLaunch,
  getBundledBackendPath,
  getManagedBackendPath,
  getVenvPythonPath,
  RunProcessLike,
} from "../../backendBootstrap";

function createBundledBackend(extensionPath: string, fingerprint?: string): string {
  const backendPath = path.join(extensionPath, "resources", "aegis-ai-core");
  fs.mkdirSync(path.join(backendPath, "src", "lsp"), { recursive: true });
  fs.writeFileSync(
    path.join(backendPath, "pyproject.toml"),
    [
      "[project]",
      'name = "aegis-ai-core"',
      'version = "1.4.0"',
      "",
    ].join("\n"),
    "utf8",
  );
  fs.writeFileSync(path.join(backendPath, "src", "lsp", "__main__.py"), "", "utf8");
  if (fingerprint) {
    fs.writeFileSync(
      path.join(backendPath, "backend-manifest.json"),
      JSON.stringify({ manifestVersion: 1, fingerprint, files: 2 }, null, 2),
      "utf8",
    );
  }
  return backendPath;
}

suite("backendBootstrap", () => {
  test("detects a bundled backend only when the LSP entry point exists", () => {
    const extensionPath = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-ext-"));
    assert.strictEqual(getBundledBackendPath(extensionPath), undefined);

    const backendPath = createBundledBackend(extensionPath);

    assert.strictEqual(getBundledBackendPath(extensionPath), backendPath);
  });

  test("bootstraps bundled backend into a managed venv", async () => {
    const extensionPath = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-ext-"));
    const globalStoragePath = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-storage-"));
    createBundledBackend(extensionPath);
    const managedBackendPath = getManagedBackendPath(globalStoragePath);
    const calls: string[] = [];
    const runProcess: RunProcessLike = async (file, args) => {
      calls.push([file, ...args].join(" "));
      if (args[0] === "-m" && args[1] === "venv") {
        fs.mkdirSync(path.dirname(getVenvPythonPath(globalStoragePath)), { recursive: true });
        fs.writeFileSync(getVenvPythonPath(globalStoragePath), "", "utf8");
      }
      return { stdout: args.includes("--version") ? "Python 3.11.9" : "", stderr: "" };
    };

    const launch = await ensureBackendLaunch({
      explicitCwd: "",
      extensionPath,
      globalStoragePath,
      preferBundledBackend: true,
      pythonPath: "python",
      serverModule: "src.lsp",
      workspaceFolders: [],
      runProcess,
    });

    assert.strictEqual(launch.source, "bundled");
    assert.strictEqual(launch.cwd, managedBackendPath);
    assert.strictEqual(launch.pythonPath, getVenvPythonPath(globalStoragePath));
    assert.deepStrictEqual(launch.args, ["-m", "src.lsp"]);
    assert.ok(fs.existsSync(path.join(managedBackendPath, "src", "lsp", "__main__.py")));
    assert.ok(calls.some((call) => call.includes("python -m venv")));
    assert.ok(calls.some((call) => call.includes("-m pip install --upgrade pip")));
    assert.ok(calls.some((call) => call.includes(`-m pip install ${managedBackendPath}`)));
  });

  test("rejects Python below 3.10 before creating the backend venv", async () => {
    const extensionPath = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-ext-"));
    const globalStoragePath = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-storage-"));
    createBundledBackend(extensionPath);
    const calls: string[] = [];
    const runProcess: RunProcessLike = async (file, args) => {
      calls.push([file, ...args].join(" "));
      return { stdout: "Python 3.9.18", stderr: "" };
    };

    await assert.rejects(
      () =>
        ensureBackendLaunch({
          explicitCwd: "",
          extensionPath,
          globalStoragePath,
          preferBundledBackend: true,
          pythonPath: "python",
          serverModule: "src.lsp",
          workspaceFolders: [],
          runProcess,
        }),
      /Python 3\.10 or newer is required/,
    );
    assert.ok(!calls.some((call) => call.includes("-m venv")));
  });

  test("uses explicit serverCwd without bootstrapping bundled backend", async () => {
    const extensionPath = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-ext-"));
    const globalStoragePath = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-storage-"));
    const explicitCwd = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-core-"));
    createBundledBackend(extensionPath);
    const calls: string[] = [];
    const runProcess: RunProcessLike = async (file, args) => {
      calls.push([file, ...args].join(" "));
      return { stdout: "Python 3.11.9", stderr: "" };
    };

    const launch = await ensureBackendLaunch({
      explicitCwd,
      extensionPath,
      globalStoragePath,
      preferBundledBackend: true,
      pythonPath: "python",
      serverModule: "src.lsp",
      workspaceFolders: [],
      runProcess,
    });

    assert.strictEqual(launch.source, "workspace");
    assert.strictEqual(launch.cwd, explicitCwd);
    assert.strictEqual(launch.pythonPath, "python");
    assert.ok(!calls.some((call) => call.includes("-m venv")));
  });

  test("reuses bundled backend when manifest fingerprint is unchanged across extension paths", async () => {
    const firstExtensionPath = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-ext-"));
    const secondExtensionPath = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-ext-"));
    const globalStoragePath = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-storage-"));
    createBundledBackend(firstExtensionPath, "same-fingerprint");
    createBundledBackend(secondExtensionPath, "same-fingerprint");
    const calls: string[] = [];
    const runProcess: RunProcessLike = async (file, args) => {
      calls.push([file, ...args].join(" "));
      if (args[0] === "-m" && args[1] === "venv") {
        fs.mkdirSync(path.dirname(getVenvPythonPath(globalStoragePath)), { recursive: true });
        fs.writeFileSync(getVenvPythonPath(globalStoragePath), "", "utf8");
      }
      return { stdout: args.includes("--version") ? "Python 3.11.9" : "", stderr: "" };
    };

    await ensureBackendLaunch({
      explicitCwd: "",
      extensionPath: firstExtensionPath,
      globalStoragePath,
      preferBundledBackend: true,
      pythonPath: "python",
      serverModule: "src.lsp",
      workspaceFolders: [],
      runProcess,
    });
    calls.length = 0;

    const launch = await ensureBackendLaunch({
      explicitCwd: "",
      extensionPath: secondExtensionPath,
      globalStoragePath,
      preferBundledBackend: true,
      pythonPath: "python",
      serverModule: "src.lsp",
      workspaceFolders: [],
      runProcess,
    });

    assert.strictEqual(launch.source, "bundled");
    assert.ok(!calls.some((call) => call.includes("-m venv")));
    assert.ok(!calls.some((call) => call.includes("-m pip install")));
  });

  test("reinstalls bundled backend when manifest fingerprint changes", async () => {
    const firstExtensionPath = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-ext-"));
    const secondExtensionPath = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-ext-"));
    const globalStoragePath = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-storage-"));
    createBundledBackend(firstExtensionPath, "old-fingerprint");
    createBundledBackend(secondExtensionPath, "new-fingerprint");
    const calls: string[] = [];
    const runProcess: RunProcessLike = async (file, args) => {
      calls.push([file, ...args].join(" "));
      if (args[0] === "-m" && args[1] === "venv") {
        fs.mkdirSync(path.dirname(getVenvPythonPath(globalStoragePath)), { recursive: true });
        fs.writeFileSync(getVenvPythonPath(globalStoragePath), "", "utf8");
      }
      return { stdout: args.includes("--version") ? "Python 3.11.9" : "", stderr: "" };
    };

    await ensureBackendLaunch({
      explicitCwd: "",
      extensionPath: firstExtensionPath,
      globalStoragePath,
      preferBundledBackend: true,
      pythonPath: "python",
      serverModule: "src.lsp",
      workspaceFolders: [],
      runProcess,
    });
    calls.length = 0;

    await ensureBackendLaunch({
      explicitCwd: "",
      extensionPath: secondExtensionPath,
      globalStoragePath,
      preferBundledBackend: true,
      pythonPath: "python",
      serverModule: "src.lsp",
      workspaceFolders: [],
      runProcess,
    });

    assert.ok(calls.some((call) => call.includes("python -m venv")));
    assert.ok(calls.some((call) => call.includes("-m pip install")));
  });
});
