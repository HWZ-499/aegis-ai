/**
 * @fileoverview Extension integration test runner.
 * Launches VS Code Extension Development Host and runs the test suite.
 */

import * as cp from "child_process";
import * as fs from "fs";
import * as path from "path";
import { downloadAndUnzipVSCode } from "@vscode/test-electron";

async function main(): Promise<void> {
  try {
    const extensionDevelopmentPath = path.resolve(__dirname, "../..");
    const extensionTestsPath = path.resolve(__dirname, "./suite/index");
    const vscodeExecutablePath = await downloadAndUnzipVSCode("stable");
    const testRoot = path.join(extensionDevelopmentPath, ".vscode-test");
    fs.mkdirSync(testRoot, { recursive: true });
    const userDataDir = fs.mkdtempSync(path.join(testRoot, "user-data-"));
    const extensionsDir = fs.mkdtempSync(path.join(testRoot, "extensions-"));

    const args = [
      "--disable-extensions",
      "--no-sandbox",
      "--disable-gpu-sandbox",
      "--disable-updates",
      "--skip-welcome",
      "--skip-release-notes",
      "--disable-workspace-trust",
      `--extensionTestsPath=${extensionTestsPath}`,
      `--extensionDevelopmentPath=${extensionDevelopmentPath}`,
      `--extensions-dir=${extensionsDir}`,
      `--user-data-dir=${userDataDir}`,
    ];

    await new Promise<void>((resolve, reject) => {
      const env = { ...process.env };
      delete env.ELECTRON_RUN_AS_NODE;
      delete env.VSCODE_RUN_AS_NODE;

      const proc = cp.spawn(vscodeExecutablePath, args, {
        stdio: "inherit",
        shell: false,
        env,
      });

      proc.on("error", reject);
      proc.on("exit", (code) => {
        if (code === 0) {
          resolve();
          return;
        }
        reject(new Error(`VS Code test host exited with code ${code}`));
      });
    });
  } catch (err) {
    console.error(err);
    console.error("Failed to run tests");
    process.exit(1);
  }
}

main();
