/**
 * @fileoverview Extension integration test runner.
 * Launches VS Code Extension Development Host and runs the test suite.
 */

import * as path from "path";
import { runTests } from "@vscode/test-electron";

async function main(): Promise<void> {
  try {
    const extensionDevelopmentPath = path.resolve(__dirname, "../..");
    const extensionTestsPath = path.resolve(__dirname, "./suite/index");

    await runTests({
      extensionDevelopmentPath,
      extensionTestsPath,
      launchArgs: ["--disable-extensions"],
    });
  } catch (err) {
    console.error(err);
    console.error("Failed to run tests");
    process.exit(1);
  }
}

main();
