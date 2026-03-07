/**
 * @fileoverview Mocha test runner for extension tests.
 * Discovers and runs all *.test.js under the test directory.
 */

import * as path from "path";
import * as fs from "fs";
import Mocha from "mocha";

export function run(): Promise<void> {
  const mocha = new Mocha({
    ui: "tdd",
    color: true,
    timeout: 20000,
  });

  const testsRoot = path.resolve(__dirname, "..");

  return new Promise((resolve, reject) => {
    const testFiles = findTestFiles(testsRoot, testsRoot, ".test.js");
    testFiles.forEach((f) => mocha.addFile(path.resolve(testsRoot, f)));

    try {
      mocha.run((failures) => {
        if (failures > 0) {
          reject(new Error(`${failures} tests failed.`));
        } else {
          resolve();
        }
      });
    } catch (err) {
      reject(err);
    }
  });
}

/**
 * Recursively find all files matching suffix under dir.
 * @param dir - Current directory to search
 * @param root - Root directory (for relative paths)
 * @param suffix - File suffix (e.g. .test.js)
 * @returns Relative paths from root
 */
function findTestFiles(dir: string, root: string, suffix: string): string[] {
  const results: string[] = [];
  if (!fs.existsSync(dir)) return results;

  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const e of entries) {
    const full = path.join(dir, e.name);
    const rel = path.relative(root, full);
    if (e.isDirectory()) {
      results.push(...findTestFiles(full, root, suffix));
    } else if (e.isFile() && e.name.endsWith(suffix)) {
      results.push(rel);
    }
  }
  return results;
}
