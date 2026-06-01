import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";

import {
  BaselineTreeProvider,
  readBaselineEntriesWithStatus,
  readBaselineEntries,
  removeBaselineEntryFromDisk,
  resolveBaselineEntryPath,
} from "../../baselineTreeProvider";

suite("baselineTreeProvider", () => {
  test("shows baseline entries only when suppressed findings are enabled", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-baseline-"));
    const baselinePath = path.join(tempDir, ".aegis-baseline.json");
    fs.writeFileSync(
      baselinePath,
      JSON.stringify(
        {
          version: 1,
          findings: [
            {
              rule_id: "SQL_INJECTION",
              file_path: "src/app.js",
              line: 12,
              fingerprint: "fp-1",
            },
          ],
        },
        null,
        2,
      ),
      "utf8",
    );

    const provider = new BaselineTreeProvider(tempDir);
    await vscode.workspace.getConfiguration("aegisAI").update("showSuppressedFindings", false, vscode.ConfigurationTarget.Global);
    assert.deepStrictEqual(provider.getChildren(), []);

    await vscode.workspace.getConfiguration("aegisAI").update("showSuppressedFindings", true, vscode.ConfigurationTarget.Global);
    const fileNodes = provider.getChildren();
    assert.strictEqual(fileNodes.length, 1);
    const ruleNodes = provider.getChildren(fileNodes[0] as any);
    assert.strictEqual(ruleNodes.length, 1);
    const entryNodes = provider.getChildren(ruleNodes[0] as any);
    assert.strictEqual(entryNodes.length, 1);
  });

  test("removeBaselineEntryFromDisk deletes the matching finding only", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-baseline-"));
    const baselinePath = path.join(tempDir, ".aegis-baseline.json");
    fs.writeFileSync(
      baselinePath,
      JSON.stringify(
        {
          version: 1,
          findings: [
            { rule_id: "SQL_INJECTION", file_path: "src/app.js", line: 12, fingerprint: "fp-1" },
            { rule_id: "XSS_RISK", file_path: "src/app.js", line: 18, fingerprint: "fp-2" },
          ],
        },
        null,
        2,
      ),
      "utf8",
    );

    assert.strictEqual(removeBaselineEntryFromDisk(tempDir, "fp-1"), true);
    assert.deepStrictEqual(readBaselineEntries(tempDir).map((entry) => entry.fingerprint), ["fp-2"]);
  });

  test("surfaces corrupt baseline files instead of showing an empty tree", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-baseline-"));
    const baselinePath = path.join(tempDir, ".aegis-baseline.json");
    fs.writeFileSync(baselinePath, "{ not valid json", "utf8");

    const status = readBaselineEntriesWithStatus(tempDir);
    assert.deepStrictEqual(status.entries, []);
    assert.ok(status.error?.includes(".aegis-baseline.json"));

    const provider = new BaselineTreeProvider(tempDir);
    await vscode.workspace.getConfiguration("aegisAI").update("showSuppressedFindings", true, vscode.ConfigurationTarget.Global);
    const nodes = provider.getChildren();
    assert.strictEqual(nodes.length, 1);
    const item = provider.getTreeItem(nodes[0] as any);
    assert.match(String(item.label), /Cannot read baseline/);
  });

  test("resolveBaselineEntryPath rejects paths outside the workspace", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-baseline-"));

    assert.strictEqual(
      resolveBaselineEntryPath(tempDir, "src/app.js"),
      path.resolve(tempDir, "src", "app.js"),
    );
    assert.strictEqual(resolveBaselineEntryPath(tempDir, "../secrets.txt"), undefined);
    assert.strictEqual(resolveBaselineEntryPath(tempDir, "src/../../secrets.txt"), undefined);
    assert.strictEqual(resolveBaselineEntryPath(tempDir, path.resolve(os.tmpdir(), "secrets.txt")), undefined);
  });
});
