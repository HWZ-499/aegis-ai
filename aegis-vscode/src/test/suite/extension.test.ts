/**
 * @fileoverview Extension integration tests: activation and command registration.
 */

import * as assert from "assert";
import * as vscode from "vscode";

const EXT_ID = "wen-zai.aegis-ai-security";

suite("Extension Test Suite", () => {
  test("Extension should be present in the extension host", () => {
    const ext = vscode.extensions.getExtension(EXT_ID);
    assert.strictEqual(ext !== undefined, true, "Extension aegis-ai.aegis-ai-security should be loaded");
  });

  test("Extension should activate and register commands", async () => {
    const ext = vscode.extensions.getExtension(EXT_ID);
    assert.ok(ext, "Extension must be loaded");
    await ext.activate();
    const commands = await vscode.commands.getCommands();
    assert.ok(
      commands.includes("aegisAI.showOutput"),
      "aegisAI.showOutput should be registered"
    );
    assert.ok(
      commands.includes("aegisAI.scanCurrentFile"),
      "aegisAI.scanCurrentFile should be registered"
    );
    assert.ok(
      commands.includes("aegisAI.scanWorkspace"),
      "aegisAI.scanWorkspace should be registered"
    );
  });
});
