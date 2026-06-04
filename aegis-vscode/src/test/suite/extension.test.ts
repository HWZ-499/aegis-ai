/**
 * @fileoverview Extension integration tests: activation and command registration.
 */

import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";

const EXT_ID = "wen-zai.aegis-ai-security";

async function waitForAegisDiagnosticLine(
  uri: vscode.Uri,
  predicate: (line: number, count: number) => boolean,
  timeoutMs = 30000,
): Promise<number> {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const diagnostics = vscode.languages
      .getDiagnostics(uri)
      .filter((diagnostic) => diagnostic.source === "Aegis AI");
    const line = diagnostics[0]?.range.start.line ?? -1;
    if (diagnostics.length > 0 && predicate(line, diagnostics.length)) {
      return line;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }

  throw new Error(`Timed out waiting for Aegis diagnostics for ${uri.fsPath}`);
}

async function waitForAegisDiagnosticCount(
  uri: vscode.Uri,
  predicate: (count: number) => boolean,
  timeoutMs = 30000,
): Promise<number> {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const count = vscode.languages
      .getDiagnostics(uri)
      .filter((diagnostic) => diagnostic.source === "Aegis AI").length;
    if (predicate(count)) {
      return count;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }

  throw new Error(`Timed out waiting for Aegis diagnostic count for ${uri.fsPath}`);
}

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
    assert.ok(
      commands.includes("aegisAI.removeRemediationComments"),
      "aegisAI.removeRemediationComments should be registered"
    );
    assert.ok(
      commands.includes("aegisAI.refreshBaseline"),
      "aegisAI.refreshBaseline should be registered"
    );
    assert.ok(
      commands.includes("aegisAI.removeBaselineEntry"),
      "aegisAI.removeBaselineEntry should be registered"
    );
    assert.ok(
      commands.includes("aegisAI.toggleSuppressedFindings"),
      "aegisAI.toggleSuppressedFindings should be registered"
    );
  });

  test("Aegis updates finding positions after save and preserves them after reopen", async function () {
    this.timeout(90000);

    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-ext-"));
    const filePath = path.join(tempDir, "smoke-vuln.js");
    fs.writeFileSync(
      filePath,
      [
        "app.get('/user', (req, res) => {",
        "  const userId = req.query.id;",
        "  const query = \"SELECT * FROM users WHERE id = '\" + userId + \"'\";",
        "  mysql.query(query);",
        "});",
        "",
      ].join("\n"),
      "utf8",
    );

    const uri = vscode.Uri.file(filePath);
    let document = await vscode.workspace.openTextDocument(uri);
    let editor = await vscode.window.showTextDocument(document);

    await vscode.commands.executeCommand("aegisAI.scanCurrentFile");
    const firstLine = await waitForAegisDiagnosticLine(uri, (line) => line >= 1);

    await editor.edit((editBuilder) => {
      editBuilder.insert(new vscode.Position(0, 0), "// padding line for smoke test\n");
    });
    await document.save();
    await vscode.commands.executeCommand("aegisAI.scanCurrentFile");

    const shiftedLine = await waitForAegisDiagnosticLine(uri, (line) => line === firstLine + 1);
    assert.strictEqual(shiftedLine, firstLine + 1);

    await vscode.commands.executeCommand("workbench.action.closeActiveEditor");
    document = await vscode.workspace.openTextDocument(uri);
    editor = await vscode.window.showTextDocument(document);
    void editor;
    const reopenedLine = await waitForAegisDiagnosticLine(uri, (line) => line === shiftedLine);
    assert.strictEqual(reopenedLine, shiftedLine);
  });

  test("Aegis scans C++ files through the VS Code extension", async function () {
    this.timeout(90000);

    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-ext-cpp-"));
    const filePath = path.join(tempDir, "course-case.cpp");
    fs.writeFileSync(
      filePath,
      [
        "#include <iostream>",
        "using namespace std;",
        "char name[20] = {'\\0'};",
        "void readName() {",
        "  cin >> name;",
        "}",
        "",
      ].join("\n"),
      "utf8",
    );

    const uri = vscode.Uri.file(filePath);
    const document = await vscode.workspace.openTextDocument(uri);
    await vscode.window.showTextDocument(document);

    await vscode.commands.executeCommand("aegisAI.scanCurrentFile");
    const count = await waitForAegisDiagnosticCount(uri, (diagnosticCount) => diagnosticCount > 0);

    assert.ok(count > 0);
    assert.strictEqual(document.languageId, "cpp");
  });

  test("inserting remediation comments does not hide findings and can be undone", async function () {
    this.timeout(90000);

    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-ext-"));
    const filePath = path.join(tempDir, "comment-regression.js");
    fs.writeFileSync(
      filePath,
      [
        "app.get('/user', (req, res) => {",
        "  const userId = req.query.id;",
        "  const query = \"SELECT * FROM users WHERE id = '\" + userId + \"'\";",
        "  mysql.query(query);",
        "});",
        "",
      ].join("\n"),
      "utf8",
    );

    const uri = vscode.Uri.file(filePath);
    let document = await vscode.workspace.openTextDocument(uri);
    let editor = await vscode.window.showTextDocument(document);

    await vscode.commands.executeCommand("aegisAI.scanCurrentFile");
    await waitForAegisDiagnosticCount(uri, (count) => count > 0);

    const diagnostics = vscode.languages.getDiagnostics(uri).filter((diagnostic) => diagnostic.source === "Aegis AI");
    const actionRange = diagnostics[0].range;
    const actions = await vscode.commands.executeCommand<(vscode.CodeAction | vscode.Command)[]>(
      "vscode.executeCodeActionProvider",
      uri,
      actionRange,
    );
    const commentAction = actions?.find((action) => "title" in action && action.title.includes("插入修复建议注释"));
    assert.ok(commentAction && "edit" in commentAction && commentAction.edit, "Expected remediation comment code action");

    await vscode.workspace.applyEdit((commentAction as vscode.CodeAction).edit!);
    await document.save();
    await vscode.commands.executeCommand("aegisAI.scanCurrentFile");

    const stillPresentAfterComment = await waitForAegisDiagnosticCount(uri, (count) => count > 0);
    assert.ok(stillPresentAfterComment > 0);
    assert.ok(document.getText().includes("Aegis 修复建议"));

    const commentLineIndex = document
      .getText()
      .split(/\r?\n/)
      .findIndex((line) => line.includes("Aegis 修复建议"));
    assert.ok(commentLineIndex >= 0);
    editor.selection = new vscode.Selection(
      new vscode.Position(commentLineIndex, 0),
      new vscode.Position(commentLineIndex, 0),
    );
    await vscode.commands.executeCommand("aegisAI.removeRemediationComments");
    await document.save();
    await vscode.commands.executeCommand("aegisAI.scanCurrentFile");

    const afterRemoval = await waitForAegisDiagnosticCount(uri, (count) => count > 0);
    assert.ok(afterRemoval > 0);
    assert.ok(!document.getText().includes("Aegis 修复建议"));

    await vscode.commands.executeCommand("workbench.action.closeActiveEditor");
    document = await vscode.workspace.openTextDocument(uri);
    editor = await vscode.window.showTextDocument(document);
    void editor;
    const afterReopen = await waitForAegisDiagnosticCount(uri, (count) => count > 0);
    assert.ok(afterReopen > 0);
  });
});
