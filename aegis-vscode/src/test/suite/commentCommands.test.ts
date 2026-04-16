import * as assert from "assert";

import {
  findAegisCommentBlock,
  removeAegisCommentBlock,
} from "../../commentCommands";

suite("Comment Command Helpers", () => {
  test("finds contiguous Aegis remediation comments", () => {
    const source = [
      "# Aegis 修复建议 (SQL_INJECTION):",
      "# 使用参数化查询",
      "# 参考: https://example.com",
      "cursor.execute(query)",
    ].join("\n");

    const block = findAegisCommentBlock(source, 1);

    assert.deepStrictEqual(block, { startLine: 0, endLineExclusive: 3 });
  });

  test("removes the full Aegis comment block only", () => {
    const source = [
      "const name = req.query.name;",
      "// Aegis AI 修复建议 (XSS_RISK) 置信度 50%",
      "// 需人工复核",
      "// 建议修改为:",
      "// res.send(escapeHtml(name));",
      "res.send(name);",
    ].join("\n");

    const updated = removeAegisCommentBlock(source, 2);

    assert.strictEqual(
      updated,
      ["const name = req.query.name;", "res.send(name);"].join("\n")
    );
  });

  test("keeps non-Aegis comments untouched", () => {
    const source = ["// ordinary comment", "console.log('safe');"].join("\n");

    const updated = removeAegisCommentBlock(source, 0);

    assert.strictEqual(updated, source);
  });

  test("does not delete adjacent user comments", () => {
    const source = [
      "// user note",
      "// Aegis AI 修复建议 (XSS_RISK) 置信度 50%",
      "// 需人工复核",
      "res.send(name);",
    ].join("\n");

    const updated = removeAegisCommentBlock(source, 2);

    assert.strictEqual(
      updated,
      ["// user note", "res.send(name);"].join("\n")
    );
  });
});
