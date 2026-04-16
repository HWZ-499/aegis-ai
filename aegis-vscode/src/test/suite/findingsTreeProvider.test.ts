import * as assert from "assert";

import { summarizeFindingMessage } from "../../findingsTreeProvider";

suite("findingsTreeProvider", () => {
  test("uses the first non-empty line as the tree label summary", () => {
    const summary = summarizeFindingMessage(
      [
        "Potential SQL injection via string concatenation。",
        "",
        "修复建议: Use parameterized queries.",
        "Aegis 可用操作:",
      ].join("\n"),
    );

    assert.strictEqual(summary, "Potential SQL injection via string concatenation。");
  });

  test("falls back to the original message when it is already one line", () => {
    assert.strictEqual(summarizeFindingMessage("Single line finding"), "Single line finding");
  });
});
