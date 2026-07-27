import * as assert from "assert";
import { Diagnostic, DiagnosticSeverity, Range } from "vscode";

import {
  compareFindingPriority,
  getAegisDiagnostics,
  severityLabel,
  summarizeFindingMessage,
} from "../../findingsTreeProvider";

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

  test("counts every Aegis severity so low findings cannot appear safe", () => {
    const low = new Diagnostic(new Range(0, 0, 0, 1), "Low finding", DiagnosticSeverity.Information);
    low.source = "Aegis AI";
    const hint = new Diagnostic(new Range(1, 0, 1, 1), "Info finding", DiagnosticSeverity.Hint);
    hint.source = "Aegis AI";
    const other = new Diagnostic(new Range(2, 0, 2, 1), "Other tool", DiagnosticSeverity.Error);
    other.source = "Other Scanner";

    assert.deepStrictEqual(getAegisDiagnostics([low, hint, other]), [low, hint]);
  });

  test("orders findings by severity, then line and message", () => {
    const findings = [
      { severity: DiagnosticSeverity.Warning, line: 2, message: "Medium" },
      { severity: DiagnosticSeverity.Error, line: 8, message: "Later high" },
      { severity: DiagnosticSeverity.Error, line: 3, message: "Earlier high" },
    ];

    assert.deepStrictEqual(findings.sort(compareFindingPriority).map((finding) => finding.message), [
      "Earlier high",
      "Later high",
      "Medium",
    ]);
  });

  test("uses security-oriented severity labels", () => {
    assert.strictEqual(severityLabel(DiagnosticSeverity.Error), "Critical / High");
    assert.strictEqual(severityLabel(DiagnosticSeverity.Warning), "Medium");
    assert.strictEqual(severityLabel(DiagnosticSeverity.Information), "Low");
    assert.strictEqual(severityLabel(DiagnosticSeverity.Hint), "Info");
  });
});
