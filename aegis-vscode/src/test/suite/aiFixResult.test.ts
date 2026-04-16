import * as assert from "assert";

import { getGenerateFixFailure } from "../../aiFixResult";

suite("aiFixResult", () => {
  test("maps provider_not_configured to actionable warning", () => {
    const failure = getGenerateFixFailure({
      uri: "file:///demo.js",
      rule_id: "SQL_INJECTION",
      error_code: "provider_not_configured",
      error_message: "AI provider is not configured. Set Aegis › AI: Provider and the matching API key.",
    });

    assert.deepStrictEqual(failure, {
      level: "warning",
      message: "Aegis: AI provider is not configured. Set Aegis › AI: Provider and the matching API key.",
    });
  });

  test("treats missing fixed_code as no applicable fix", () => {
    const failure = getGenerateFixFailure({
      uri: "file:///demo.js",
      rule_id: "XSS_RISK",
      fixed_code: "",
      confidence: 0.52,
      fix_suggestion: "Escape the response output.",
      start_line: 4,
      end_line: 4,
      requires_review: true,
    });

    assert.deepStrictEqual(failure, {
      level: "info",
      message: "Aegis: AI reviewed this finding but did not return a safe replacement.",
    });
  });
});
