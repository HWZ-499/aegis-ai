import * as assert from "assert";

import { getAiConfigurationError } from "../../aiPreflight";

suite("AI Preflight Helpers", () => {
  test("returns disabled message when AI fixes are turned off", () => {
    const message = getAiConfigurationError("deepseek", {}, false);
    assert.ok(message?.includes("disabled"));
  });

  test("requires DeepSeek API key", () => {
    const message = getAiConfigurationError("deepseek", {}, true);
    assert.ok(message?.includes("DEEPSEEK_API_KEY"));
  });

  test("accepts Ollama without API key", () => {
    const message = getAiConfigurationError("ollama", {}, true);
    assert.strictEqual(message, undefined);
  });

  test("requires custom endpoint base url and key", () => {
    const message = getAiConfigurationError("custom", {}, true);
    assert.ok(message?.includes("AI_BASE_URL"));
    assert.ok(message?.includes("AI_API_KEY"));
  });
});
