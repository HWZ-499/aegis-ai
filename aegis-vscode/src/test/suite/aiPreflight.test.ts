import * as assert from "assert";

import { getAiConfigurationError, getAiServerEnvironment } from "../../aiPreflight";

suite("AI Preflight Helpers", () => {
  test("returns disabled message when AI fixes are turned off", () => {
    const message = getAiConfigurationError("deepseek", {}, false);
    assert.ok(message?.includes("disabled"));
  });

  test("requires DeepSeek API key", () => {
    const message = getAiConfigurationError("deepseek", {}, true);
    assert.ok(message?.includes("DEEPSEEK_API_KEY"));
  });

  test("defaults to Ollama without API key", () => {
    const message = getAiConfigurationError("", {}, true);
    assert.strictEqual(message, undefined);
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

  test("maps Ollama settings to server environment", () => {
    const env = getAiServerEnvironment(
      {
        provider: "ollama",
        model: "codellama:13b",
        baseUrl: "http://localhost:11434/v1",
        envFile: "C:\\workspace\\.env",
      },
      {},
    );

    assert.strictEqual(env.AI_PROVIDER, "ollama");
    assert.strictEqual(env.AI_MODEL, "codellama:13b");
    assert.strictEqual(env.OLLAMA_MODEL, "codellama:13b");
    assert.strictEqual(env.OLLAMA_BASE_URL, "http://localhost:11434/v1");
    assert.strictEqual(env.AEGIS_ENV_FILE, "C:\\workspace\\.env");
  });

  test("maps custom base URL from settings before preflight", () => {
    const env = getAiServerEnvironment(
      {
        provider: "custom",
        baseUrl: "https://llm.example.test/v1",
      },
      { AI_API_KEY: "custom-key" },
    );

    assert.strictEqual(env.AI_BASE_URL, "https://llm.example.test/v1");
    assert.strictEqual(getAiConfigurationError("custom", env, true), undefined);
  });
});
