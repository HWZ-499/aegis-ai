import * as assert from "assert";
import { OutputChannel } from "vscode";

import {
  AEGIS_LANGUAGE_IDS,
  AegisInitializationOptions,
  createLanguageClientOptions,
} from "../../languageClientOptions";

suite("languageClientOptions", () => {
  test("covers every supported editor language without a recursive file watcher", () => {
    const initializationOptions: AegisInitializationOptions = {
      severity_minimum: "Low",
      exclude_patterns: ["**/node_modules/**"],
      disabled_rules: [],
      ai_enabled: true,
      ai_provider: "ollama",
      scan_on_save: true,
      scan_on_change: true,
      experimental_cross_file: false,
    };

    const options = createLanguageClientOptions({} as OutputChannel, initializationOptions);
    const languages = (options.documentSelector ?? []).map((selector) =>
      typeof selector === "string" ? selector : selector.language,
    );

    assert.deepStrictEqual(languages, [...AEGIS_LANGUAGE_IDS]);
    assert.strictEqual(options.synchronize?.fileEvents, undefined);
    assert.strictEqual(options.initializationOptions, initializationOptions);
  });
});
