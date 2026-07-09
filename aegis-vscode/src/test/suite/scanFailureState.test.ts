import * as assert from "assert";

import {
  normalizeScanFailureMessage,
  ScanFailureState,
  scanFailureViewMessage,
} from "../../scanFailureState";

suite("scanFailureState", () => {
  test("normalizes multiline and missing scan errors for the UI", () => {
    assert.strictEqual(
      normalizeScanFailureMessage("  parser crashed\nwhile reading file  "),
      "parser crashed while reading file",
    );
    assert.strictEqual(
      normalizeScanFailureMessage(),
      "The scanner failed before producing diagnostics.",
    );
  });

  test("keeps a failed document out of the safe state until it is rescanned", () => {
    const state = new ScanFailureState();
    const failedUri = "file:///workspace/broken.js";

    state.record({ uri: failedUri, message: "Tree-sitter parser unavailable" });

    assert.strictEqual(state.getForUri(failedUri), "Tree-sitter parser unavailable");
    assert.strictEqual(state.getForUri("file:///workspace/other.js"), undefined);

    state.clearForScan(failedUri);
    assert.strictEqual(state.getForUri(failedUri), undefined);
  });

  test("shows a generic failure until the next scan starts", () => {
    const state = new ScanFailureState();
    state.record({ message: "backend connection dropped" });

    assert.strictEqual(state.getForUri("file:///workspace/demo.py"), "backend connection dropped");
    assert.strictEqual(
      scanFailureViewMessage(state.getForUri("file:///workspace/demo.py")),
      "Last scan failed: backend connection dropped Open the Aegis output for details.",
    );

    state.clearForScan("file:///workspace/demo.py");
    assert.strictEqual(state.getForUri("file:///workspace/demo.py"), undefined);
  });
});
