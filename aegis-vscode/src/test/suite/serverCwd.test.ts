import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { resolveServerCwd } from "../../serverCwd";

suite("serverCwd", () => {
  test("finds aegis-ai-core when the opened workspace is nested inside the core repo", () => {
    const repoRoot = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-cwd-"));
    const coreRoot = path.join(repoRoot, "aegis-ai-core");
    const nestedWorkspace = path.join(
      coreRoot,
      "tests",
      "rules",
      "hardcoded_credentials",
      "true_positive",
    );
    const packagedExtensionPath = path.join(os.tmpdir(), "vscode-ext", "aegis-ai-security");
    fs.mkdirSync(nestedWorkspace, { recursive: true });

    const result = resolveServerCwd({
      explicitCwd: "",
      workspaceFolders: [nestedWorkspace],
      extensionPath: packagedExtensionPath,
    });

    assert.strictEqual(result.cwd, coreRoot);
  });
});
