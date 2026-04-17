import * as assert from "assert";

import { ExecFileLike, isPythonVersionSupported, parsePythonVersion, probePythonVersion } from "../../pythonProbe";

suite("pythonProbe", () => {
  test("uses stderr when python reports version there", async () => {
    const version = await probePythonVersion(
      "python",
      ((file, args, options, callback) => {
        void file;
        void args;
        void options;
        callback(null, "", "Python 3.11.9");
      }) as ExecFileLike,
    );

    assert.strictEqual(version, "Python 3.11.9");
  });

  test("rejects when probing fails", async () => {
    await assert.rejects(async () =>
      probePythonVersion(
        "python",
        ((file, args, options, callback) => {
          void file;
          void args;
          void options;
          callback(new Error("missing python"), "", "");
        }) as ExecFileLike,
      ),
    );
  });

  test("parses Python version output", () => {
    assert.deepStrictEqual(parsePythonVersion("Python 3.11.9"), {
      major: 3,
      minor: 11,
      patch: 9,
      raw: "Python 3.11.9",
    });
  });

  test("requires Python 3.10 or newer", () => {
    assert.strictEqual(isPythonVersionSupported("Python 3.9.18"), false);
    assert.strictEqual(isPythonVersionSupported("Python 3.10.0"), true);
    assert.strictEqual(isPythonVersionSupported("Python 3.12.1"), true);
  });
});
