import * as assert from "assert";

import { ExecFileLike, probePythonVersion } from "../../pythonProbe";

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
});
