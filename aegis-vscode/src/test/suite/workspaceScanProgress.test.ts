import * as assert from "assert";

import { WorkspaceScanProgress } from "../../workspaceScanProgress";

suite("workspaceScanProgress", () => {
  test("reports proportional increments and completes the active scan", async () => {
    const tracker = new WorkspaceScanProgress();
    const reports: { message?: string; increment?: number }[] = [];
    const completion = tracker.start("scan-1", { report: (value) => reports.push(value) });

    tracker.report({ scanId: "scan-1", current: 1, total: 4 });
    tracker.report({ scanId: "scan-1", current: 3, total: 4 });
    tracker.report({ scanId: "scan-1", current: 4, total: 4 });
    await completion;

    assert.deepStrictEqual(reports, [
      { message: "Scanning 1/4", increment: 25 },
      { message: "Scanning 3/4", increment: 50 },
      { message: "Scanning 4/4", increment: 25 },
    ]);
    assert.strictEqual(tracker.isActive, false);
  });

  test("ignores delayed notifications from another scan", () => {
    const tracker = new WorkspaceScanProgress();
    const reports: { message?: string; increment?: number }[] = [];
    void tracker.start("current", { report: (value) => reports.push(value) });

    tracker.report({ scanId: "stale", current: 10, total: 10 });

    assert.deepStrictEqual(reports, []);
    assert.strictEqual(tracker.isActive, true);
    tracker.finish("current");
  });

  test("finishes cleanly when no supported files are found", async () => {
    const tracker = new WorkspaceScanProgress();
    const reports: { message?: string; increment?: number }[] = [];
    const completion = tracker.start("empty", { report: (value) => reports.push(value) });

    tracker.report({ scanId: "empty", current: 0, total: 0 });
    await completion;

    assert.deepStrictEqual(reports, [{ message: "No supported files found" }]);
    assert.strictEqual(tracker.isActive, false);
  });

  test("rejects a second active scan instead of replacing its promise", () => {
    const tracker = new WorkspaceScanProgress();
    void tracker.start("first", { report: () => undefined });

    assert.throws(
      () => tracker.start("second", { report: () => undefined }),
      /already in progress/,
    );
    tracker.finish("first");
  });
});
