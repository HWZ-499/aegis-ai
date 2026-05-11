import * as assert from "assert";

import { buildTaintPathHtmlForTest, TaintPathData } from "../../taintPathWebview";

suite("taintPathWebview", () => {
  test("serializes taint node locations without inline JavaScript handlers", () => {
    const data: TaintPathData = {
      vulnType: "XSS_RISK",
      severity: "High",
      taintPath: {
        nodes: [
          {
            nodeType: "SOURCE",
            name: "req.query.name",
            filePath: "C:/tmp/x');alert(1);//.js",
            line: 3,
            column: 0,
            codeSnippet: "const name = req.query.name;",
          },
        ],
        edges: [],
        pathLength: 1,
        isSanitized: false,
        riskLevel: "High",
        confidence: 0.9,
      },
    };

    const html = buildTaintPathHtmlForTest(data);

    assert.ok(!html.includes("onclick="));
    assert.ok(!html.includes("jumpTo('"));
    assert.ok(html.includes("data-node-index=\"0\""));
    assert.ok(html.includes("\\u0027") || html.includes("x');alert(1);"));
    assert.ok(html.includes("JSON.parse"));
  });
});
