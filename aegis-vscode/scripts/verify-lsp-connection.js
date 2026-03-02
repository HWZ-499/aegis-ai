/**
 * 在本机验证 LSP 连接：用 Node 模拟扩展的 spawn + stdio，
 * 若此脚本能收到 Diagnostics，说明问题在 Cursor/扩展加载，不在 Python 或 cwd。
 *
 * 用法（在 aegis-vscode 目录）：node scripts/verify-lsp-connection.js
 */

const path = require("path");
const { spawn } = require("child_process");

const AEGIS_CORE = path.join(__dirname, "..", "..", "aegis-ai-core");

function makeLspMessage(method, params, id) {
  const body = { jsonrpc: "2.0", method, params };
  if (id != null) body.id = id;
  const content = JSON.stringify(body);
  return `Content-Length: ${Buffer.byteLength(content, "utf8")}\r\n\r\n${content}`;
}

function readLspMessage(stream) {
  return new Promise((resolve, reject) => {
    let header = "";
    const onData = (chunk) => {
      header += chunk.toString("utf8");
      const idx = header.indexOf("\r\n\r\n");
      if (idx === -1) return;
      stream.removeListener("data", onData);
      const match = header.match(/Content-Length:\s*(\d+)/i);
      if (!match) return reject(new Error("No Content-Length"));
      const len = parseInt(match[1], 10);
      const bodyStart = idx + 4;
      let body = header.slice(bodyStart);
      const bodyBytes = Buffer.byteLength(body, "utf8");
      if (bodyBytes >= len) {
        try {
          resolve(JSON.parse(body.slice(0, len)));
        } catch (e) {
          reject(e);
        }
        return;
      }
      const need = len - bodyBytes;
      const rest = [];
      let got = 0;
      const onData2 = (c) => {
        rest.push(c);
        got += c.length;
        if (got >= need) {
          stream.removeListener("data", onData2);
          const full = body + Buffer.concat(rest).toString("utf8").slice(0, need);
          try {
            resolve(JSON.parse(full));
          } catch (e) {
            reject(e);
          }
        }
      };
      stream.on("data", onData2);
    };
    stream.on("data", onData);
  });
}

function readUntilMethod(stream, targetMethod, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  const tryRead = () => {
    if (Date.now() > deadline) return Promise.reject(new Error("Timeout"));
    return readLspMessage(stream).then((msg) => {
      if (msg.method === targetMethod) return msg;
      return tryRead();
    });
  };
  return tryRead();
}

async function main() {
  console.log("aegis-ai-core 路径:", AEGIS_CORE);
  console.log("启动: python -m src.lsp (cwd = aegis-ai-core) ...");

  const proc = spawn("python", ["-m", "src.lsp"], {
    cwd: AEGIS_CORE,
    stdio: ["pipe", "pipe", "pipe"],
  });

  proc.stderr.on("data", (d) => process.stderr.write(d));

  const send = (msg) => {
    const s = makeLspMessage(msg.method, msg.params, msg.id);
    proc.stdin.write(s, "utf8");
  };

  try {
    send({ method: "initialize", params: { processId: null, capabilities: {}, rootUri: "file:///tmp" }, id: 1 });
    const initResp = await readLspMessage(proc.stdout);
    if (initResp.id !== 1 || !initResp.result) {
      console.error("initialize 失败:", initResp);
      process.exit(1);
    }
    console.log("initialize OK");

    send({ method: "initialized", params: {} });

    const code = 'eval("console.log(\'Hello, world!\');");';
    const uri = "file:///tmp/test.js";
    send({
      method: "textDocument/didOpen",
      params: {
        textDocument: { uri, languageId: "javascript", version: 1, text: code },
      },
    });

    const notif = await readUntilMethod(proc.stdout, "textDocument/publishDiagnostics", 10000);
    const diags = notif.params.diagnostics || [];
    console.log("publishDiagnostics 收到条数:", diags.length);
    if (diags.length > 0) {
      console.log("第一条:", diags[0].message, "code:", diags[0].code);
      console.log("\n结论: LSP Server 在本机工作正常，能返回 Diagnostics。");
      console.log("若 Cursor 里仍无波浪线，多半是扩展未正确加载（例如用了旧 VSIX）。");
      console.log("建议: 先卸载已安装的 Aegis 扩展，再用「从文件夹安装」选 aegis-vscode 目录。");
    } else {
      console.log("未收到 Diagnostic（异常）。");
    }
  } catch (e) {
    console.error("错误:", e.message);
    process.exit(1);
  } finally {
    proc.stdin.end();
    proc.kill();
  }
}

main();
