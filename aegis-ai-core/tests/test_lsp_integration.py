"""
test_lsp_integration.py - LSP 集成测试（单流程验收）

覆盖端到端流程：启动 LSP server -> initialize -> textDocument/didOpen（含漏洞代码）
-> 断言收到 textDocument/publishDiagnostics 且诊断非空。
"""

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest


def _make_lsp_message(method: str, params: dict, id_: int | None = None) -> bytes:
    """构造 LSP JSON-RPC 消息（含 Content-Length header）。"""
    body: dict = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    }
    if id_ is not None:
        body["id"] = id_
    content = json.dumps(body)
    header = f"Content-Length: {len(content)}\r\n\r\n"
    return (header + content).encode("utf-8")


def _read_lsp_response(proc: subprocess.Popen, timeout: float = 10.0) -> dict:
    """从 LSP Server stdout 读取一条 LSP 响应/通知。"""
    header_data = b""
    start = time.time()
    while True:
        if time.time() - start > timeout:
            raise TimeoutError("Timed out reading LSP response header")
        byte = proc.stdout.read(1)
        if byte == b"":
            raise EOFError("Server closed stdout")
        header_data += byte
        if header_data.endswith(b"\r\n\r\n"):
            break
    header_str = header_data.decode("utf-8")
    content_length = None
    for line in header_str.strip().split("\r\n"):
        if line.lower().startswith("content-length:"):
            content_length = int(line.split(":")[1].strip())
            break
    if content_length is None:
        raise ValueError(f"No Content-Length in header: {header_str}")
    body_data = b""
    while len(body_data) < content_length:
        remaining = content_length - len(body_data)
        chunk = proc.stdout.read(remaining)
        if chunk == b"":
            raise EOFError("Server closed stdout before body completed")
        body_data += chunk
    return json.loads(body_data.decode("utf-8"))


def _read_until_method(
    proc: subprocess.Popen, target_method: str, timeout: float = 10.0
) -> dict:
    """持续读取直到收到指定 method 的消息。"""
    start = time.time()
    while True:
        remaining = timeout - (time.time() - start)
        if remaining <= 0:
            raise TimeoutError(f"Timed out waiting for '{target_method}' message")
        msg = _read_lsp_response(proc, timeout=min(remaining, 5.0))
        if msg.get("method") == target_method:
            return msg


def test_lsp_integration_initialize_didopen_publish_diagnostics():
    """
    端到端：启动 LSP -> initialize -> didOpen（漏洞代码）-> 收到 publishDiagnostics 且非空。
    """
    proc = subprocess.Popen(
        [sys.executable, "-m", "src.lsp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    try:
        # initialize
        init_msg = _make_lsp_message(
            "initialize",
            {
                "processId": None,
                "capabilities": {},
                "rootUri": "file:///tmp/test",
            },
            id_=1,
        )
        proc.stdin.write(init_msg)
        proc.stdin.flush()
        response = _read_lsp_response(proc)
        assert response.get("id") == 1
        assert "result" in response

        initialized_msg = _make_lsp_message("initialized", {})
        proc.stdin.write(initialized_msg)
        proc.stdin.flush()

        # didOpen with vulnerable code
        vulnerable_code = "eval(req.query.x);\n"
        uri = "file:///tmp/test/vuln.js"
        did_open_msg = _make_lsp_message(
            "textDocument/didOpen",
            {
                "textDocument": {
                    "uri": uri,
                    "languageId": "javascript",
                    "version": 1,
                    "text": vulnerable_code,
                },
            },
        )
        proc.stdin.write(did_open_msg)
        proc.stdin.flush()

        # assert publishDiagnostics received and non-empty
        notification = _read_until_method(proc, "textDocument/publishDiagnostics")
        params = notification["params"]
        assert params["uri"] == uri
        assert len(params["diagnostics"]) > 0, (
            "Expected at least one diagnostic for vulnerable code"
        )
    finally:
        proc.stdin.close()
        proc.terminate()
        proc.wait(timeout=5)
