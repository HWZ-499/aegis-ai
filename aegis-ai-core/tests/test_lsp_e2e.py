"""
test_lsp_e2e.py - Aegis AI LSP Server 端到端集成测试

通过子进程启动 LSP Server，模拟 LSP 客户端发送 initialize / didOpen 请求，
验证 Server 能正确返回 Diagnostics。
"""

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest


# LSP 消息工具函数
def _make_lsp_message(method: str, params: dict, id_: int = None) -> bytes:
    """
    构造 LSP JSON-RPC 消息（包含 Content-Length header）。

    Args:
        method: JSON-RPC 方法名
        params: 参数字典
        id_: 请求 ID（通知消息可为 None）

    Returns:
        完整的 LSP 消息 bytes。
    """
    body = {
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
    """
    从 LSP Server 的 stdout 中读取一条 LSP 响应/通知。

    Args:
        proc: LSP Server 子进程
        timeout: 超时秒数

    Returns:
        解析后的 JSON-RPC 消息字典。
    """
    # 读取 Content-Length header
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

    # 解析 Content-Length
    header_str = header_data.decode("utf-8")
    content_length = None
    for line in header_str.strip().split("\r\n"):
        if line.lower().startswith("content-length:"):
            content_length = int(line.split(":")[1].strip())
            break

    if content_length is None:
        raise ValueError(f"No Content-Length in header: {header_str}")

    # 读取 body
    body_data = b""
    while len(body_data) < content_length:
        remaining = content_length - len(body_data)
        chunk = proc.stdout.read(remaining)
        if chunk == b"":
            raise EOFError("Server closed stdout before body completed")
        body_data += chunk

    return json.loads(body_data.decode("utf-8"))


def _read_until_method(proc: subprocess.Popen, target_method: str,
                       timeout: float = 10.0) -> dict:
    """
    持续读取 LSP 消息，直到收到指定 method 的消息。

    中间收到的其他通知（如 window/showMessage、window/logMessage）会被跳过。

    Args:
        proc: LSP Server 子进程
        target_method: 目标 JSON-RPC method 名
        timeout: 总超时秒数

    Returns:
        匹配 target_method 的消息字典。
    """
    start = time.time()
    while True:
        remaining = timeout - (time.time() - start)
        if remaining <= 0:
            raise TimeoutError(
                f"Timed out waiting for '{target_method}' message"
            )
        msg = _read_lsp_response(proc, timeout=remaining)
        if msg.get("method") == target_method:
            return msg


class TestLSPEndToEnd:
    """LSP Server 端到端集成测试。"""

    @pytest.fixture()
    def lsp_server(self):
        """启动 LSP Server 子进程。"""
        proc = subprocess.Popen(
            [sys.executable, "-m", "src.lsp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(Path(__file__).resolve().parent.parent),
        )
        yield proc
        # 清理
        proc.stdin.close()
        proc.terminate()
        proc.wait(timeout=5)

    def _initialize(self, proc: subprocess.Popen) -> dict:
        """发送 initialize 请求并读取响应。"""
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

        # 发送 initialized 通知
        initialized_msg = _make_lsp_message("initialized", {})
        proc.stdin.write(initialized_msg)
        proc.stdin.flush()

        return response

    def test_initialize_response(self, lsp_server):
        """Server 能正确响应 initialize 请求。"""
        response = self._initialize(lsp_server)
        result = response["result"]

        # 检查 server capabilities
        caps = result.get("capabilities", {})
        assert caps is not None

        # 应该支持 textDocumentSync
        text_doc_sync = caps.get("textDocumentSync")
        assert text_doc_sync is not None

    def test_didopen_vulnerable_js_publishes_diagnostics(self, lsp_server):
        """打开含漏洞的 JS 文件应发布 Diagnostics。"""
        self._initialize(lsp_server)

        vulnerable_code = 'const userInput = req.query.name;\neval(userInput);\n'
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
        lsp_server.stdin.write(did_open_msg)
        lsp_server.stdin.flush()

        # 读取 publishDiagnostics 通知（跳过其他通知）
        notification = _read_until_method(lsp_server, "textDocument/publishDiagnostics")

        params = notification["params"]
        assert params["uri"] == uri
        assert len(params["diagnostics"]) > 0

        # 至少一个 RCE 相关的 Diagnostic
        codes = [d.get("code", "") for d in params["diagnostics"]]
        assert any("RCE" in str(c) for c in codes), f"Expected RCE diagnostic, got: {codes}"

        # 验证 source 都是 Aegis AI
        for d in params["diagnostics"]:
            assert d["source"] == "Aegis AI"

    def test_didopen_safe_js_publishes_empty_diagnostics(self, lsp_server):
        """打开安全的 JS 文件应发布空 Diagnostics。"""
        self._initialize(lsp_server)

        safe_code = 'const x = 1 + 2;\nconsole.log(x);\n'
        uri = "file:///tmp/test/safe.js"

        did_open_msg = _make_lsp_message(
            "textDocument/didOpen",
            {
                "textDocument": {
                    "uri": uri,
                    "languageId": "javascript",
                    "version": 1,
                    "text": safe_code,
                },
            },
        )
        lsp_server.stdin.write(did_open_msg)
        lsp_server.stdin.flush()

        notification = _read_until_method(lsp_server, "textDocument/publishDiagnostics")
        assert notification["params"]["diagnostics"] == []

    def test_didopen_unsupported_language_publishes_empty(self, lsp_server):
        """打开不支持的语言文件应发布空 Diagnostics。"""
        self._initialize(lsp_server)

        uri = "file:///tmp/test/readme.md"
        did_open_msg = _make_lsp_message(
            "textDocument/didOpen",
            {
                "textDocument": {
                    "uri": uri,
                    "languageId": "markdown",
                    "version": 1,
                    "text": "# Hello",
                },
            },
        )
        lsp_server.stdin.write(did_open_msg)
        lsp_server.stdin.flush()

        notification = _read_until_method(lsp_server, "textDocument/publishDiagnostics")
        assert notification["params"]["diagnostics"] == []

    def test_didopen_vulnerable_python_publishes_diagnostics(self, lsp_server):
        """打开含漏洞的 Python 文件应发布 Diagnostics。"""
        self._initialize(lsp_server)

        vulnerable_code = 'import os\nuser_input = input()\nos.system(user_input)\n'
        uri = "file:///tmp/test/vuln.py"

        did_open_msg = _make_lsp_message(
            "textDocument/didOpen",
            {
                "textDocument": {
                    "uri": uri,
                    "languageId": "python",
                    "version": 1,
                    "text": vulnerable_code,
                },
            },
        )
        lsp_server.stdin.write(did_open_msg)
        lsp_server.stdin.flush()

        notification = _read_until_method(lsp_server, "textDocument/publishDiagnostics")
        assert len(notification["params"]["diagnostics"]) > 0

    def test_severity_mapping_in_diagnostics(self, lsp_server):
        """验证 Diagnostic 中的 severity 值符合 LSP 规范。"""
        self._initialize(lsp_server)

        # eval(userInput) 应该产生 High/Critical severity
        vulnerable_code = 'eval(userInput);\n'
        uri = "file:///tmp/test/eval.js"

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
        lsp_server.stdin.write(did_open_msg)
        lsp_server.stdin.flush()

        notification = _read_until_method(lsp_server, "textDocument/publishDiagnostics")
        diagnostics = notification["params"]["diagnostics"]
        assert len(diagnostics) > 0

        for d in diagnostics:
            # LSP severity: 1=Error, 2=Warning, 3=Information, 4=Hint
            assert d["severity"] in [1, 2, 3, 4]
