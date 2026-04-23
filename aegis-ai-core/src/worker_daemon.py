#!/usr/bin/env python3
"""
worker_daemon.py - Aegis 扫描守护进程（TDD 9.1.1 单守护进程 + 任务队列）

与 LSP 通过 IPC（本脚本使用 TCP Socket，可替换为 Named Pipe）通信：
- 接收扫描请求（file_path, content, language），返回 findings JSON。
- 内存保护：处理 N 个请求后或内存超阈值时优雅退出，由调用方重启。

运行方式（供 LSP/扩展将来对接）:
  python -m src.worker_daemon [--port 0] [--max-requests 1000] [--max-memory-mb 500]
  --port 0 表示自动选端口，启动后打印端口到 stdout，便于父进程连接。

当前为骨架：仅实现 TCP 接收/发送与请求计数，实际扫描逻辑复用 rule_engine。
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("aegis.worker_daemon")

# 默认内存/请求上限（TDD 9.1.1）
DEFAULT_MAX_REQUESTS = 1000
DEFAULT_MAX_MEMORY_MB = 500


def run_scan(file_path: str, content: str, language: str) -> list:
    """执行单文件扫描，返回 finding 列表。"""
    from src.analysis.rule_engine import analyze_javascript, analyze_python

    path = Path(file_path)
    if language == "python":
        return analyze_python(content, path)
    if language in ("javascript", "typescript"):
        return analyze_javascript(content, path, language=language)
    return []


def current_memory_mb() -> float:
    """当前进程内存占用（MB），不可用时返回 0。"""
    try:
        import psutil

        rss_bytes = psutil.Process(os.getpid()).memory_info().rss
        return float(rss_bytes) / (1024 * 1024)
    except (ImportError, OSError):
        return 0.0


def main() -> None:
    parser = argparse.ArgumentParser(description="Aegis scan worker daemon (TDD 9.1.1)")
    parser.add_argument("--port", type=int, default=0, help="TCP port (0=auto)")
    parser.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS)
    parser.add_argument("--max-memory-mb", type=float, default=DEFAULT_MAX_MEMORY_MB)
    args = parser.parse_args()

    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", args.port))
    port = sock.getsockname()[1]
    sock.listen(1)
    logger.info(
        "Worker daemon listening on 127.0.0.1:%s (max_requests=%s, max_memory_mb=%s)",
        port,
        args.max_requests,
        args.max_memory_mb,
    )

    request_count = 0
    while True:
        if request_count >= args.max_requests:
            logger.info("Reached max_requests=%s, exiting for graceful restart", args.max_requests)
            break
        mem_mb = current_memory_mb()
        if mem_mb > 0 and mem_mb >= args.max_memory_mb:
            logger.info("Memory %.1f MB >= %s MB, exiting for graceful restart", mem_mb, args.max_memory_mb)
            break

        try:
            sock.settimeout(5.0)
            conn, _ = sock.accept()
        except TimeoutError:
            continue
        except OSError as e:
            logger.exception("Accept error: %s", e)
            break

        try:
            with conn:
                buf = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    if b"\n" in buf or len(buf) > 1024 * 1024:
                        break
                raw = buf.decode("utf-8", errors="ignore").strip()
                if not raw:
                    conn.sendall(b'{"findings":[],"error":"empty request"}\n')
                    continue
                req = json.loads(raw.split("\n")[0])
                file_path = req.get("file_path", "")
                content = req.get("content", "")
                language = req.get("language", "javascript")
                findings = run_scan(file_path, content, language)
                request_count += 1
                out = json.dumps({"findings": findings}, ensure_ascii=False) + "\n"
                conn.sendall(out.encode("utf-8"))
        except Exception as e:  # Intentional: top-level defensive catch
            logger.exception("Request error: %s", e)
            try:
                conn.sendall(json.dumps({"findings": [], "error": str(e)}).encode("utf-8") + b"\n")
            except OSError as send_err:
                logger.debug("Failed to send error response to client: %s", send_err)

    sock.close()
    logger.info("Worker daemon exited (request_count=%s)", request_count)


if __name__ == "__main__":
    main()
