"""
logging_config.py — 统一日志配置。

在进程入口处调用一次 ``setup_logging()``，所有模块使用
``logging.getLogger(__name__)`` 自动继承统一格式。
"""

from __future__ import annotations

import logging
import sys

_CONFIGURED = False

_DEFAULT_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
_DEFAULT_DATEFMT = "%Y-%m-%d %H:%M:%S"


def setup_logging(
    level: str = "INFO",
    json_format: bool = False,
) -> None:
    """
    一次性初始化根 Logger。

    Args:
        level: 日志级别（DEBUG / INFO / WARNING / ERROR）。
        json_format: 是否使用 JSON 结构化输出（需要 python-json-logger）。
    """
    global _CONFIGURED
    if _CONFIGURED:
        return
    _CONFIGURED = True

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    handler = logging.StreamHandler(sys.stderr)

    if json_format:
        try:
            from pythonjsonlogger import jsonlogger

            handler.setFormatter(
                jsonlogger.JsonFormatter(
                    "%(asctime)s %(name)s %(levelname)s %(message)s",
                    datefmt=_DEFAULT_DATEFMT,
                )
            )
        except ImportError:
            handler.setFormatter(logging.Formatter(_DEFAULT_FORMAT, datefmt=_DEFAULT_DATEFMT))
            logging.getLogger(__name__).warning("python-json-logger not installed, falling back to text format")
    else:
        handler.setFormatter(logging.Formatter(_DEFAULT_FORMAT, datefmt=_DEFAULT_DATEFMT))

    root.handlers.clear()
    root.addHandler(handler)

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("chromadb").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
