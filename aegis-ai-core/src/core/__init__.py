"""
Aegis AI Core — 共享基础设施模块。

提供统一配置、日志、数据模型，供 analysis / scanner / lsp / server 层引用。
"""

from .config import get_settings
from .logging_config import setup_logging
from .models import Finding, RelatedLocation, TaintStep, ScanResult, AuditResponse

__all__ = [
    "get_settings",
    "setup_logging",
    "Finding",
    "RelatedLocation",
    "TaintStep",
    "ScanResult",
    "AuditResponse",
]
