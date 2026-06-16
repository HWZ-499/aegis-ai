# scanner - 漏扫工具模块
"""
漏扫工具模块：批量扫描、报告生成、CLI 工具
"""

from .project_scanner import ProjectScanner
from .report_generator import ReportGenerator


def cli_main(*args, **kwargs):
    """Lazily dispatch to the CLI entrypoint without eager module import side effects."""
    from .cli import main

    return main(*args, **kwargs)


__all__ = ["ProjectScanner", "ReportGenerator", "cli_main"]
