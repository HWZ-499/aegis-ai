"""Shared runtime diagnostics for recoverable analyzer degradation."""

from __future__ import annotations

import logging
from pathlib import Path


def log_analysis_degradation(
    logger: logging.Logger,
    *,
    language: str,
    stage: str,
    file_path: Path | str,
    error: BaseException,
) -> None:
    """Log a recoverable analyzer failure with a stable, searchable schema."""
    logger.debug(
        "analysis_degraded language=%s stage=%s file=%s error=%s: %s",
        language,
        stage,
        file_path,
        type(error).__name__,
        error,
    )


__all__ = ["log_analysis_degradation"]
