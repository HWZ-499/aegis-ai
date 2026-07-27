"""Shared filesystem metadata helpers with observable degradation."""

from __future__ import annotations

import logging
from pathlib import Path


def get_file_size(
    file_path: Path | str,
    *,
    logger: logging.Logger,
    component: str,
) -> int | None:
    """Return file size, or ``None`` when metadata is unavailable."""
    path = Path(file_path)
    try:
        return path.stat().st_size
    except OSError as error:
        logger.debug(
            "file_metadata_degraded component=%s path=%s error=%s: %s",
            component,
            path,
            type(error).__name__,
            error,
        )
        return None


__all__ = ["get_file_size"]
