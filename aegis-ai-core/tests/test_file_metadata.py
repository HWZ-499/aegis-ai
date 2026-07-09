import logging
from pathlib import Path

import pytest

from src.core.file_metadata import get_file_size


def test_get_file_size_logs_metadata_degradation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    file_path = tmp_path / "app.py"
    file_path.write_text("print('ok')\n", encoding="utf-8")
    original_stat = Path.stat

    def failing_stat(path: Path, *args, **kwargs):
        if path == file_path:
            raise OSError("metadata unavailable")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", failing_stat)
    logger = logging.getLogger("test.file_metadata")

    with caplog.at_level(logging.DEBUG, logger="test.file_metadata"):
        size = get_file_size(file_path, logger=logger, component="test")

    assert size is None
    assert "file_metadata_degraded component=test" in caplog.text
    assert "error=OSError: metadata unavailable" in caplog.text
