from __future__ import annotations

import json
from pathlib import Path

from src.scanner.false_positive_manager import FalsePositiveManager
from src.scanner.performance_optimizer import ScanCache
from src.scanner.rule_config import RuleConfig


def test_false_positive_manager_falls_back_when_config_shape_is_invalid(tmp_path: Path) -> None:
    config_path = tmp_path / ".aegis-fp.json"
    config_path.write_text(json.dumps(["invalid-shape"]), encoding="utf-8")

    manager = FalsePositiveManager(str(config_path))

    assert manager.list_false_positives() == []
    assert manager.is_false_positive("app.py", 1, "SQL_INJECTION") is False


def test_rule_config_falls_back_when_config_shape_is_invalid(tmp_path: Path) -> None:
    config_path = tmp_path / "rules.json"
    config_path.write_text(json.dumps(["invalid-shape"]), encoding="utf-8")

    cfg = RuleConfig(str(config_path))

    # Default config should still work for rule checks.
    assert cfg.is_rule_enabled("SQL_INJECTION", r"r'foo'") is True


def test_scan_cache_rejects_non_list_findings_in_cache_file(tmp_path: Path) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text("print('ok')", encoding="utf-8")

    cache = ScanCache(cache_dir=str(tmp_path / "cache"), ttl_hours=24)
    cache_key = cache._get_cache_key(source_file)
    cache_file = Path(cache.cache_dir) / f"{cache_key}.json"
    cache_file.write_text(
        json.dumps(
            {
                "file_path": str(source_file),
                "findings": {"bad": "shape"},
            }
        ),
        encoding="utf-8",
    )

    assert cache.get_cached_result(source_file) is None
