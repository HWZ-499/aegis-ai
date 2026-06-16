from pathlib import Path

import pytest

from src.scanner.performance_optimizer import PerformanceOptimizer


def test_scan_files_optimized_reuses_rule_version_hash_per_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files = [tmp_path / "a.py", tmp_path / "b.py"]
    for file_path in files:
        file_path.write_text("print('ok')\n", encoding="utf-8")

    optimizer = PerformanceOptimizer(
        cache_dir=str(tmp_path / ".aegis-cache"),
        use_cache=True,
        use_parallel=False,
    )
    assert optimizer.cache is not None

    hash_calls = 0

    def fake_rules_hash() -> str:
        nonlocal hash_calls
        hash_calls += 1
        return "rules-v1"

    monkeypatch.setattr(optimizer.cache, "_get_rules_version_hash", fake_rules_hash)

    scanned: list[Path] = []

    def scan_func(file_path: Path) -> list[dict]:
        scanned.append(file_path)
        return [{"rule_id": "demo", "file": str(file_path)}]

    first_results = optimizer.scan_files_optimized(
        files,
        scan_func=scan_func,
        project_path=tmp_path,
        supported_extensions={".py": "python"},
    )

    assert hash_calls == 1
    assert set(first_results) == set(files)
    assert scanned == files

    scanned.clear()
    second_results = optimizer.scan_files_optimized(
        files,
        scan_func=scan_func,
        project_path=tmp_path,
        supported_extensions={".py": "python"},
    )

    assert hash_calls == 2
    assert set(second_results) == set(files)
    assert scanned == []
