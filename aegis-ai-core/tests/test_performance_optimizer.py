from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Lock, get_ident

import pytest

from src.scanner.performance_optimizer import PerformanceOptimizer, ScanCache


def test_scan_cache_keeps_identical_same_named_files_separate(tmp_path: Path) -> None:
    first_file = tmp_path / "first" / "index.py"
    second_file = tmp_path / "second" / "index.py"
    for file_path in (first_file, second_file):
        file_path.parent.mkdir()
        file_path.write_text("print('same content')\n", encoding="utf-8")

    cache = ScanCache(cache_dir=str(tmp_path / ".aegis-cache"))
    cache.save_result(first_file, [{"source": "first"}], rules_version_hash="rules-v1")
    cache.save_result(second_file, [{"source": "second"}], rules_version_hash="rules-v1")

    assert cache.get_cached_result(first_file, rules_version_hash="rules-v1") == [{"source": "first"}]
    assert cache.get_cached_result(second_file, rules_version_hash="rules-v1") == [{"source": "second"}]


def test_scan_cache_concurrent_writers_leave_complete_json(tmp_path: Path) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text("print('ok')\n", encoding="utf-8")
    cache = ScanCache(cache_dir=str(tmp_path / ".aegis-cache"))

    def write_result(index: int) -> None:
        cache.save_result(
            source_file,
            [{"writer": index, "payload": "x" * 1000}],
            rules_version_hash="rules-v1",
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(write_result, range(32)))

    result = cache.get_cached_result(source_file, rules_version_hash="rules-v1")
    assert result is not None
    assert len(result) == 1
    assert result[0]["writer"] in range(32)
    assert result[0]["payload"] == "x" * 1000
    assert list(cache.cache_dir.glob("*.tmp")) == []


def test_scan_cache_failed_replace_preserves_previous_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text("print('ok')\n", encoding="utf-8")
    cache = ScanCache(cache_dir=str(tmp_path / ".aegis-cache"))
    cache.save_result(source_file, [{"version": "old"}], rules_version_hash="rules-v1")

    def fail_replace(source: Path, destination: Path) -> None:
        raise OSError("simulated interruption")

    monkeypatch.setattr("src.scanner.performance_optimizer.os.replace", fail_replace)

    cache.save_result(source_file, [{"version": "new"}], rules_version_hash="rules-v1")

    assert cache.get_cached_result(source_file, rules_version_hash="rules-v1") == [{"version": "old"}]
    assert list(cache.cache_dir.glob("*.tmp")) == []


def test_scan_cache_clear_removes_orphaned_temp_files(tmp_path: Path) -> None:
    cache = ScanCache(cache_dir=str(tmp_path / ".aegis-cache"))
    orphan = cache.cache_dir / ".orphan.tmp"
    orphan.write_text("partial", encoding="utf-8")

    cache.clear_cache()

    assert not orphan.exists()


def test_scan_files_optimized_runs_scan_func_concurrently_and_keeps_input_order(tmp_path: Path) -> None:
    files = [tmp_path / "first.py", tmp_path / "second.py"]
    for file_path in files:
        file_path.write_text("print('ok')\n", encoding="utf-8")

    optimizer = PerformanceOptimizer(
        use_cache=False,
        use_parallel=True,
        max_workers=2,
    )
    rendezvous = Barrier(2, timeout=5)
    worker_ids: set[int] = set()
    worker_ids_lock = Lock()

    def scan_func(file_path: Path) -> list[dict]:
        with worker_ids_lock:
            worker_ids.add(get_ident())
        rendezvous.wait()
        return [{"file": file_path.name}]

    results = optimizer.scan_files_optimized(
        files,
        scan_func=scan_func,
        project_path=tmp_path,
        supported_extensions={".py": "python"},
    )

    assert list(results) == files
    assert len(worker_ids) == 2


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

    original_get_file_hash = optimizer.cache._get_file_hash
    file_hash_calls = 0

    def counted_file_hash(file_path: Path) -> str:
        nonlocal file_hash_calls
        file_hash_calls += 1
        return original_get_file_hash(file_path)

    monkeypatch.setattr(optimizer.cache, "_get_file_hash", counted_file_hash)

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
    assert file_hash_calls == len(files)
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
    assert file_hash_calls == len(files) * 2
    assert set(second_results) == set(files)
    assert scanned == []
