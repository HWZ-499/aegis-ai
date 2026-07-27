from pathlib import Path

import pytest

from src.analysis.dsl import load_dsl_rule_definitions
from src.scanner.project_scanner import ProjectScanner


def _write_custom_rule(rules_dir: Path, *, rule_id: str, language: str, pattern: str, vuln_type: str) -> None:
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / f"{language}.custom.yaml").write_text(
        f"""
id: {rule_id}
language: {language}
severity: HIGH
message: "Custom {language} rule"
vuln_type: {vuln_type}
patterns:
  - pattern: {pattern}
""",
        encoding="utf-8",
    )


def test_default_scan_keeps_business_like_source_directories(tmp_path: Path) -> None:
    """默认配置不应静默跳过常见业务源码目录。"""
    for rel in ("lib/app.py", "public/app.js", "static/handler.py", "resources/main.go"):
        file_path = tmp_path / rel
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text("print('ok')\n", encoding="utf-8")

    scanner = ProjectScanner(str(tmp_path))
    discovered, skipped = scanner._get_discovery()
    discovered_rel = {str(path.relative_to(tmp_path)).replace("\\", "/") for path in discovered}
    skipped_rel = {str(path).replace("\\", "/") for path, _ in skipped}

    assert "lib/app.py" in discovered_rel
    assert "public/app.js" in discovered_rel
    assert "static/handler.py" in discovered_rel
    assert "resources/main.go" in discovered_rel
    assert "lib/app.py" not in skipped_rel
    assert "public/app.js" not in skipped_rel
    assert "static/handler.py" not in skipped_rel
    assert "resources/main.go" not in skipped_rel


def test_default_scan_still_skips_dependency_and_build_directories(tmp_path: Path) -> None:
    """依赖和构建目录仍应被默认忽略。"""
    for rel in ("node_modules/pkg/index.js", "dist/app.js", "build/main.py"):
        file_path = tmp_path / rel
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text("eval(input)\n", encoding="utf-8")

    scanner = ProjectScanner(str(tmp_path))
    discovered, _ = scanner._get_discovery()
    discovered_rel = {str(path.relative_to(tmp_path)).replace("\\", "/") for path in discovered}

    assert "node_modules/pkg/index.js" not in discovered_rel
    assert "dist/app.js" not in discovered_rel
    assert "build/main.py" not in discovered_rel


def test_source_reader_preserves_universal_newlines_and_ignores_invalid_utf8(tmp_path: Path) -> None:
    source_file = tmp_path / "mixed.py"
    source_file.write_bytes(
        b"first" + bytes([13, 10]) + b"second" + bytes([13]) + b"third" + bytes([10]) + b"invalid:" + bytes([255, 10])
    )

    source = ProjectScanner._read_source_file(source_file)

    assert source == "first\nsecond\nthird\ninvalid:\n"


def test_scan_project_applies_extra_php_dsl_rules(tmp_path: Path) -> None:
    """ProjectScanner should pass custom DSL dirs through the PHP analyzer."""
    rules_dir = tmp_path / ".aegis" / "rules"
    _write_custom_rule(
        rules_dir,
        rule_id="dsl.php.custom-dangerous-call",
        language="php",
        pattern="dangerous_php($ARG)",
        vuln_type="CUSTOM_PHP_RISK",
    )
    app = tmp_path / "app.php"
    app.write_text("<?php\n$input = $_GET['x'];\ndangerous_php($input);\n", encoding="utf-8")

    scanner = ProjectScanner(
        str(tmp_path),
        use_cache=False,
        use_parallel=False,
    )

    results = scanner.scan_project()

    findings = results["app.php"]
    assert any(
        finding.get("type") == "CUSTOM_PHP_RISK" and finding.get("rule_id") == "dsl.php.custom-dangerous-call"
        for finding in findings
    )


def test_scan_project_applies_extra_java_dsl_rules(tmp_path: Path) -> None:
    """ProjectScanner should merge custom DSL rules into Java default rules."""
    rules_dir = tmp_path / ".aegis" / "rules"
    _write_custom_rule(
        rules_dir,
        rule_id="dsl.java.custom-dangerous-call",
        language="java",
        pattern="dangerousJava($ARG)",
        vuln_type="CUSTOM_JAVA_RISK",
    )
    app = tmp_path / "App.java"
    app.write_text(
        "class App { void run(String input) { dangerousJava(input); } }\n",
        encoding="utf-8",
    )

    scanner = ProjectScanner(
        str(tmp_path),
        use_cache=False,
        use_parallel=False,
    )

    results = scanner.scan_project()

    findings = results["App.java"]
    assert any(
        finding.get("type") == "CUSTOM_JAVA_RISK" and finding.get("rule_id") == "dsl.java.custom-dangerous-call"
        for finding in findings
    )


def test_scan_project_cache_invalidates_when_custom_dsl_rule_changes(tmp_path: Path) -> None:
    """Project scan cache must be invalidated when project DSL rules change."""
    rules_dir = tmp_path / ".aegis" / "rules"
    _write_custom_rule(
        rules_dir,
        rule_id="dsl.php.custom-cache-sensitive",
        language="php",
        pattern="not_present($ARG)",
        vuln_type="CUSTOM_CACHE_RISK",
    )
    app = tmp_path / "app.php"
    app.write_text("<?php\n$input = $_GET['x'];\ndangerous_php($input);\n", encoding="utf-8")

    first_scanner = ProjectScanner(str(tmp_path), use_cache=True, use_parallel=False)
    first_results = first_scanner.scan_project()

    assert not any(
        finding.get("rule_id") == "dsl.php.custom-cache-sensitive"
        for findings in first_results.values()
        for finding in findings
    )

    _write_custom_rule(
        rules_dir,
        rule_id="dsl.php.custom-cache-sensitive",
        language="php",
        pattern="dangerous_php($ARG)",
        vuln_type="CUSTOM_CACHE_RISK",
    )

    second_scanner = ProjectScanner(str(tmp_path), use_cache=True, use_parallel=False)
    second_results = second_scanner.scan_project()

    assert any(
        finding.get("type") == "CUSTOM_CACHE_RISK" and finding.get("rule_id") == "dsl.php.custom-cache-sensitive"
        for finding in second_results["app.php"]
    )


def test_scan_project_resets_state_and_returns_stable_snapshots(tmp_path: Path) -> None:
    """同一个 ProjectScanner 实例重复扫描时不应累计旧状态或回写旧结果。"""
    file_path = tmp_path / "app.py"
    file_path.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    scanner = ProjectScanner(str(tmp_path), use_cache=False, use_parallel=False)

    first_results = scanner.scan_project()
    first_stats = scanner.get_stats()

    assert first_results == {}
    assert first_stats["scanned_files"] == 1
    assert first_stats["files_with_issues"] == 0
    assert first_stats["total_issues"] == 0

    file_path.write_text('password = "secret123"\n', encoding="utf-8")

    second_results = scanner.scan_project()
    second_stats = scanner.get_stats()

    assert first_results == {}
    assert list(second_results) == ["app.py"]
    assert second_stats["scanned_files"] == 1
    assert second_stats["files_with_issues"] == 1
    assert second_stats["total_issues"] == 1


def test_project_scanner_rejects_removed_legacy_engine(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="legacy scan engine has been removed"):
        ProjectScanner(str(tmp_path), engine="legacy")


def test_scan_project_reports_partial_scan_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Analyzer failures must be visible in scan stats, not reported as a clean scan."""
    file_path = tmp_path / "app.py"
    file_path.write_text("print('ok')\n", encoding="utf-8")

    def fail_analyzer(*args, **kwargs):
        raise RuntimeError("parser unavailable")

    monkeypatch.setattr("src.scanner.project_scanner.analyze_source", fail_analyzer)

    scanner = ProjectScanner(str(tmp_path), use_cache=False, use_parallel=False)
    results = scanner.scan_project()
    stats = scanner.get_stats()

    assert results == {}
    assert stats["scanned_files"] == 1
    assert stats["total_issues"] == 0
    assert stats["partial"] is True
    assert stats["error_count"] == 1
    assert stats["errors"] == [
        {
            "file": "app.py",
            "phase": "scan",
            "message": "parser unavailable",
        }
    ]


def test_parallel_scan_reports_each_worker_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Parallel worker failures must all be retained in the scan summary."""
    for name in ("first.py", "second.py"):
        (tmp_path / name).write_text("print('ok')\n", encoding="utf-8")

    def fail_analyzer(*args, **kwargs):
        raise RuntimeError("parser unavailable")

    monkeypatch.setattr("src.scanner.project_scanner.analyze_source", fail_analyzer)

    scanner = ProjectScanner(
        str(tmp_path),
        use_cache=False,
        use_parallel=True,
        max_workers=2,
    )
    results = scanner.scan_project()
    stats = scanner.get_stats()

    assert results == {}
    assert stats["scanned_files"] == 2
    assert stats["partial"] is True
    assert stats["error_count"] == 2
    assert sorted(error["file"] for error in stats["errors"]) == ["first.py", "second.py"]


def test_project_scan_loads_dsl_definitions_once_for_all_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for index in range(3):
        (tmp_path / f"app_{index}.py").write_text("print('ok')\n", encoding="utf-8")

    load_calls = 0

    def counted_loader(*args, **kwargs):
        nonlocal load_calls
        load_calls += 1
        return load_dsl_rule_definitions(*args, **kwargs)

    monkeypatch.setattr("src.scanner.project_scanner.load_dsl_rule_definitions", counted_loader)

    scanner = ProjectScanner(str(tmp_path), use_cache=False, use_parallel=True, max_workers=2)
    scanner.scan_project()

    assert load_calls == 1
    assert scanner._dsl_rule_definitions is None


def test_scan_session_releases_transient_state_but_keeps_persistent_cache(tmp_path: Path) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text("print('ok')\n", encoding="utf-8")
    scanner = ProjectScanner(str(tmp_path), use_cache=True, use_parallel=False)
    assert scanner.optimizer is not None
    assert scanner.optimizer.cache is not None
    persistent_cache = scanner.optimizer.cache
    persistent_cache.save_result(source_file, [{"type": "TEST"}], rules_version_hash="rules-v1")

    with pytest.raises(RuntimeError, match="stop scan"):
        with scanner.scan_session():
            assert scanner._dsl_rule_definitions is not None
            scanner._source_snapshot[source_file.resolve()] = "print('ok')\n"
            raise RuntimeError("stop scan")

    assert scanner._source_snapshot == {}
    assert scanner._dsl_rule_definitions is None
    assert scanner.optimizer.cache is persistent_cache
    assert persistent_cache.get_cached_result(source_file, rules_version_hash="rules-v1") == [{"type": "TEST"}]
    assert scanner.get_stats()["scan_time"] is not None


def test_project_scan_cleans_session_when_cross_file_analysis_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text("print('ok')\n", encoding="utf-8")
    scanner = ProjectScanner(
        str(tmp_path),
        use_cache=False,
        use_parallel=False,
        use_cross_file=True,
    )

    def fail_cross_file(*args, **kwargs):
        scanner._source_snapshot[source_file.resolve()] = "temporary"
        raise RuntimeError("cross-file failed")

    monkeypatch.setattr(scanner, "_merge_cross_file_findings", fail_cross_file)

    with pytest.raises(RuntimeError, match="cross-file failed"):
        scanner.scan_project()

    assert scanner._source_snapshot == {}
    assert scanner._dsl_rule_definitions is None
