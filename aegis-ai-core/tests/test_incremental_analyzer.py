from src.analysis.incremental_analyzer import IncrementalAnalyzer


def test_source_change_outside_functions_requires_full_rescan() -> None:
    """函数外部改动会影响全局 findings 和行号，不能直接复用缓存。"""
    analyzer = IncrementalAnalyzer()
    file_path = "demo.js"
    original = "function foo() {\n  return 1;\n}\nconst password = 'secret';\n"
    updated = "// inserted comment\nfunction foo() {\n  return 1;\n}\nconst password = 'secret';\n"

    analyzer.update_cache(
        file_path,
        original,
        "javascript",
        [{"type": "HARDCODED_CREDENTIALS", "line": 4}],
    )

    changed, full_rescan = analyzer.get_changed_functions(file_path, updated, "javascript")
    assert changed == []
    assert full_rescan is True
