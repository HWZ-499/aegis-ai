import logging

import pytest

import src.analysis.incremental_analyzer as incremental_module
from src.analysis.incremental_analyzer import IncrementalAnalyzer


def test_changed_function_partial_source_preserves_line_numbers_and_import_context() -> None:
    """变更函数切片应保留原始行号，并保留 import 上下文供别名规则使用。"""
    analyzer = IncrementalAnalyzer()
    file_path = "service.py"
    original = "\n".join(
        [
            "import os",
            "",
            "def safe():",
            "    return 'ok'",
            "",
            "def run(cmd):",
            "    return cmd",
        ]
    )
    updated = "\n".join(
        [
            "import os",
            "",
            "def safe():",
            "    return 'ok'",
            "",
            "def run(cmd):",
            "    os.system(cmd)",
        ]
    )

    analyzer.update_cache(
        file_path,
        original,
        "python",
        [{"type": "HARDCODED_CREDENTIALS", "line": 4}],
    )

    changed, full_rescan = analyzer.get_changed_functions(file_path, updated, "python")
    assert changed == ["run"]
    assert full_rescan is False

    partial = analyzer.build_partial_source(file_path, updated, "python", changed)
    assert partial is not None
    partial_lines = partial.splitlines()

    assert len(partial_lines) == len(updated.splitlines())
    assert partial_lines[0] == "import os"
    assert partial_lines[2] == ""
    assert partial_lines[5] == "def run(cmd):"
    assert partial_lines[6] == "    os.system(cmd)"


def test_merge_partial_findings_shifts_cached_lines_for_unchanged_functions() -> None:
    """变更函数增删行后，未变函数的缓存 finding 行号必须跟随新位置。"""
    analyzer = IncrementalAnalyzer()
    file_path = "service.py"
    original = "\n".join(
        [
            "def changed():",
            "    return 1",
            "",
            "def later(cmd):",
            "    os.system(cmd)",
        ]
    )
    updated = "\n".join(
        [
            "def changed():",
            "    value = 1",
            "    return value",
            "",
            "def later(cmd):",
            "    os.system(cmd)",
        ]
    )

    analyzer.update_cache(
        file_path,
        original,
        "python",
        [
            {
                "type": "RCE_COMMAND_EXEC",
                "line": 5,
                "start_line": 5,
                "end_line": 5,
                "related_locations": [{"start_line": 5, "end_line": 5}],
            }
        ],
    )

    changed, full_rescan = analyzer.get_changed_functions(file_path, updated, "python")
    assert changed == ["changed"]
    assert full_rescan is False

    merged = analyzer.merge_partial_findings(file_path, changed, [], code=updated, language="python")

    assert merged == [
        {
            "type": "RCE_COMMAND_EXEC",
            "line": 6,
            "start_line": 6,
            "end_line": 6,
            "related_locations": [{"start_line": 6, "end_line": 6}],
        }
    ]


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


def test_incremental_parser_initialization_degradation_is_logged(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    class FailingParser:
        def __init__(self) -> None:
            raise RuntimeError("incremental parser failed")

    monkeypatch.setattr(incremental_module, "TREE_SITTER_AVAILABLE", True)
    monkeypatch.setattr(incremental_module, "Parser", FailingParser)
    analyzer = IncrementalAnalyzer()

    with caplog.at_level(logging.DEBUG, logger="src.analysis.incremental_analyzer"):
        parser = analyzer._get_parser("python")

    assert parser is None
    assert "incremental_analysis_degraded language=python stage=parser_init" in caplog.text


def test_incremental_parse_degradation_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    class FailingParser:
        def parse(self, code: bytes) -> object:
            raise RuntimeError("incremental parse failed")

    analyzer = IncrementalAnalyzer()

    with caplog.at_level(logging.DEBUG, logger="src.analysis.incremental_analyzer"):
        functions = analyzer._extract_functions("def f(): pass", "python", FailingParser())

    assert functions is None
    assert "incremental_analysis_degraded language=python stage=parse" in caplog.text
