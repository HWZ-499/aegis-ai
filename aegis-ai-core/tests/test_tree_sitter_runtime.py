import logging
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

import src.analysis.tree_sitter_runtime as runtime
from src.analysis.tree_sitter_runtime import (
    TREE_SITTER_RUNTIME_AVAILABLE,
    get_cached_language,
    get_thread_parser,
)


@pytest.mark.skipif(not TREE_SITTER_RUNTIME_AVAILABLE, reason="tree-sitter runtime unavailable")
def test_tree_sitter_runtime_reuses_language_and_parser_in_same_thread() -> None:
    assert get_cached_language("python") is get_cached_language("python")
    assert get_thread_parser("python") is get_thread_parser("python")


@pytest.mark.skipif(not TREE_SITTER_RUNTIME_AVAILABLE, reason="tree-sitter runtime unavailable")
def test_tree_sitter_runtime_keeps_parsers_isolated_between_threads() -> None:
    rendezvous = Barrier(2, timeout=5)

    def get_parser() -> object:
        parser = get_thread_parser("javascript")
        rendezvous.wait()
        return parser

    with ThreadPoolExecutor(max_workers=2) as executor:
        parsers = list(executor.map(lambda _index: get_parser(), range(2)))

    assert parsers[0] is not parsers[1]


def test_tree_sitter_runtime_logs_parser_initialization_degradation(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    class FailingParser:
        def __init__(self) -> None:
            raise RuntimeError("parser init failed")

    monkeypatch.setattr(runtime, "TREE_SITTER_RUNTIME_AVAILABLE", True)
    monkeypatch.setattr(runtime, "Parser", FailingParser)
    runtime._parser_local.parsers = {}

    with caplog.at_level(logging.DEBUG, logger="src.analysis.tree_sitter_runtime"):
        parser = runtime.get_thread_parser("python")

    assert parser is None
    assert "parser_runtime_degraded language=python stage=initialize" in caplog.text
    assert "error=RuntimeError: parser init failed" in caplog.text
