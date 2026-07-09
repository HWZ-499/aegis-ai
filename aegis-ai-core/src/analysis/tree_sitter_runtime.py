"""Thread-local Tree-sitter runtime helpers.

Language objects are immutable and shared process-wide. Parser instances are
reused only within the current thread because Parser is not documented as
safe for concurrent use.
"""

from __future__ import annotations

import logging
import threading
from functools import lru_cache
from typing import Any

try:
    from tree_sitter import Parser
    from tree_sitter_languages import get_language

    TREE_SITTER_RUNTIME_AVAILABLE = True
except ImportError:
    Parser = None  # type: ignore[misc,assignment]
    get_language = None  # type: ignore[assignment]
    TREE_SITTER_RUNTIME_AVAILABLE = False

_parser_local = threading.local()
logger = logging.getLogger(__name__)


@lru_cache(maxsize=16)
def get_cached_language(language: str) -> Any:
    """Return one immutable Tree-sitter Language object per language name."""
    if not TREE_SITTER_RUNTIME_AVAILABLE or get_language is None:
        return None
    return get_language(language)


def get_thread_parser(language: str) -> Any:
    """Return a parser cached for the current thread and language."""
    if not TREE_SITTER_RUNTIME_AVAILABLE or Parser is None:
        return None

    parsers = getattr(_parser_local, "parsers", None)
    if parsers is None:
        parsers = {}
        _parser_local.parsers = parsers

    parser = parsers.get(language)
    if parser is not None:
        return parser

    try:
        parser = Parser()
        parser.set_language(get_cached_language(language))
    except (RuntimeError, ValueError, OSError) as error:
        logger.debug(
            "parser_runtime_degraded language=%s stage=initialize error=%s: %s",
            language,
            type(error).__name__,
            error,
        )
        return None
    parsers[language] = parser
    return parser


__all__ = [
    "TREE_SITTER_RUNTIME_AVAILABLE",
    "get_cached_language",
    "get_thread_parser",
]
