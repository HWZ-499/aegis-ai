"""Shared language identifiers, aliases, and file-extension detection."""

from __future__ import annotations

from pathlib import Path
from typing import Literal, TypeAlias, cast

AnalysisLanguage: TypeAlias = Literal[
    "python",
    "javascript",
    "typescript",
    "php",
    "java",
    "go",
    "c",
    "cpp",
]

FULL_SUPPORT_EXTENSION_LANGUAGE_MAP: dict[str, AnalysisLanguage] = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".php": "php",
    ".phtml": "php",
    ".php5": "php",
    ".java": "java",
    ".go": "go",
}

PARTIAL_SUPPORT_EXTENSION_LANGUAGE_MAP: dict[str, AnalysisLanguage] = {
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".hxx": "cpp",
}

EXTENSION_LANGUAGE_MAP: dict[str, AnalysisLanguage] = {
    **FULL_SUPPORT_EXTENSION_LANGUAGE_MAP,
    **PARTIAL_SUPPORT_EXTENSION_LANGUAGE_MAP,
}

LANGUAGE_ALIASES: dict[str, AnalysisLanguage] = {
    "py": "python",
    "python": "python",
    "js": "javascript",
    "jsx": "javascript",
    "javascript": "javascript",
    "ts": "typescript",
    "tsx": "typescript",
    "typescript": "typescript",
    "php": "php",
    "java": "java",
    "go": "go",
    "golang": "go",
    "c": "c",
    "cc": "cpp",
    "c++": "cpp",
    "cpp": "cpp",
    "cxx": "cpp",
}

SUPPORTED_ANALYSIS_LANGUAGES = frozenset(LANGUAGE_ALIASES.values())


def normalize_analysis_language(
    language: str | None = None,
    file_path: Path | str | None = None,
) -> AnalysisLanguage | None:
    """Normalize a language alias, falling back to the file extension."""
    raw = (language or "").strip().lower()
    normalized = LANGUAGE_ALIASES.get(raw)
    if normalized is not None:
        return normalized
    if file_path is None:
        return None
    suffix = Path(file_path).suffix.lower()
    detected = EXTENSION_LANGUAGE_MAP.get(suffix)
    return cast(AnalysisLanguage | None, detected)


__all__ = [
    "AnalysisLanguage",
    "EXTENSION_LANGUAGE_MAP",
    "FULL_SUPPORT_EXTENSION_LANGUAGE_MAP",
    "LANGUAGE_ALIASES",
    "PARTIAL_SUPPORT_EXTENSION_LANGUAGE_MAP",
    "SUPPORTED_ANALYSIS_LANGUAGES",
    "normalize_analysis_language",
]
