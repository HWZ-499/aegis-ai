"""Compatibility adapter for the canonical multi-language analysis entry.

Historically this module maintained a second set of parsers and regex rules.
Since Aegis 1.5 it delegates to :func:`src.analysis.rule_engine.analyze_source`
so CLI, LSP, project scans, and compatibility callers share one rule path.
New code should import ``analyze_source`` directly.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, cast

from src.analysis.languages import EXTENSION_LANGUAGE_MAP, normalize_analysis_language
from src.analysis.rule_engine import analyze_source

_analyzer_local = threading.local()

_LEGACY_EXTENSION_NAMES = {
    ".rb": "ruby",
    ".rs": "rust",
    ".swift": "swift",
    ".kt": "kotlin",
}

_DEFAULT_FILENAMES = {
    "python": "source.py",
    "javascript": "source.js",
    "typescript": "source.ts",
    "php": "source.php",
    "java": "Source.java",
    "go": "source.go",
    "c": "source.c",
    "cpp": "source.cpp",
}


class MultiLanguageASTAnalyzer:
    """Source-compatible adapter backed by the maintained rule engine."""

    def detect_language(self, file_path: str, code_content: str) -> str:
        """Return the language inferred from a path, with legacy name hints."""
        suffix = Path(file_path).suffix.lower()
        supported = EXTENSION_LANGUAGE_MAP.get(suffix)
        if supported is not None:
            return supported
        legacy_name = _LEGACY_EXTENSION_NAMES.get(suffix)
        if legacy_name is not None:
            return legacy_name

        lowered = code_content.lower()
        if "<?php" in lowered:
            return "php"
        if "public class" in code_content or "import java" in code_content:
            return "java"
        if "package main" in code_content or "func " in code_content:
            return "go"
        if "#include" in code_content:
            return "c"
        if "function" in code_content and ("var " in code_content or "const " in code_content):
            return "javascript"
        return "unknown"

    def analyze(
        self,
        code_content: str,
        language: str | None = None,
        file_path: str | None = None,
    ) -> list[dict[str, Any]]:
        """Analyze source through the same dispatch path used in production."""
        requested = language
        if requested is None and file_path is not None:
            requested = self.detect_language(file_path, code_content)
        if requested is None:
            requested = "python"

        normalized = normalize_analysis_language(requested, file_path)
        if normalized is None:
            return []

        resolved_path = file_path or _DEFAULT_FILENAMES[normalized]
        findings = analyze_source(code_content, resolved_path, language=normalized)
        return cast(list[dict[str, Any]], findings)


def analyze_code_multi_language(
    code_content: str,
    file_path: str | None = None,
) -> list[dict[str, Any]]:
    """Compatibility helper; prefer ``rule_engine.analyze_source`` in new code."""
    analyzer = getattr(_analyzer_local, "analyzer", None)
    if analyzer is None:
        analyzer = MultiLanguageASTAnalyzer()
        _analyzer_local.analyzer = analyzer
    return cast(MultiLanguageASTAnalyzer, analyzer).analyze(code_content, file_path=file_path)


__all__ = ["MultiLanguageASTAnalyzer", "analyze_code_multi_language"]
