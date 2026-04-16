"""
incremental_analyzer.py — O5 函数级增量分析

核心思路：保留每个文件的 AST 和函数级分析结果，
当文件变更时只重新分析发生变化的函数，合并其余缓存结果。
利用 tree-sitter 的增量解析加速 AST 重建。
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any, cast

logger = logging.getLogger(__name__)

try:
    from tree_sitter import Parser
    from tree_sitter_languages import get_language

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Parser = None  # type: ignore[misc,assignment]
    get_language = None  # type: ignore[misc,assignment]

# tree-sitter language name mapping
_TS_LANG_MAP: dict[str, str] = {
    "javascript": "javascript",
    "typescript": "typescript",
    "python": "python",
    "php": "php",
    "java": "java",
    "go": "go",
}

# Function declaration node types per language
_FUNC_NODE_TYPES: dict[str, set[str]] = {
    "javascript": {
        "function_declaration",
        "arrow_function",
        "method_definition",
        "function_expression",
    },
    "typescript": {
        "function_declaration",
        "arrow_function",
        "method_definition",
        "function_expression",
    },
    "python": {"function_definition"},
    "php": {"function_definition", "method_declaration"},
    "java": {"method_declaration", "constructor_declaration"},
    "go": {"function_declaration", "method_declaration"},
}


@dataclass
class FunctionInfo:
    """Represents a parsed function with its hash for change detection."""

    name: str
    start_line: int
    end_line: int
    content_hash: str
    node_start_byte: int = 0
    node_end_byte: int = 0


@dataclass
class FileAnalysisCache:
    """Cache entry for a single file."""

    source_hash: str = ""
    functions: dict[str, FunctionInfo] = field(default_factory=dict)
    # Findings keyed by function name; "__global__" for top-level code
    findings_by_func: dict[str, list[dict]] = field(default_factory=dict)
    tree_bytes: bytes | None = None  # serialized tree for incremental parse


class IncrementalAnalyzer:
    """
    函数级增量分析器。

    当文件变更时，仅重新分析发生变化的函数，并合并缓存结果。
    """

    def __init__(self) -> None:
        self._cache: dict[str, FileAnalysisCache] = {}  # file_path -> cache
        self._parsers: dict[str, Any] = {}

    def _get_parser(self, language: str) -> Any:
        """Get or create a tree-sitter parser for the given language."""
        if not TREE_SITTER_AVAILABLE:
            return None
        if language not in self._parsers:
            ts_lang = _TS_LANG_MAP.get(language)
            if not ts_lang or get_language is None:
                return None
            try:
                parser = Parser()
                parser.set_language(get_language(ts_lang))
                self._parsers[language] = parser
            except (RuntimeError, ValueError, OSError):
                return None
        return self._parsers.get(language)

    def get_changed_functions(self, file_path: str, code: str, language: str) -> tuple[list[str], bool]:
        """
        Determine which functions changed since last analysis.

        Returns:
            (changed_function_names, full_rescan_needed)
            If full_rescan_needed is True, caller should do a full scan.
        """
        source_hash = hashlib.md5(code.encode()).hexdigest()
        cached = self._cache.get(file_path)

        # No cache — full rescan
        if cached is None or cached.source_hash == "":
            return [], True

        # Unchanged
        if cached.source_hash == source_hash:
            return [], False

        parser = self._get_parser(language)
        if parser is None:
            return [], True

        new_functions = self._extract_functions(code, language, parser)
        if new_functions is None:
            return [], True

        changed: list[str] = []
        old_funcs = cached.functions

        # Detect changed & new functions
        for name, info in new_functions.items():
            old = old_funcs.get(name)
            if old is None or old.content_hash != info.content_hash:
                changed.append(name)

        # Detect deleted functions (findings for them must be removed)
        for name in old_funcs:
            if name not in new_functions:
                changed.append(name)

        # 源码变了但函数体哈希没变，通常意味着修改发生在函数外部：
        # 例如顶部新增注释、全局常量/敏感信息位置移动、函数之间插入注释等。
        # 这类变更会影响全局 findings 和行号，因此不能直接复用缓存结果。
        if not changed:
            return [], True

        # If more than 60% of functions changed, full rescan is more efficient
        total = max(len(new_functions), len(old_funcs), 1)
        if len(changed) / total > 0.6:
            return [], True

        return changed, False

    def update_cache(
        self,
        file_path: str,
        code: str,
        language: str,
        findings: list[dict],
    ) -> None:
        """
        Update the cache after a full or partial analysis.

        Args:
            file_path: File path
            code: Current source code
            language: Language key
            findings: All findings for this file (will be bucketed by function)
        """
        source_hash = hashlib.md5(code.encode()).hexdigest()
        parser = self._get_parser(language)

        functions: dict[str, FunctionInfo] = {}
        if parser is not None:
            extracted = self._extract_functions(code, language, parser)
            if extracted is not None:
                functions = extracted

        # Bucket findings by function
        findings_by_func: dict[str, list[dict]] = {"__global__": []}
        for f in findings:
            line = f.get("line", 0)
            placed = False
            for fname, finfo in functions.items():
                if finfo.start_line <= line <= finfo.end_line:
                    findings_by_func.setdefault(fname, []).append(f)
                    placed = True
                    break
            if not placed:
                findings_by_func["__global__"].append(f)

        self._cache[file_path] = FileAnalysisCache(
            source_hash=source_hash,
            functions=functions,
            findings_by_func=findings_by_func,
        )

    def get_cached_findings(self, file_path: str) -> list[dict] | None:
        """Return cached findings for a file, or None if not cached."""
        cached = self._cache.get(file_path)
        if cached is None or cached.source_hash == "":
            return None
        all_findings: list[dict] = []
        for func_findings in cached.findings_by_func.values():
            all_findings.extend(func_findings)
        return all_findings

    def merge_partial_findings(self, file_path: str, changed_funcs: list[str], new_findings: list[dict]) -> list[dict]:
        """
        Merge new partial findings (for changed functions) with cached findings
        for unchanged functions.

        Args:
            file_path: File path
            changed_funcs: Names of functions that were re-analyzed
            new_findings: Fresh findings from re-analyzing only changed functions

        Returns:
            Complete finding list for the file.
        """
        cached = self._cache.get(file_path)
        if cached is None:
            return new_findings

        result: list[dict] = []
        changed_set = set(changed_funcs)

        # Keep cached findings for unchanged functions
        for fname, func_findings in cached.findings_by_func.items():
            if fname not in changed_set:
                result.extend(func_findings)

        # Add new findings for changed functions
        result.extend(new_findings)
        return result

    def invalidate(self, file_path: str) -> None:
        """Remove cache for a specific file."""
        self._cache.pop(file_path, None)

    def invalidate_all(self) -> None:
        """Clear entire cache."""
        self._cache.clear()

    def _extract_functions(self, code: str, language: str, parser: Any) -> dict[str, FunctionInfo] | None:
        """Extract function info from source code using tree-sitter."""
        try:
            tree = parser.parse(code.encode())
        except (RuntimeError, ValueError):
            return None

        func_types = _FUNC_NODE_TYPES.get(language, set())
        if not func_types:
            return None

        functions: dict[str, FunctionInfo] = {}
        self._walk_functions(tree.root_node, func_types, code, functions)
        return functions

    def _walk_functions(
        self,
        node: Any,
        func_types: set[str],
        code: str,
        result: dict[str, FunctionInfo],
    ) -> None:
        """Recursively walk AST to find function nodes."""
        if node.type in func_types:
            name = self._get_function_name(node)
            if name:
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                content = code[node.start_byte : node.end_byte]
                content_hash = hashlib.md5(content.encode()).hexdigest()
                result[name] = FunctionInfo(
                    name=name,
                    start_line=start_line,
                    end_line=end_line,
                    content_hash=content_hash,
                    node_start_byte=node.start_byte,
                    node_end_byte=node.end_byte,
                )

        for child in node.children:
            self._walk_functions(child, func_types, code, result)

    @staticmethod
    def _get_function_name(node: Any) -> str:
        """Extract function name from a function AST node."""
        # Try 'name' child first (Python, JS function_declaration, etc.)
        for child in node.children:
            if child.type in ("identifier", "property_identifier"):
                return cast(bytes, child.text).decode()

        # Arrow functions assigned to variables: const foo = () => {}
        parent = node.parent
        if parent and parent.type in (
            "variable_declarator",
            "assignment_expression",
            "pair",
        ):
            for child in parent.children:
                if child.type in ("identifier", "property_identifier"):
                    return cast(bytes, child.text).decode()

        return ""
