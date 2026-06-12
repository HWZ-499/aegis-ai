"""
incremental_analyzer.py — O5 函数级增量分析

核心思路：保留每个文件的 AST 和函数级分析结果，
当文件变更时只重新分析发生变化的函数，合并其余缓存结果。
利用 tree-sitter 的增量解析加速 AST 重建。
"""

from __future__ import annotations

import hashlib
import logging
from copy import deepcopy
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
    start_column: int = 0
    node_type: str = ""


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

        # Deleted functions can shift all following line numbers and remove cached
        # findings. Fall back to a full scan instead of trying to repair cache state.
        for name in old_funcs:
            if name not in new_functions:
                return [], True

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

    def build_partial_source(
        self,
        file_path: str,
        code: str,
        language: str,
        changed_funcs: list[str],
    ) -> str | None:
        """
        Build a sparse source file containing only changed top-level functions.

        The returned source keeps the original line count by replacing unrelated
        lines with blanks, so findings emitted by the normal analyzer keep their
        original line numbers. Top-level import/require lines are preserved to
        keep common alias-based rules working.
        """
        if language not in {"python", "javascript", "typescript"}:
            return None
        if not changed_funcs:
            return None

        cached = self._cache.get(file_path)
        if cached is None:
            return None
        if cached.findings_by_func.get("__global__"):
            return None

        parser = self._get_parser(language)
        if parser is None:
            return None
        functions = self._extract_functions(code, language, parser)
        if functions is None:
            return None

        lines = code.splitlines()
        selected: list[FunctionInfo] = []
        for name in changed_funcs:
            info = functions.get(name)
            if info is None or not self._can_slice_function(info, language, lines):
                return None
            selected.append(info)

        sparse_lines = ["" for _ in lines]
        for idx, line in enumerate(lines):
            if self._is_context_line(line, language):
                sparse_lines[idx] = line

        for info in selected:
            start = max(info.start_line - 1, 0)
            end = min(info.end_line, len(lines))
            for idx in range(start, end):
                sparse_lines[idx] = lines[idx]

        return "\n".join(sparse_lines)

    def filter_findings_for_functions(
        self,
        file_path: str,
        code: str,
        language: str,
        function_names: list[str],
        findings: list[dict],
    ) -> list[dict]:
        """Keep only findings that fall inside the requested functions."""
        parser = self._get_parser(language)
        if parser is None:
            return findings
        functions = self._extract_functions(code, language, parser)
        if functions is None:
            return findings

        ranges: list[tuple[int, int]] = []
        for name in function_names:
            info = functions.get(name)
            if info is not None:
                ranges.append((info.start_line, info.end_line))

        if not ranges:
            return []

        filtered: list[dict] = []
        for finding in findings:
            line = int(finding.get("line", 0) or 0)
            if any(start <= line <= end for start, end in ranges):
                filtered.append(finding)
        return filtered

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

    def merge_partial_findings(
        self,
        file_path: str,
        changed_funcs: list[str],
        new_findings: list[dict],
        code: str | None = None,
        language: str | None = None,
    ) -> list[dict]:
        """
        Merge new partial findings (for changed functions) with cached findings
        for unchanged functions.

        Args:
            file_path: File path
            changed_funcs: Names of functions that were re-analyzed
            new_findings: Fresh findings from re-analyzing only changed functions
            code: Current full source, used to remap cached finding line numbers
            language: Language key for parsing current full source

        Returns:
            Complete finding list for the file.
        """
        cached = self._cache.get(file_path)
        if cached is None:
            return new_findings

        result: list[dict] = []
        changed_set = set(changed_funcs)
        new_functions: dict[str, FunctionInfo] | None = None
        if code is not None and language is not None:
            parser = self._get_parser(language)
            if parser is not None:
                new_functions = self._extract_functions(code, language, parser)

        # Keep cached findings for unchanged functions
        for fname, func_findings in cached.findings_by_func.items():
            if fname not in changed_set:
                delta = 0
                if fname != "__global__" and new_functions is not None:
                    old_info = cached.functions.get(fname)
                    new_info = new_functions.get(fname)
                    if old_info is None or new_info is None:
                        continue
                    delta = new_info.start_line - old_info.start_line
                result.extend(self._shift_finding_lines(f, delta) for f in func_findings)

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
                    start_column=node.start_point[1],
                    node_type=node.type,
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

    @staticmethod
    def _can_slice_function(info: FunctionInfo, language: str, lines: list[str]) -> bool:
        """Return whether a function can be scanned as a standalone sparse slice."""
        if not (1 <= info.start_line <= len(lines)):
            return False

        start_text = lines[info.start_line - 1].lstrip()
        if language == "python":
            return info.node_type == "function_definition" and info.start_column == 0

        if language in {"javascript", "typescript"}:
            if info.node_type == "method_definition":
                return False
            return start_text.startswith(
                (
                    "function ",
                    "async function ",
                    "export function ",
                    "export async function ",
                    "const ",
                    "let ",
                    "var ",
                    "export const ",
                    "export let ",
                    "export var ",
                )
            )

        return False

    @staticmethod
    def _is_context_line(line: str, language: str) -> bool:
        """Keep lightweight context lines needed by alias/import-based rules."""
        stripped = line.strip()
        if language == "python":
            return stripped.startswith(("import ", "from "))
        if language in {"javascript", "typescript"}:
            return stripped.startswith("import ") or "require(" in stripped
        return False

    @classmethod
    def _shift_finding_lines(cls, finding: dict, delta: int) -> dict:
        """Return a copy of a finding with line-based fields shifted."""
        shifted = deepcopy(finding)
        if delta == 0:
            return shifted

        for key in ("line", "start_line", "end_line", "taint_source_line"):
            value = shifted.get(key)
            if isinstance(value, int) and value > 0:
                shifted[key] = value + delta

        related_locations = shifted.get("related_locations")
        if isinstance(related_locations, list):
            for location in related_locations:
                if not isinstance(location, dict):
                    continue
                for key in ("start_line", "end_line", "line"):
                    value = location.get(key)
                    if isinstance(value, int) and value > 0:
                        location[key] = value + delta

        return shifted
