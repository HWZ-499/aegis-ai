"""
dependency_tracker.py — O5 跨文件依赖追踪

当文件 A 的导出函数签名变化时，自动识别哪些其他文件导入了 A，
返回需要重新扫描的受影响文件集合。
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Import patterns by language
_JS_IMPORT_RE = re.compile(
    r"""(?:import\s+.*?\s+from\s+['"](.+?)['"]|require\s*\(\s*['"](.+?)['"]\s*\))"""
)
_PY_IMPORT_RE = re.compile(
    r"""(?:from\s+(\S+)\s+import|import\s+(\S+))"""
)


class DependencyTracker:
    """
    Tracks import relationships between files to determine
    which files need rescanning when an export signature changes.
    """

    def __init__(self) -> None:
        # file_path → set of resolved imported file paths
        self._import_graph: dict[str, set[str]] = {}
        # file_path → hash of exported function signatures
        self._export_hashes: dict[str, str] = {}

    def update_imports(
        self, file_path: str, code: str, language: str, project_root: str
    ) -> None:
        """
        Parse and record the import relationships for a file.

        Args:
            file_path: Absolute file path
            code: Source code content
            language: Language key
            project_root: Project root for resolving relative imports
        """
        imports: set[str] = set()

        if language in ("javascript", "typescript"):
            for m in _JS_IMPORT_RE.finditer(code):
                raw = m.group(1) or m.group(2) or ""
                resolved = self._resolve_js_import(raw, file_path, project_root)
                if resolved:
                    imports.add(resolved)
        elif language == "python":
            for m in _PY_IMPORT_RE.finditer(code):
                raw = m.group(1) or m.group(2) or ""
                resolved = self._resolve_py_import(raw, file_path, project_root)
                if resolved:
                    imports.add(resolved)

        self._import_graph[file_path] = imports

    def update_export_hash(self, file_path: str, code: str) -> bool:
        """
        Compute a hash of the file's "exported interface" (first 200 lines
        of function/class signatures) and return True if it changed.

        This is a lightweight heuristic — not a full symbol table.
        """
        # Extract function/class/export lines as a proxy for "public API"
        sig_lines: list[str] = []
        for line in code.splitlines()[:200]:
            stripped = line.strip()
            if any(
                stripped.startswith(kw)
                for kw in (
                    "export ",
                    "module.exports",
                    "def ",
                    "class ",
                    "function ",
                    "public ",
                    "func ",
                )
            ):
                sig_lines.append(stripped)

        new_hash = hashlib.md5("\n".join(sig_lines).encode()).hexdigest()
        old_hash = self._export_hashes.get(file_path, "")
        self._export_hashes[file_path] = new_hash
        return new_hash != old_hash

    def get_affected_files(self, changed_file: str) -> set[str]:
        """
        Return the set of files that need rescanning because they import
        the changed file (whose export signature changed).

        Always includes the changed file itself.
        """
        affected: set[str] = {changed_file}

        for file_path, imports in self._import_graph.items():
            if changed_file in imports:
                affected.add(file_path)

        return affected

    def invalidate(self, file_path: str) -> None:
        """Remove a file from tracking."""
        self._import_graph.pop(file_path, None)
        self._export_hashes.pop(file_path, None)

    # ── Private resolution helpers ────────────────────────────────────────

    @staticmethod
    def _resolve_js_import(
        raw_path: str, importer: str, project_root: str
    ) -> str | None:
        """Resolve a JS/TS import specifier to an absolute path (best-effort)."""
        if not raw_path.startswith("."):
            return None  # Skip bare specifiers (npm packages)

        base_dir = str(Path(importer).parent)
        candidate = Path(base_dir) / raw_path

        for ext in ("", ".js", ".ts", ".jsx", ".tsx", "/index.js", "/index.ts"):
            p = candidate.parent / (candidate.name + ext) if ext else candidate
            if p.exists():
                return str(p.resolve())

        return None

    @staticmethod
    def _resolve_py_import(
        raw_module: str, importer: str, project_root: str
    ) -> str | None:
        """Resolve a Python import to an absolute file path (best-effort)."""
        parts = raw_module.split(".")
        base = Path(project_root)

        # Try as relative path from project root
        candidate = base / "/".join(parts)
        for suffix in (".py", "/__init__.py"):
            p = Path(str(candidate) + suffix)
            if p.exists():
                return str(p.resolve())

        return None
