"""
dependency_tracker.py — O5 跨文件依赖追踪

当文件 A 的导出函数签名变化时，自动识别哪些其他文件导入了 A，
返回需要重新扫描的受影响文件集合。
"""

from __future__ import annotations

import ast
import hashlib
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Import patterns by language
_JS_IMPORT_RE = re.compile(r"""(?:import\s+.*?\s+from\s+['"](.+?)['"]|require\s*\(\s*['"](.+?)['"]\s*\))""")
_PY_IMPORT_RE = re.compile(r"""(?:from\s+(\S+)\s+import|import\s+(\S+))""")
_PY_FROM_IMPORT_RE = re.compile(r"""^\s*from\s+(\S+)\s+import\s+([^\n#]+)""", re.MULTILINE)
_PY_DIRECT_IMPORT_RE = re.compile(r"""^\s*import\s+([^\n#]+)""", re.MULTILINE)


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

    def update_imports(self, file_path: str, code: str, language: str, project_root: str) -> None:
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
            imports.update(self._extract_py_imports(code, file_path, project_root))

        self._import_graph[file_path] = imports

    def update_export_hash(self, file_path: str, code: str) -> bool:
        """
        Compute a hash of the file's "exported interface" from function/class
        signatures and return True if it changed.

        This is a lightweight heuristic — not a full symbol table.
        """
        # Extract function/class/export lines as a proxy for "public API"
        sig_lines: list[str] = []
        for line in code.splitlines():
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

    def has_export_hash(self, file_path: str) -> bool:
        """Return whether this file already has a recorded export signature."""
        return file_path in self._export_hashes

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
    def _resolve_js_import(raw_path: str, importer: str, project_root: str) -> str | None:
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
    def _resolve_py_import(raw_module: str, importer: str, project_root: str) -> str | None:
        """Resolve a Python import to an absolute file path (best-effort)."""
        level = len(raw_module) - len(raw_module.lstrip("."))
        return DependencyTracker._resolve_py_module(raw_module[level:], importer, project_root, level=level)

    @classmethod
    def _extract_py_imports(cls, code: str, importer: str, project_root: str) -> set[str]:
        """Extract Python imports with AST parsing, falling back to regex for incomplete code."""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return cls._extract_py_imports_with_regex(code, importer, project_root)

        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    resolved = cls._resolve_py_module(alias.name, importer, project_root, level=0)
                    if resolved:
                        imports.add(resolved)
            elif isinstance(node, ast.ImportFrom):
                imports.update(cls._resolve_py_import_from(node, importer, project_root))

        return imports

    @classmethod
    def _extract_py_imports_with_regex(cls, code: str, importer: str, project_root: str) -> set[str]:
        """Best-effort fallback for unsaved buffers that do not parse yet."""
        imports: set[str] = set()

        for match in _PY_FROM_IMPORT_RE.finditer(code):
            raw_module = match.group(1)
            imported_names = [name.strip().split(" as ", 1)[0] for name in match.group(2).split(",")]
            imports.update(cls._resolve_py_from_parts(raw_module, imported_names, importer, project_root))

        for match in _PY_DIRECT_IMPORT_RE.finditer(code):
            for raw_module in match.group(1).split(","):
                raw_module = raw_module.strip().split(" as ", 1)[0]
                resolved = cls._resolve_py_module(raw_module, importer, project_root, level=0)
                if resolved:
                    imports.add(resolved)

        if imports:
            return imports

        for match in _PY_IMPORT_RE.finditer(code):
            raw_module = match.group(1) or match.group(2) or ""
            level = len(raw_module) - len(raw_module.lstrip("."))
            resolved = cls._resolve_py_module(raw_module[level:], importer, project_root, level=level)
            if resolved:
                imports.add(resolved)
        return imports

    @classmethod
    def _resolve_py_import_from(cls, node: ast.ImportFrom, importer: str, project_root: str) -> set[str]:
        imports: set[str] = set()
        module = node.module or ""

        if module == "__future__":
            return imports

        imported_names = [alias.name for alias in node.names]
        return cls._resolve_py_from_parts(module, imported_names, importer, project_root, level=node.level)

    @classmethod
    def _resolve_py_from_parts(
        cls,
        module: str,
        imported_names: list[str],
        importer: str,
        project_root: str,
        *,
        level: int | None = None,
    ) -> set[str]:
        imports: set[str] = set()
        if level is None:
            level = len(module) - len(module.lstrip("."))
            module = module[level:]

        resolved_module = cls._resolve_py_module(module, importer, project_root, level=level)
        if resolved_module:
            imports.add(resolved_module)

        for imported_name in imported_names:
            if not imported_name or imported_name == "*":
                continue
            imported_module = f"{module}.{imported_name}" if module else imported_name
            resolved_import = cls._resolve_py_module(imported_module, importer, project_root, level=level)
            if resolved_import:
                imports.add(resolved_import)

        return imports

    @classmethod
    def _resolve_py_module(
        cls,
        raw_module: str,
        importer: str,
        project_root: str,
        *,
        level: int,
    ) -> str | None:
        """Resolve a Python module name to an absolute file path (best-effort)."""
        module_parts = [part for part in raw_module.split(".") if part]
        root = Path(project_root).resolve()
        importer_path = Path(importer).resolve()

        if level > 0:
            base = importer_path.parent
            for _ in range(level - 1):
                base = base.parent
        else:
            base = root

        candidate = base.joinpath(*module_parts) if module_parts else base
        return cls._resolve_py_candidate(candidate, root)

    @staticmethod
    def _resolve_py_candidate(candidate: Path, project_root: Path) -> str | None:
        """Resolve module candidate paths while keeping dependencies inside project_root."""
        candidates = [candidate]
        if candidate.suffix != ".py":
            candidates.append(candidate.with_suffix(".py"))
        candidates.append(candidate / "__init__.py")

        for path in candidates:
            if not path.is_file():
                continue
            resolved = path.resolve()
            try:
                if not resolved.is_relative_to(project_root):
                    continue
            except ValueError:
                continue
            return str(resolved)

        return None
