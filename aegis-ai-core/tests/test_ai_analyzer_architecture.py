from __future__ import annotations

import ast
from pathlib import Path

from src.scanner.ai_analyzer import build_local_fix_analysis


def test_ai_analyzer_keeps_local_fix_implementation_split_out() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    analyzer_path = repo_root / "src/scanner/ai_analyzer.py"
    local_fix_path = repo_root / "src/scanner/local_fix.py"
    analyzer_source = analyzer_path.read_text(encoding="utf-8")
    local_fix_source = local_fix_path.read_text(encoding="utf-8")

    assert len(analyzer_source.splitlines()) <= 1150
    assert "def _build_local_cpp_fix_replacement(" not in analyzer_source
    assert "from .local_fix import" in analyzer_source
    assert callable(build_local_fix_analysis)

    tree = ast.parse(local_fix_source, filename=str(local_fix_path))
    imported_modules = {
        node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module != "__future__"
    }
    imported_modules.update(
        alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
    )
    assert imported_modules <= {"re", "dataclasses", "typing"}
