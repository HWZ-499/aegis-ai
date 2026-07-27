from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path


class _BroadCatchVisitor(ast.NodeVisitor):
    def __init__(self, relative_path: str) -> None:
        self.relative_path = relative_path
        self.scope: list[str] = []
        self.broad_catches: list[tuple[str, str]] = []
        self.bare_catches: list[tuple[str, str]] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        location = (self.relative_path, ".".join(self.scope))
        if node.type is None:
            self.bare_catches.append(location)
        elif isinstance(node.type, ast.Name) and node.type.id in {"Exception", "BaseException"}:
            self.broad_catches.append(location)
        self.generic_visit(node)


def test_broad_exception_catches_are_limited_to_explicit_boundaries() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    source_root = repo_root / "src"
    allowed = Counter(
        {
            ("src/worker_daemon.py", "run_daemon"): 1,
            ("src/lsp/server.py", "scan_document"): 1,
            ("src/scanner/cli.py", "main"): 1,
            ("src/ai/llm_gateway.py", "OpenAICompatibleProvider.generate"): 1,
            ("src/ai/llm_gateway.py", "LLMGateway.generate"): 1,
        }
    )
    actual: Counter[tuple[str, str]] = Counter()
    bare: list[tuple[str, str]] = []

    for path in source_root.rglob("*.py"):
        relative_path = path.relative_to(repo_root).as_posix()
        visitor = _BroadCatchVisitor(relative_path)
        visitor.visit(ast.parse(path.read_text(encoding="utf-8"), filename=relative_path))
        actual.update(visitor.broad_catches)
        bare.extend(visitor.bare_catches)

    assert bare == []
    assert actual == allowed
