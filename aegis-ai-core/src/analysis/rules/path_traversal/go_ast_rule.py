"""
path_traversal.go_ast_rule

Go path-traversal AST / taint rule.

Detection targets:
1. Tree-sitter AST node-level analysis (visit):
   - os.Open(userInput), os.OpenFile(userInput, ...), os.Create(userInput)
   - os.ReadFile(userInput), ioutil.ReadFile(userInput)
   - os.Stat(userInput), os.Remove(userInput)
   - os.MkdirAll(userInput, ...), os.RemoveAll(userInput), os.Rename(userInput, ...)
   - ioutil.WriteFile(userInput, ...), ioutil.ReadDir(userInput)
2. TaintGraph path analysis (after_file, fallback):
   - Traces user input to PATH_TRAVERSAL sinks via SourceSinkRegistry.
"""

from __future__ import annotations

from typing import Any

from ...base import (
    AnalysisContext,
    SecurityRule,
    safe_find_paths,
    tree_sitter_node_to_range,
)
from ...base.user_input_detector import is_user_input_node

try:
    from tree_sitter import Node

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any  # type: ignore[misc,assignment]

# ------------------------------------------------------------------
# Dangerous file-system functions keyed by package
# ------------------------------------------------------------------
# Map: func_name -> frozenset of known packages that expose it.
# When package cannot be resolved we still flag if the function name
# is in the combined set.
_PATH_SINK_FUNCS: dict[str, frozenset[str]] = {
    # os package
    "Open": frozenset(["os"]),
    "OpenFile": frozenset(["os"]),
    "Create": frozenset(["os"]),
    "ReadFile": frozenset(["os", "ioutil"]),
    "Stat": frozenset(["os"]),
    "Lstat": frozenset(["os"]),
    "Remove": frozenset(["os"]),
    "RemoveAll": frozenset(["os"]),
    "Rename": frozenset(["os"]),
    "Mkdir": frozenset(["os"]),
    "MkdirAll": frozenset(["os"]),
    # ioutil (deprecated but still common)
    "ReadDir": frozenset(["ioutil", "os"]),
    "WriteFile": frozenset(["ioutil", "os"]),
}

# Union of all recognised function names (for quick pre-check)
_ALL_SINK_FUNC_NAMES: frozenset[str] = frozenset(_PATH_SINK_FUNCS.keys())

# Known sanitizer function names (package.Func patterns)
_PATH_SANITIZERS: frozenset[str] = frozenset(
    [
        "filepath.Clean",
        "filepath.Abs",
        "filepath.Base",
        "filepath.Rel",
        "path.Clean",
        "path.Base",
    ]
)


class GoPathTraversalAstRule(SecurityRule):
    """
    Tree-sitter AST + TaintGraph based Go path-traversal detection rule.
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="PATH_TRAVERSAL_GO_TAINT",
            severity="High",
            languages=["go"],
        )
        self._reported_lines: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported_lines = set()

    # ------------------------------------------------------------------
    # AST visit
    # ------------------------------------------------------------------
    def visit(self, node: Any, context: AnalysisContext) -> None:
        """
        Per-node AST analysis: detect file-system calls receiving user input.
        """
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        if node.type == "call_expression":
            self._check_call_expression(node, context)

    def _check_call_expression(self, node: Any, context: AnalysisContext) -> None:
        """Detect os.Open(var), filepath.Join(var), etc."""
        func_name, pkg_name = self._get_qualified_name(node)
        if func_name is None:
            return

        # Quick reject: function name not in our sink list
        if func_name not in _ALL_SINK_FUNC_NAMES:
            return

        # If we can resolve the package, verify it is an expected one
        allowed_pkgs = _PATH_SINK_FUNCS[func_name]
        if pkg_name and pkg_name not in allowed_pkgs:
            return

        args = self._get_arguments(node)
        if not args:
            return

        # Determine which argument index carries the path.
        # Most functions: first argument is the path.
        # os.OpenFile(name, flag, perm) -> index 0
        # os.Rename(old, new) -> index 0 (old) or 1 (new)
        # filepath.Join(elems...) -> any argument
        if func_name == "Join":
            # filepath.Join: any segment could be user-controlled
            tainted_args = args
        elif func_name == "Rename":
            # both src and dst are interesting
            tainted_args = args[:2] if len(args) >= 2 else args
        else:
            # first argument is the path
            tainted_args = args[:1]

        for arg in tainted_args:
            # Skip if the argument is wrapped in a known sanitizer
            if self._is_sanitized_call(arg):
                continue
            if self._subtree_has_user_input(arg, context):
                qualified = f"{pkg_name}.{func_name}" if pkg_name else func_name
                self._report(node, context, qualified)
                return

    # ------------------------------------------------------------------
    # TaintGraph fallback (after_file)
    # ------------------------------------------------------------------
    def after_file(self, context: AnalysisContext) -> None:
        """Read TaintGraph Source->Sink paths as fallback."""
        graph = getattr(context, "taint_graph", None)
        if graph is None:
            return

        reported_sinks: set[str] = set()
        paths = safe_find_paths(graph, self.rule_id)

        for path in paths:
            if getattr(path, "is_sanitized", False):
                continue

            sink = getattr(path, "sink_node", None)
            source = getattr(path, "source_node", None)
            if sink is None or source is None:
                continue

            sink_id = getattr(sink, "id", "")
            if not sink_id or sink_id in reported_sinks:
                continue

            category = (sink.extras or {}).get("category") if hasattr(sink, "extras") else None
            if category != "path_traversal":
                continue

            line_no = getattr(sink, "line", 0) or 0
            if line_no in self._reported_lines:
                continue

            reported_sinks.add(sink_id)

            src_expr = getattr(source, "name", "") or getattr(source, "code_snippet", "")
            sink_expr = getattr(sink, "name", "") or getattr(sink, "code_snippet", "")

            details = (
                "检测到 Go 代码中用户可控输入流入 os.Open/os.OpenFile 等文件访问 API，"
                "且未检测到 filepath.Clean 或目录白名单校验，存在路径穿越风险。"
            )

            finding: dict[str, Any] = {
                "type": "PATH_TRAVERSAL",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": details,
                "source_expr": src_expr,
                "sink_expr": sink_expr,
            }
            context.add_finding(finding)

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------
    @staticmethod
    def _get_node_text(node: Any) -> str | None:
        if hasattr(node, "text"):
            raw = node.text
            return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        return None

    @staticmethod
    def _get_qualified_name(node: Any) -> tuple[str | None, str | None]:
        """Extract (func_name, package_name) from a call_expression."""
        for child in node.children:
            if child.type == "selector_expression":
                parts: list[str] = []
                for sub in child.children:
                    if sub.type in ("identifier", "field_identifier"):
                        text = sub.text
                        parts.append(text.decode("utf-8") if isinstance(text, bytes) else str(text))
                if len(parts) >= 2:
                    return parts[-1], parts[0]
                if len(parts) == 1:
                    return parts[0], None
            if child.type == "identifier":
                text = child.text
                name = text.decode("utf-8") if isinstance(text, bytes) else str(text)
                return name, None
        return None, None

    @staticmethod
    def _get_arguments(node: Any) -> list[Any]:
        """Extract argument nodes from a call_expression."""
        for child in node.children:
            if child.type == "argument_list":
                return [c for c in child.children if c.type not in ("(", ")", ",")]
        return []

    def _is_sanitized_call(self, node: Any) -> bool:
        """Check whether *node* is a call to a known path sanitizer.

        Matches patterns like ``filepath.Clean(x)`` or ``path.Base(x)``.
        """
        if not hasattr(node, "type") or node.type != "call_expression":
            return False
        func_name, pkg_name = self._get_qualified_name(node)
        if func_name is None:
            return False
        qualified = f"{pkg_name}.{func_name}" if pkg_name else func_name
        return qualified in _PATH_SANITIZERS

    def _subtree_has_user_input(self, node: Any, context: AnalysisContext) -> bool:
        """Recursively check whether any node in the subtree is user input."""
        if is_user_input_node(node, context, language="go"):
            return True
        for child in getattr(node, "children", []) or []:
            if self._subtree_has_user_input(child, context):
                return True
        return False

    def _collect_identifiers(self, node: Any) -> list[str]:
        """Collect all identifier / field_identifier names in the subtree."""
        result: list[str] = []
        if node.type in ("identifier", "field_identifier"):
            text = self._get_node_text(node)
            if text:
                result.append(text)
        for child in getattr(node, "children", []) or []:
            result.extend(self._collect_identifiers(child))
        return result

    def _report(self, node: Any, context: AnalysisContext, func_desc: str) -> None:
        line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
        if line in self._reported_lines:
            return

        # Sanitizer awareness: if all identifiers in the call are marked as
        # sanitized by the dataflow tracker, skip the finding.
        identifiers = self._collect_identifiers(node)
        if identifiers and (context.taint_graph or context.dataflow_tracker):
            if all(context.is_var_sanitized(v) for v in identifiers):
                return

        self._reported_lines.add(line)
        finding: dict[str, Any] = {
            "type": "PATH_TRAVERSAL",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line,
            "details": (
                f"检测到 {func_desc}() 调用中包含用户可控输入，"
                "且未经 filepath.Clean 等清理，存在路径穿越风险，"
                "建议使用 filepath.Clean 清理并校验目录白名单。"
            ),
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)


__all__ = ["GoPathTraversalAstRule"]
