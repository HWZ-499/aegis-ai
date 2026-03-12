"""
path_traversal.java_ast_rule

Java 路径穿越 AST/污点规则。

检测目标：
1. Tree-sitter AST 节点级分析（visit）：
   - new File(userInput) / new FileInputStream(userInput) / new FileOutputStream(userInput)
   - Paths.get(userInput)
   - Files.readAllBytes / Files.write / Files.newInputStream / Files.newOutputStream 等
2. TaintGraph 路径分析（after_file，兜底）：
   - 通过 SourceSinkRegistry 的 Java Sources/Sinks 追踪用户输入到文件系统 sink。
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

# 危险的文件构造类（通过 new XxxClass(path) 创建）
_FILE_CONSTRUCTOR_CLASSES = frozenset(
    [
        "File",
        "FileInputStream",
        "FileOutputStream",
        "FileReader",
        "FileWriter",
        "RandomAccessFile",
    ]
)

# 危险的静态方法调用（receiver.method 形式）
_FILE_STATIC_METHODS: dict[str, frozenset[str]] = {
    "Paths": frozenset(["get"]),
    "Files": frozenset(
        [
            "readAllBytes",
            "readAllLines",
            "readString",
            "write",
            "newInputStream",
            "newOutputStream",
            "newBufferedReader",
            "newBufferedWriter",
            "copy",
            "move",
            "delete",
            "deleteIfExists",
            "createFile",
            "createDirectory",
            "createDirectories",
            "list",
            "walk",
            "lines",
        ]
    ),
    "Path": frozenset(["of"]),
}


class JavaPathTraversalAstRule(SecurityRule):
    """
    基于 Tree-sitter AST + TaintGraph 的 Java 路径穿越检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="PATH_TRAVERSAL_JAVA_TAINT",
            severity="High",
            languages=["java"],
        )
        self._reported_lines: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported_lines = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """
        逐节点 AST 分析：检测文件系统 API 使用用户可控输入的模式。
        """
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        if node.type == "method_invocation":
            self._check_method_invocation(node, context)
        elif node.type == "object_creation_expression":
            self._check_object_creation(node, context)

    def _check_method_invocation(self, node: Any, context: AnalysisContext) -> None:
        """检测 Paths.get(userInput) / Files.readAllBytes(userInput) 等模式。"""
        receiver = self._get_receiver_name(node)
        method_name = self._get_method_name(node)
        if receiver is None or method_name is None:
            return

        allowed_methods = _FILE_STATIC_METHODS.get(receiver)
        if allowed_methods is None or method_name not in allowed_methods:
            return

        args = self._get_arguments(node)
        if not args:
            return

        first_arg = args[0]

        # 检查第一个参数是否包含用户输入
        if not self._subtree_has_user_input(first_arg, context):
            return

        self._report(node, context, f"{receiver}.{method_name}")

    def _check_object_creation(self, node: Any, context: AnalysisContext) -> None:
        """检测 new File(userInput) / new FileInputStream(userInput) 等模式。"""
        type_name = self._get_created_type(node)
        if type_name is None or type_name not in _FILE_CONSTRUCTOR_CLASSES:
            return

        args = self._get_arguments(node)
        if not args:
            return

        first_arg = args[0]

        # 检查第一个参数是否包含用户输入
        if not self._subtree_has_user_input(first_arg, context):
            return

        self._report(node, context, f"new {type_name}")

    def after_file(self, context: AnalysisContext) -> None:
        """
        TaintGraph 兜底：在 AST visit 未覆盖的情况下，读取 TaintGraph 路径。
        """
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
            # 跳过 visit 阶段已报告的行
            if line_no in self._reported_lines:
                continue

            reported_sinks.add(sink_id)

            src_expr = getattr(source, "name", "") or getattr(source, "code_snippet", "")
            sink_expr = getattr(sink, "name", "") or getattr(sink, "code_snippet", "")

            details = (
                "检测到 Java 代码中用户可控输入流入文件系统访问（如 new File()/FileInputStream），"
                "且未检测到路径规范化或白名单校验，存在目录穿越风险。"
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
    # 辅助方法
    # ------------------------------------------------------------------
    @staticmethod
    def _get_node_text(node: Any) -> str | None:
        if hasattr(node, "text"):
            raw = node.text
            return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        return None

    @staticmethod
    def _get_receiver_name(node: Any) -> str | None:
        """提取方法调用的 receiver 名称（如 Paths.get → "Paths"）。"""
        children = list(node.children)
        if len(children) >= 3 and children[1].type == ".":
            first = children[0]
            if first.type == "identifier":
                text = first.text
                return text.decode("utf-8") if isinstance(text, bytes) else str(text)
        return None

    @staticmethod
    def _get_method_name(node: Any) -> str | None:
        """从 method_invocation 节点提取方法名。"""
        children = list(node.children)
        # obj.method(...) 形式: [identifier, ".", identifier, argument_list]
        if len(children) >= 3 and children[1].type == ".":
            name_node = children[2]
            if name_node.type == "identifier":
                text = name_node.text
                return text.decode("utf-8") if isinstance(text, bytes) else str(text)
        # method(...) 形式: [identifier, argument_list]
        for child in children:
            if child.type == "identifier":
                text = child.text
                return text.decode("utf-8") if isinstance(text, bytes) else str(text)
        return None

    @staticmethod
    def _get_created_type(node: Any) -> str | None:
        """从 object_creation_expression 节点提取类型名（如 new File → "File"）。"""
        for child in node.children:
            if child.type == "type_identifier":
                text = child.text
                return text.decode("utf-8") if isinstance(text, bytes) else str(text)
        return None

    @staticmethod
    def _get_arguments(node: Any) -> list[Any]:
        """提取参数节点列表。"""
        for child in node.children:
            if child.type == "argument_list":
                return [c for c in child.children if c.type not in ("(", ")", ",")]
        return []

    def _subtree_has_user_input(self, node: Any, context: AnalysisContext) -> bool:
        """递归检查子树中是否包含用户输入节点。"""
        if is_user_input_node(node, context, language="java"):
            return True
        for child in getattr(node, "children", []) or []:
            if self._subtree_has_user_input(child, context):
                return True
        return False

    def _collect_identifiers(self, node: Any) -> list[str]:
        """收集子树中所有 identifier 文本。"""
        result: list[str] = []
        if node.type == "identifier":
            text = self._get_node_text(node)
            if text:
                result.append(text)
        for child in getattr(node, "children", []) or []:
            result.extend(self._collect_identifiers(child))
        return result

    def _report(self, node: Any, context: AnalysisContext, sink_label: str) -> None:
        """生成 finding 并添加到 context。"""
        line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
        if line in self._reported_lines:
            return

        # Sanitizer 感知
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
                f"检测到 {sink_label}() 调用中使用了用户可控输入作为文件路径参数，"
                "且未检测到路径规范化或白名单校验，存在目录穿越风险。"
            ),
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)


__all__ = ["JavaPathTraversalAstRule"]
