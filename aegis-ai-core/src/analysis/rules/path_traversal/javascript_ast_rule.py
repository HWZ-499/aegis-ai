"""
path_traversal.javascript_ast_rule

JavaScript/TypeScript 路径遍历 / 不安全文件访问 AST 规则。

检测目标：
- Node.js fs 模块的文件操作（fs.open/readFile/writeFile 等）使用用户输入作为路径。

说明：
- 使用 Tree-sitter Node；
- 需要区分文件操作和 UI 操作（如 window.open, snackBar.open 等）。
"""

from __future__ import annotations

from typing import Any, Dict

from ...base import AnalysisContext, SecurityRule
from ...base.user_input_detector import is_user_input_node

# Tree-sitter Node 类型
try:
    from tree_sitter import Node
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any


class JavaScriptPathTraversalAstRule(SecurityRule):
    """
    基于 Tree-sitter AST 的 JavaScript/TypeScript 路径遍历检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="PATH_TRAVERSAL_JS_AST",
            severity="High",
            languages=["javascript", "typescript"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """
        访问 Tree-sitter AST 节点。
        """
        if not TREE_SITTER_AVAILABLE:
            return

        if not isinstance(node, Node) or node.type != "call_expression":
            return

        # 提取方法调用信息
        method_name = None
        object_name = None

        for child in node.children:
            if child.type == "member_expression":
                for subchild in child.children:
                    if subchild.type == "identifier":
                        object_name = self._get_node_text(subchild)
                    elif subchild.type == "property_identifier":
                        method_name = self._get_node_text(subchild)

        # 检查是否是文件操作
        if not self._is_file_operation(object_name, method_name):
            return

        # 检查参数中是否有用户输入
        if not node.children:
            return

        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    if self._looks_like_user_input(arg):
                        line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
                        finding: Dict[str, Any] = {
                            "type": "PATH_TRAVERSAL",
                            "rule_id": self.rule_id,
                            "severity": self.severity,
                            "line": line_no,
                            "details": f"文件操作 {object_name}.{method_name}() 使用疑似用户输入作为路径参数，可能存在路径遍历风险。",
                        }
                        context.add_finding(finding)
                        return

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------
    @staticmethod
    def _is_file_operation(obj_name: str | None, method_name: str | None) -> bool:
        """
        判断是否为文件操作（排除 UI 操作）。
        """
        if obj_name == "fs" and method_name in (
            "open",
            "readFile",
            "writeFile",
            "createReadStream",
            "createWriteStream",
            "readdir",
            "stat",
        ):
            return True

        if obj_name == "path" and method_name == "join":
            # path.join 需要检查是否包含用户输入
            return True

        # 排除 UI 操作
        ui_objects = ["window", "snackBar", "dialog", "modal", "toast", "alert", "popup"]
        if obj_name in ui_objects and method_name == "open":
            return False

        return False

    @staticmethod
    def _looks_like_user_input(node: Node) -> bool:
        """
        判断节点是否来自用户输入（结构化检测）。

        使用 ``is_user_input_node`` 进行精确 AST 匹配，
        不再使用关键词子串模糊搜索。
        """
        return is_user_input_node(node, language="javascript")

    @staticmethod
    def _get_node_text(node: Node) -> str | None:
        """提取节点的文本内容。"""
        if hasattr(node, "text"):
            return node.text.decode("utf-8")
        return None


__all__ = ["JavaScriptPathTraversalAstRule"]
