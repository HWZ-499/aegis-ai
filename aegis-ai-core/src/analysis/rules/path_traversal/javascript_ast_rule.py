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

from typing import Any

from ...base import AnalysisContext, SecurityRule
from ...base.user_input_detector import is_user_input_node

# Tree-sitter Node 类型
try:
    from tree_sitter import Node

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any  # type: ignore[misc,assignment]


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

        # 取路径参数（文件操作第一个参数）
        path_arg = None
        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    if arg.type not in ("(", ",", ")"):
                        path_arg = arg
                        break
                break
        if path_arg is None:
            return

        # 【污点 + 净化感知】优先使用 taint_graph / dataflow_tracker
        if context.taint_graph or context.dataflow_tracker:
            identifiers = self._collect_identifiers_from_node(path_arg)
            if identifiers and all(context.is_var_sanitized(v) for v in identifiers):
                return
            if identifiers and any(context.is_var_tainted(v) for v in identifiers):
                line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
                finding = self._make_finding(line_no, object_name, method_name)
                context.add_finding(finding)
                return
            # 若 identifiers 存在但未追踪到污点，继续降级到结构化检测
            # （孤立片段如 fs.readFile(req.query.path) 中 req 可能未被 collector 标记）
        # 降级：结构化用户输入检测
        if self._looks_like_user_input(path_arg, context):
            line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
            finding = self._make_finding(line_no, object_name, method_name)
            context.add_finding(finding)

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

    def _collect_identifiers_from_node(self, node: Node) -> list[str]:
        """
        从 AST 节点子树收集标识符与 member_expression 文本，供污点/净化查询。
        """
        out: list[str] = []
        if node.type == "identifier":
            t = self._get_node_text(node)
            if t:
                out.append(t)
            return out
        if node.type == "member_expression":
            full = self._get_node_text(node)
            if full:
                out.append(full)
            return out
        for child in getattr(node, "children", []) or []:
            out.extend(self._collect_identifiers_from_node(child))
        return out

    def _make_finding(self, line_no: int, object_name: str | None, method_name: str | None) -> dict[str, Any]:
        """构建 PATH_TRAVERSAL finding。"""
        return {
            "type": "PATH_TRAVERSAL",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line_no,
            "details": f"文件操作 {object_name or '?'}.{method_name or '?'}() 使用疑似用户输入作为路径参数，可能存在路径遍历风险。建议使用 path.basename/path.normalize 或白名单校验。",
        }

    @staticmethod
    def _looks_like_user_input(node: Node, context: AnalysisContext | None = None) -> bool:
        """
        判断节点是否来自用户输入（结构化检测 + 污点查询）。

        使用 ``is_user_input_node`` 进行精确 AST 匹配。
        """
        return is_user_input_node(node, context, language="javascript")

    @staticmethod
    def _get_node_text(node: Node) -> str | None:
        """提取节点的文本内容。"""
        if hasattr(node, "text"):
            return node.text.decode("utf-8")
        return None


__all__ = ["JavaScriptPathTraversalAstRule"]
