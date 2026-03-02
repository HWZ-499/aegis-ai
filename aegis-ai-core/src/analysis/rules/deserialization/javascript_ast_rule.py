"""
deserialization.javascript_ast_rule

JavaScript/TypeScript 反序列化风险 AST 规则。

检测目标：
- JSON.parse() 对不可信数据执行反序列化。

说明：
- 使用 Tree-sitter Node；
- JSON.parse 本身是安全的，但如果参数来自用户输入，可能存在风险。
"""

from __future__ import annotations

import re
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


class JavaScriptDeserializationAstRule(SecurityRule):
    """
    基于 Tree-sitter AST 的 JavaScript/TypeScript 反序列化风险检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="DESERIALIZATION_JS_AST",
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

        # 提取函数名
        function_name = None
        for child in node.children:
            if child.type == "member_expression":
                for subchild in child.children:
                    if subchild.type == "property_identifier":
                        function_name = self._get_node_text(subchild)
            elif child.type == "identifier":
                function_name = self._get_node_text(child)

        if function_name != "parse":
            return

        # 检查是否是 JSON.parse
        is_json_parse = False
        for child in node.children:
            if child.type == "member_expression":
                for subchild in child.children:
                    if subchild.type == "identifier" and self._get_node_text(subchild) == "JSON":
                        is_json_parse = True
                        break

        if not is_json_parse:
            return

        # 检查参数是否是用户输入
        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    if self._looks_like_user_input(arg):
                        # 排除 localStorage/sessionStorage（通常是安全的）
                        arg_text = self._get_node_text(arg) or ""
                        if "localStorage" in arg_text or "sessionStorage" in arg_text:
                            continue

                        # 【修复镜像陷阱】排除 req.params.*, req.query.*（简单的 URL 参数，通常是字符串）
                        # JSON.parse 对字符串参数通常是安全的（除非是复杂的对象）
                        if self._is_simple_url_param(arg):
                            continue

                        line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
                        finding: Dict[str, Any] = {
                            "type": "DESERIALIZATION",
                            "rule_id": self.rule_id,
                            "severity": self.severity,
                            "line": line_no,
                            "details": "对疑似用户输入执行 JSON.parse()，存在反序列化风险，建议先验证输入。",
                        }
                        context.add_finding(finding)
                        return

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------
    @staticmethod
    def _looks_like_user_input(node: Node) -> bool:
        """
        判断节点是否来自用户输入（结构化检测）。

        使用 ``is_user_input_node`` 进行精确 AST 匹配，
        不再使用关键词子串模糊搜索。
        """
        return is_user_input_node(node, language="javascript")

    @staticmethod
    def _is_simple_url_param(node: Node) -> bool:
        """
        判断是否是简单的 URL 参数（req.params.*, req.query.*）。
        
        这些参数通常是字符串类型，JSON.parse 对字符串参数通常是安全的
        （除非是复杂的对象，但这种情况较少）。
        
        Args:
            node: Tree-sitter Node（通常是 member_expression 或 identifier）
        
        Returns:
            True 如果是简单的 URL 参数，False 否则
        """
        text = JavaScriptDeserializationAstRule._get_node_text(node) or ""
        text_lower = text.lower()
        
        # 匹配 req.params.*, req.query.* 模式
        # 这些是简单的 URL 参数，通常是字符串
        simple_url_param_patterns = [
            r"req\.params\.",
            r"req\.query\.",
            r"request\.params\.",
            r"request\.query\.",
        ]
        
        for pattern in simple_url_param_patterns:
            if re.search(pattern, text_lower):
                return True
        
        return False

    @staticmethod
    def _get_node_text(node: Node) -> str | None:
        """提取节点的文本内容。"""
        if hasattr(node, "text"):
            return node.text.decode("utf-8")
        return None


__all__ = ["JavaScriptDeserializationAstRule"]
