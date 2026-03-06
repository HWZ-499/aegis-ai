"""
deserialization.javascript_ast_rule

JavaScript/TypeScript 反序列化风险 AST 规则。

检测目标：
- JSON.parse()、node-serialize.unserialize()、js-yaml.load() 对不可信数据执行反序列化。
- 接入污点分析 + 净化感知。
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


def _get_node_text(node: Any) -> str | None:
    """提取 Tree-sitter 节点文本。"""
    if hasattr(node, "text"):
        raw = node.text
        return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
    return None


def _collect_identifiers_from_node(node: Any) -> list[str]:
    """从 AST 节点子树收集标识符与 member_expression 文本。"""
    out: list[str] = []
    if getattr(node, "type", None) == "identifier":
        t = _get_node_text(node)
        if t:
            out.append(t)
        return out
    if getattr(node, "type", None) == "member_expression":
        full = _get_node_text(node)
        if full:
            out.append(full)
        return out
    for child in getattr(node, "children", []) or []:
        out.extend(_collect_identifiers_from_node(child))
    return out


class JavaScriptDeserializationAstRule(SecurityRule):
    """
    基于 Tree-sitter AST 的 JavaScript/TypeScript 反序列化风险检测规则。
    支持 JSON.parse、unserialize、js-yaml.load；污点 + 净化感知。
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

        obj_name: str | None = None
        method_name: str | None = None
        for child in node.children:
            if child.type == "member_expression":
                parts = []
                for subchild in child.children:
                    if subchild.type == "identifier":
                        parts.append(_get_node_text(subchild) or "")
                    elif subchild.type == "property_identifier":
                        parts.append(_get_node_text(subchild) or "")
                if len(parts) >= 2:
                    obj_name, method_name = parts[0], parts[-1]
                elif len(parts) == 1:
                    obj_name = parts[0]
            elif child.type == "identifier":
                obj_name = _get_node_text(child)

        # 安全 sink（不报）
        if (obj_name, method_name) in (("yaml", "safeLoad"), ("js-yaml", "safeLoad")):
            return
        # 危险 sink：JSON.parse / unserialize / serialize.unserialize / yaml.load / js-yaml.load
        is_sink = (
            (obj_name == "JSON" and method_name == "parse")
            or (obj_name == "unserialize" and method_name is None)
            or (obj_name == "serialize" and method_name == "unserialize")
            or (obj_name == "yaml" and method_name == "load")
            or (obj_name == "js-yaml" and method_name == "load")
        )
        if not is_sink:
            return

        # 取第一个参数
        arg_node = None
        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    if arg.type not in (",", ")"):
                        arg_node = arg
                        break
                break
        if arg_node is None:
            return

        arg_text = _get_node_text(arg_node) or ""
        if "localStorage" in arg_text or "sessionStorage" in arg_text:
            return
        if self._is_simple_url_param(arg_node):
            return

        # 【污点 + 净化感知】
        if context.taint_graph or context.dataflow_tracker:
            identifiers = _collect_identifiers_from_node(arg_node)
            if identifiers and all(context.is_var_sanitized(v) for v in identifiers):
                return
            if identifiers and any(context.is_var_tainted(v) for v in identifiers):
                line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
                context.add_finding(self._make_finding(line_no))
                return
            if identifiers:
                return
        # 降级：结构化用户输入检测（仅 JSON.parse 保留原逻辑）
        if obj_name == "JSON" and method_name == "parse" and self._looks_like_user_input(arg_node, context):
            line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
            context.add_finding(self._make_finding(line_no))

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------
    def _make_finding(self, line_no: int) -> Dict[str, Any]:
        """构建 DESERIALIZATION finding。"""
        return {
            "type": "DESERIALIZATION",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line_no,
            "details": "对疑似用户输入执行反序列化（JSON.parse/unserialize/yaml.load 等），存在反序列化风险，建议先验证或净化输入。",
        }

    @staticmethod
    def _looks_like_user_input(node: Node, context: AnalysisContext | None = None) -> bool:
        """
        判断节点是否来自用户输入（结构化检测 + 污点查询）。
        """
        return is_user_input_node(node, context, language="javascript")

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
        text = _get_node_text(node) or ""
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


__all__ = ["JavaScriptDeserializationAstRule"]
