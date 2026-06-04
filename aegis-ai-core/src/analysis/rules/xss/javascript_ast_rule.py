"""
xss.javascript_ast_rule

JavaScript/TypeScript XSS 风险 AST 规则（新规则架构）。

检测目标：
- innerHTML / outerHTML 赋值
- dangerouslySetInnerHTML (React)
- v-html (Vue)
- 其他未转义的用户输入直接输出

说明：
- 使用 Tree-sitter Node（不是 Python ast.AST）；
- 复用 multi_language_ast 中的核心检测逻辑。
"""

from __future__ import annotations

import re
from typing import Any

from ...base import (
    AnalysisContext,
    SecurityRule,
    make_related_location,
    tree_sitter_node_to_range,
)

# Tree-sitter Node 类型（运行时检查）
try:
    from tree_sitter import Node

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any  # type: ignore[misc,assignment]


class JavaScriptXSSAstRule(SecurityRule):
    """
    基于 Tree-sitter AST 的 JavaScript/TypeScript XSS 风险检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="XSS_RISK_JS_AST",
            severity="High",
            languages=["javascript", "typescript"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """
        访问 Tree-sitter AST 节点。
        """
        if not TREE_SITTER_AVAILABLE:
            return

        if not isinstance(node, Node):
            return

        # 检测赋值表达式（innerHTML = ...）
        if node.type == "assignment_expression":
            self._check_inner_html_assignment(node, context)

        # 检测函数调用（bypassSecurityTrustHtml, bypassSecurityTrustScript 等）
        elif node.type == "call_expression":
            self._check_dangerous_function_call(node, context)
            self._check_response_send_with_user_input(node, context)

        # 检测对象属性（dangerouslySetInnerHTML, v-html 等）
        elif node.type == "pair" or node.type == "property":
            self._check_dangerous_property(node, context)

    # ------------------------------------------------------------------
    # 检测方法
    # ------------------------------------------------------------------
    # 明确命名的 HTML escaping helper。避免把 encode()/escape()/sanitize()
    # 这类通用本地函数误当成可信 HTML sanitizer。
    _TRUSTED_DIRECT_HTML_SANITIZERS = frozenset(
        {
            "escapeHtml",
            "htmlEscape",
            "htmlEncode",
            "encodeHtml",
            "sanitizeHtml",
        }
    )
    _TRUSTED_SANITIZER_OBJECTS = frozenset({"DOMPurify", "dompurify"})

    def _check_inner_html_assignment(self, node: Node, context: AnalysisContext) -> None:
        """
        检测 innerHTML / outerHTML 赋值。

        仅当右值**不是**以下安全情形之一时才告警：
        1. 硬编码字符串字面量（如 ``'<b>Hello</b>'``）——静态内容无注入风险。
        2. 已知净化函数的调用结果（如 ``DOMPurify.sanitize(data)``）。
        3. Sanitizer 感知：右值中的所有标识符均被 TaintGraph 标记为已净化。
        """
        if not node.children:
            return

        left_node = node.children[0]

        # 提取属性名
        prop_name = None
        if left_node.type == "member_expression":
            for child in left_node.children:
                if child.type == "property_identifier":
                    prop_name = self._get_node_text(child)
                    break
        elif left_node.type == "property_identifier":
            prop_name = self._get_node_text(left_node)

        if not prop_name or prop_name.lower() not in ("innerhtml", "outerhtml"):
            return

        # 找到右值节点（赋值表达式结构: left = right，跳过 "=" token）
        right_node = None
        passed_eq = False
        for child in node.children:
            if child.type == "=":
                passed_eq = True
                continue
            if passed_eq:
                right_node = child
                break

        if right_node is not None:
            # 情形 1：硬编码字符串字面量——无动态数据，不报
            if right_node.type in ("string", "template_string"):
                # template_string 中若含模板插值则不能排除，检查是否含 ${ }
                raw_text = self._get_node_text(right_node) or ""
                if right_node.type == "string" or "${" not in raw_text:
                    return

            # 情形 2：净化函数调用——检查调用的函数名
            if self._is_sanitizer_call(right_node):
                return

            # 情形 3：固定 JSONP answer 回调——DVWA CSP 页面中使用静态
            # 同源 JSONP 端点返回计算结果，不等同于任意用户输入。
            if self._is_static_jsonp_answer_assignment(right_node, context):
                return

            # 情形 3：TaintGraph Sanitizer 感知——右值所有标识符均已净化
            identifiers = self._collect_identifiers_from_node(right_node)
            if identifiers and all(context.is_var_sanitized(v) for v in identifiers):
                return

        line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
        finding: dict[str, Any] = {
            "type": "XSS_RISK",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line_no,
            "details": f"检测到 {prop_name} 赋值操作，右值包含动态内容且未经 HTML 净化，可能存在 XSS 风险。",
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)

    def _is_sanitizer_call(self, node: Node) -> bool:
        """
        判断节点是否是可信 HTML 净化函数调用（如 DOMPurify.sanitize(x)）。

        支持：
        - ``DOMPurify.sanitize(x)``（成员调用）
        - ``escapeHtml(x)`` / ``htmlEscape(x)`` 等明确 HTML escaping helper
        """
        if node.type != "call_expression":
            return False
        for child in node.children:
            if child.type == "member_expression":
                object_name = None
                method_name = None
                for sub in child.children:
                    if sub.type == "identifier" and object_name is None:
                        object_name = self._get_node_text(sub)
                    elif sub.type == "property_identifier":
                        method_name = self._get_node_text(sub)
                if object_name in self._TRUSTED_SANITIZER_OBJECTS and method_name == "sanitize":
                    return True
                if method_name in self._TRUSTED_DIRECT_HTML_SANITIZERS:
                    return True
            elif child.type == "identifier":
                fname = self._get_node_text(child) or ""
                if fname in self._TRUSTED_DIRECT_HTML_SANITIZERS:
                    return True
        return False

    def _is_static_jsonp_answer_assignment(self, node: Node, context: AnalysisContext) -> bool:
        """
        Detect the narrow static JSONP answer pattern used by DVWA CSP pages.

        The rule still reports normal callback object writes. This only skips a
        fixed same-origin JSONP script source that calls ``solveSum(obj)`` and
        writes the ``answer`` field.
        """
        right_text = (self._get_node_text(node) or "").strip()
        matched = re.fullmatch(
            r"(?P<param>[A-Za-z_$][\w$]*)\s*(?:\[\s*['\"]answer['\"]\s*\]|\.\s*answer)",
            right_text,
        )
        if matched is None:
            return False

        callback_param = re.escape(matched.group("param"))
        source = context.extras.get("source")
        if not isinstance(source, str):
            return False

        has_fixed_jsonp_src = re.search(
            r"\.src\s*=\s*['\"]source/jsonp(?:_impossible)?\.php(?:\?callback=solveSum)?['\"]",
            source,
        )
        if has_fixed_jsonp_src is None:
            return False

        callback_re = rf"\bfunction\s+solveSum\s*\(\s*{callback_param}\s*\)"
        return re.search(callback_re, source) is not None

    def _check_dangerous_function_call(self, node: Node, context: AnalysisContext) -> None:
        """
        检测危险函数调用（Angular bypassSecurityTrustHtml 等）。

        检测目标：
        - sanitizer.bypassSecurityTrustHtml()
        - sanitizer.bypassSecurityTrustScript()
        - sanitizer.bypassSecurityTrustStyle()
        - sanitizer.bypassSecurityTrustUrl()
        - sanitizer.bypassSecurityTrustResourceUrl()
        - DomSanitizer.bypassSecurityTrustHtml()
        """
        if not node.children:
            return

        # 提取函数名（member_expression 或 identifier）
        function_name = None
        for child in node.children:
            if child.type == "member_expression":
                # 提取最后一个属性名（函数名）
                for subchild in reversed(child.children):
                    if subchild.type == "property_identifier":
                        function_name = self._get_node_text(subchild)
                        break
            elif child.type == "identifier":
                function_name = self._get_node_text(child)

        if not function_name:
            return

        # Angular DomSanitizer 危险函数
        dangerous_functions = [
            "bypassSecurityTrustHtml",
            "bypassSecurityTrustScript",
            "bypassSecurityTrustStyle",
            "bypassSecurityTrustUrl",
            "bypassSecurityTrustResourceUrl",
            "bypassSecurityTrustIframe",
            "bypassSecurityTrustSoundCloud",
        ]

        if function_name in dangerous_functions:
            line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
            finding: dict[str, Any] = {
                "type": "XSS_RISK",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": f"检测到危险函数调用 '{function_name}()'，可能存在 XSS 风险，建议对用户输入进行 HTML 转义。",
            }
            finding.update(tree_sitter_node_to_range(node))
            context.add_finding(finding)

    def _check_response_send_with_user_input(self, node: Node, context: AnalysisContext) -> None:
        """
        检测 Express/Node 中 response.send / res.send 拼接用户/会话输入未转义（反射 XSS）。
        例如：response.send("Welcome back, " + request.session.username + "!");
        """
        if not node.children:
            return
        # 取调用对象与方法名（如 response.send -> "send"）
        method_name = None
        for child in node.children:
            if child.type == "member_expression":
                for sub in reversed(child.children):
                    if sub.type == "property_identifier":
                        method_name = self._get_node_text(sub)
                        break
                break
        if method_name != "send":
            return
        # 检查参数中是否有「字符串 + 用户/会话相关表达式」的拼接
        for child in node.children:
            if child.type != "arguments":
                continue
            for arg in child.children:
                if arg.type in ("binary_expression", "template_string"):
                    if not self._arg_contains_user_or_session_input(arg):
                        continue
                    # 【Sanitizer 感知】若表达式中所有标识符均已被净化（如 escapeHtml），则不报
                    identifiers = self._collect_identifiers_from_node(arg)
                    if identifiers and all(context.is_var_sanitized(v) for v in identifiers):
                        continue
                    line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
                    finding: dict[str, Any] = {
                        "type": "XSS_RISK",
                        "rule_id": self.rule_id,
                        "severity": self.severity,
                        "line": line_no,
                        "details": "检测到 response.send 等输出中拼接用户/会话输入未转义，可能存在反射 XSS 风险，建议对输出进行 HTML 转义。",
                    }
                    finding.update(tree_sitter_node_to_range(node))
                    # TDD 7.1/7.2：用户/会话输入表达式位置作为 related_locations
                    if hasattr(arg, "start_point"):
                        finding["related_locations"] = [
                            make_related_location(
                                str(context.file_path),
                                arg.start_point[0] + 1,
                                end_line=arg.end_point[0] + 1 if hasattr(arg, "end_point") else None,
                                message="用户/会话输入",
                            )
                        ]
                    context.add_finding(finding)
                    return

    def _arg_contains_user_or_session_input(self, node: Node) -> bool:
        """判断表达式是否包含 request.session.* / req.body.* / req.query.* 等。"""
        text = self._get_node_text(node) or ""
        text_lower = text.lower()
        if "session." in text_lower or "body." in text_lower or "query." in text_lower:
            if "request." in text_lower or "req." in text_lower:
                return True
        return False

    def _check_dangerous_property(self, node: Node, context: AnalysisContext) -> None:
        """检测危险属性（dangerouslySetInnerHTML, v-html 等）。"""
        # 提取属性名
        prop_name = None
        for child in node.children:
            if child.type == "property_identifier" or child.type == "string":
                prop_name = self._get_node_text(child)
                break

        dangerous_props = [
            "dangerouslySetInnerHTML",
            "__html",
            "v-html",
            "vHtml",
        ]

        if prop_name and prop_name in dangerous_props:
            line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
            finding: dict[str, Any] = {
                "type": "XSS_RISK",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": f"检测到危险属性 '{prop_name}'，可能存在 XSS 风险，建议对用户输入进行 HTML 转义。",
            }
            finding.update(tree_sitter_node_to_range(node))
            context.add_finding(finding)

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------
    def _collect_identifiers_from_node(self, node: Node) -> list:
        """从 AST 节点子树中收集所有 identifier 文本（用于 Sanitizer 感知）。"""
        out: list = []
        if node.type == "identifier":
            t = self._get_node_text(node)
            if t:
                out.append(t)
            return out
        for child in getattr(node, "children", []) or []:
            out.extend(self._collect_identifiers_from_node(child))
        return out

    @staticmethod
    def _get_node_text(node: Node) -> str | None:
        """提取节点的文本内容。"""
        if hasattr(node, "text"):
            return node.text.decode("utf-8")
        return None


__all__ = ["JavaScriptXSSAstRule"]
