"""
js_dataflow_collector.py - JavaScript/TypeScript 数据流收集器（阶段二增强版）

在 AST 遍历时自动收集变量赋值信息，用于污点分析。

新增功能（阶段二）：
- Express / Koa 路由回调识别：``app.get('/x', (req, res) => {...})``
  → ``req`` 参数自动标记为 Source
- 解构赋值追踪：``const { name, email } = req.body``
  → ``name`` / ``email`` 继承 ``req.body`` 的污点
- Sanitizer 调用检测：``const safe = parseInt(tainted)``
  → ``safe`` 标记为已净化

设计：
- 作为 SecurityRule 的子类，在规则引擎遍历 AST 时自动调用
- 不产生 findings，只向 ``context.dataflow_tracker`` 注入信息
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .security_rule import SecurityRule
from .analysis_context import AnalysisContext

# Tree-sitter Node 类型
try:
    from tree_sitter import Node
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any  # type: ignore[misc,assignment]

# Express / Koa 路由方法
_ROUTE_METHODS = {
    "get", "post", "put", "delete", "patch", "all", "use",
    "options", "head",
}

# 可能是 Express app / router 的对象名
_ROUTE_OBJECTS = {
    "app", "router", "route", "server",
}


class JavaScriptDataFlowCollector(SecurityRule):
    """
    JavaScript/TypeScript 数据流收集器（阶段二增强版）。

    功能：
    - 收集变量声明（const / let / var）
    - 收集赋值表达式
    - 识别 Express 路由回调，标记 ``req`` 为 Source
    - 追踪解构赋值的属性继承
    - 将所有信息存储到 ``context.dataflow_tracker``
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="DATAFLOW_COLLECTOR_JS",
            severity="Info",
            languages=["javascript", "typescript"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """访问 AST 节点，收集数据流信息。"""
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        # ── 变量声明（含解构） ──
        if node.type in ("variable_declaration", "lexical_declaration"):
            self._collect_variable_declaration(node, context)

        # ── 赋值表达式 ──
        elif node.type == "assignment_expression":
            self._collect_assignment(node, context)

        # ── Express 路由回调 ──
        elif node.type == "call_expression":
            self._check_route_handler(node, context)

    # ──────────────────────────────────────────────
    # 变量声明收集
    # ──────────────────────────────────────────────

    def _collect_variable_declaration(self, node: Node, context: AnalysisContext) -> None:
        """
        收集变量声明，包括普通赋值和解构赋值。

        普通：``const userId = req.body.userId``
        解构：``const { name, email } = req.body``
        """
        for child in node.children:
            if child.type != "variable_declarator":
                continue

            # 找到左侧和右侧
            left_node = None
            value_node = None
            for subchild in child.children:
                if subchild.type == "identifier":
                    left_node = subchild
                elif subchild.type == "object_pattern":
                    left_node = subchild  # 解构模式
                elif subchild.type == "array_pattern":
                    left_node = subchild
                elif subchild.type not in ("=",):
                    value_node = subchild

            if left_node is None or value_node is None:
                continue

            line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0

            # ── 解构赋值：object_pattern ──
            if left_node.type == "object_pattern":
                props = self._extract_destructured_properties(left_node)
                value_text = self._get_node_text(value_node) or ""
                if props and context.dataflow_tracker:
                    context.dataflow_tracker.track_destructuring(props, value_text, line)

            # ── 普通赋值 ──
            elif left_node.type == "identifier":
                var_name = self._get_node_text(left_node)
                value_text = self._get_node_text(value_node)
                if var_name and value_text:
                    context.track_assignment(var_name, value_text, line)

    def _extract_destructured_properties(self, pattern_node: Node) -> List[str]:
        """
        从 object_pattern 节点提取属性名。

        ``{ name, email, age: userAge }`` → ``["name", "email", "userAge"]``
        """
        props: List[str] = []
        for child in pattern_node.children:
            if child.type == "shorthand_property_identifier_pattern":
                # { name } → name
                name = self._get_node_text(child)
                if name:
                    props.append(name)
            elif child.type == "pair_pattern":
                # { age: userAge } → userAge（取 value 部分）
                for subchild in child.children:
                    if subchild.type == "identifier":
                        name = self._get_node_text(subchild)
                        if name:
                            props.append(name)
                            break  # 只取第一个 identifier 作为 value
        return props

    # ──────────────────────────────────────────────
    # 赋值表达式收集
    # ──────────────────────────────────────────────

    def _collect_assignment(self, node: Node, context: AnalysisContext) -> None:
        """收集赋值表达式。"""
        left_node = None
        right_node = None

        for child in node.children:
            if child.type == "identifier":
                left_node = child
            elif child.type == "member_expression":
                for subchild in child.children:
                    if subchild.type == "property_identifier":
                        left_node = subchild
            elif child.type not in ("=",):
                right_node = child

        if left_node and right_node:
            var_name = self._get_node_text(left_node)
            value_expr = self._get_node_text(right_node)
            if var_name and value_expr:
                line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
                context.track_assignment(var_name, value_expr, line)

    # ──────────────────────────────────────────────
    # Express 路由回调识别
    # ──────────────────────────────────────────────

    def _check_route_handler(self, node: Node, context: AnalysisContext) -> None:
        """
        识别 Express / Koa 路由处理函数。

        模式：
        - ``app.get('/path', (req, res) => { ... })``
        - ``router.post('/api', handler)``
        - ``app.use(middleware)``

        识别后将回调函数的第一个参数（通常是 ``req``）标记为 Source。
        """
        # 提取 callee 信息
        method_name = None
        object_name = None

        for child in node.children:
            if child.type == "member_expression":
                for subchild in child.children:
                    if subchild.type == "identifier":
                        object_name = self._get_node_text(subchild)
                    elif subchild.type == "property_identifier":
                        method_name = self._get_node_text(subchild)

        if not method_name or not object_name:
            return

        # 是否是路由注册调用
        if (
            method_name.lower() not in _ROUTE_METHODS
            or object_name.lower() not in _ROUTE_OBJECTS
        ):
            return

        line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0

        # 从 arguments 中找到回调函数
        for child in node.children:
            if child.type != "arguments":
                continue
            for arg in child.children:
                if arg.type in ("arrow_function", "function_expression", "function"):
                    # 提取回调参数
                    req_param = self._extract_first_param(arg)
                    if req_param and context.dataflow_tracker:
                        context.dataflow_tracker.mark_as_source(
                            req_param, line, source_type="express_route_callback"
                        )
                    return

    def _extract_first_param(self, func_node: Node) -> Optional[str]:
        """
        提取函数的第一个参数名。

        ``(req, res) => {...}`` → ``"req"``
        ``function(request, response) {...}`` → ``"request"``
        """
        for child in func_node.children:
            if child.type == "formal_parameters":
                for param in child.children:
                    if param.type == "identifier":
                        return self._get_node_text(param)
                    # 跳过 "(" "," ")"
        return None

    # ──────────────────────────────────────────────
    # 辅助方法
    # ──────────────────────────────────────────────

    @staticmethod
    def _get_node_text(node: Node) -> Optional[str]:
        """提取节点的文本内容。"""
        if hasattr(node, "text"):
            return node.text.decode("utf-8")
        return None


__all__ = ["JavaScriptDataFlowCollector"]
