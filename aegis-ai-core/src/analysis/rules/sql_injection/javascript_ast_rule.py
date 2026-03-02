"""
sql_injection.javascript_ast_rule

JavaScript/TypeScript SQL 注入 AST 规则（新规则架构）。

检测目标：
- 字符串拼接构造 SQL（.query("..." + var)）
- 模板字符串 SQL（`SELECT ... ${var}`）
- Sequelize/Mongoose ORM 危险用法（字符串拼接在 where 条件中）

说明：
- 使用 Tree-sitter Node（不是 Python ast.AST）；
- 目前先做基础检测，后续可以结合数据流分析做更精确的判断。
"""

from __future__ import annotations

from typing import Any, Dict

from ...base import (
    AnalysisContext,
    SecurityRule,
    is_likely_seed_or_migration,
    make_related_location,
    tree_sitter_node_to_range,
)
from ...base.user_input_detector import is_user_input_node

# Tree-sitter Node 类型（运行时检查）
try:
    from tree_sitter import Node
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any


class JavaScriptSQLInjectionAstRule(SecurityRule):
    """
    基于 Tree-sitter AST 的 JavaScript/TypeScript SQL 注入检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="SQL_INJECTION_JS_AST",
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

        # 1. 检测字符串拼接（binary_expression with +）
        if node.type == "binary_expression":
            self._check_string_concatenation(node, context)

        # 2. 检测模板字符串（template_string）
        elif node.type == "template_string":
            self._check_template_string(node, context)

        # 3. 检测函数调用中的 SQL 拼接（call_expression）
        elif node.type == "call_expression":
            self._check_sql_method_call(node, context)

    # ------------------------------------------------------------------
    # 检测方法
    # ------------------------------------------------------------------
    def _check_string_concatenation(self, node: Node, context: AnalysisContext) -> None:
        """检测字符串拼接形式的 SQL 注入。"""
        # 检查是否是 + 运算符
        operator = None
        left = None
        right = None

        for child in node.children:
            if child.type == "+":
                operator = child
            elif child.type in ("string", "template_string", "identifier", "member_expression"):
                if left is None:
                    left = child
                else:
                    right = child

        if operator is None or left is None or right is None:
            return

        # 检查是否包含 SQL 关键词
        left_text = self._get_node_text(left) or ""
        right_text = self._get_node_text(right) or ""

        sql_keywords = ["select", "insert", "update", "delete", "drop", "create", "alter", "where"]
        has_sql = any(kw in left_text.lower() or kw in right_text.lower() for kw in sql_keywords)

        if not has_sql:
            return

        # 检查是否包含疑似用户输入
        tainted_side = None
        if self._looks_like_user_input(left, context):
            tainted_side = left
        elif self._looks_like_user_input(right, context):
            tainted_side = right

        if tainted_side is None:
            return

        # 【Sanitizer 感知】若污染侧已被 Guard Clause 净化，则不报
        if context.taint_graph or context.dataflow_tracker:
            # 收集涉及的变量/表达式名（member_expression 返回完整路径，如 req.body.id）
            tainted_names = self._collect_identifiers_from_node(tainted_side)
            if tainted_names and all(context.is_var_sanitized(v) for v in tainted_names):
                return

        line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
        finding: Dict[str, Any] = {
            "type": "SQL_INJECTION",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line_no,
            "details": "检测到 SQL 字符串拼接且包含疑似用户输入，存在 SQL 注入风险，建议使用参数化查询。",
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)

    def _check_template_string(self, node: Node, context: AnalysisContext) -> None:
        """检测模板字符串形式的 SQL 注入（`SELECT ... ${var}`）。污点感知 + 种子/迁移文件抑制。"""
        text = self._get_node_text(node) or ""

        sql_keywords = ["select", "insert", "update", "delete", "drop", "create", "alter", "where"]
        has_sql = any(kw in text.lower() for kw in sql_keywords)

        if not has_sql:
            return

        if "${" not in text:
            return

        # 【降低误报】种子/迁移/建表文件中模板 SQL 不报
        if is_likely_seed_or_migration(context.file_path):
            return

        # 【污点感知】若存在 dataflow_tracker 且插值变量均已被追踪，仅当至少一个被污染时报；否则保守报出
        identifiers = self._collect_identifiers_from_node(node)
        if (context.taint_graph or context.dataflow_tracker) and identifiers:
            # 【Sanitizer 感知】若所有插值变量均已被净化（如 parseInt），则不报
            if all(context.is_var_sanitized(v) for v in identifiers):
                return
            if any(context.is_var_tainted(v) for v in identifiers):
                line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
                finding: Dict[str, Any] = {
                    "type": "SQL_INJECTION",
                    "rule_id": self.rule_id,
                    "severity": self.severity,
                    "line": line_no,
                    "details": "检测到模板字符串形式的 SQL 且包含变量插值，存在 SQL 注入风险，建议使用参数化查询。",
                }
                finding.update(tree_sitter_node_to_range(node))
                # TDD 7.1/7.2：污点来源作为 related_locations
                for v in identifiers:
                    taint_source = context.get_taint_source(v)
                    if taint_source and getattr(taint_source, "line", None) is not None:
                        finding["related_locations"] = [
                            make_related_location(
                                str(context.file_path),
                                getattr(taint_source, "line", 0),
                                message=f"SOURCE: {getattr(taint_source, 'source_expr', v)}",
                            )
                        ]
                        break
                context.add_finding(finding)
                return
            # 仅当所有插值变量均已被追踪且均未污染时才抑制（避免单片段/无数据流时漏报）
            if all(context.has_tracked_var(v) for v in identifiers):
                return
        # 无 tracker、无法解析出标识符、或存在未追踪变量时保留原逻辑（保守报出）
        line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
        finding: Dict[str, Any] = {
            "type": "SQL_INJECTION",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line_no,
            "details": "检测到模板字符串形式的 SQL 且包含变量插值，存在 SQL 注入风险，建议使用参数化查询。",
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)

    def _check_sql_method_call(self, node: Node, context: AnalysisContext) -> None:
        """检测 .query() / .find() 等方法调用中的 SQL 拼接。"""
        # 提取方法名
        method_name = None
        for child in node.children:
            if child.type == "member_expression":
                for subchild in child.children:
                    if subchild.type == "property_identifier":
                        method_name = self._get_node_text(subchild)
                        break

        # 覆盖 ORM（find/findOne）与原生 Driver（query/execute，如 mysql、mysql2）
        if method_name not in ("query", "execute", "find", "findOne", "findAll", "findById"):
            return

        # 检查参数中是否有字符串拼接
        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    if arg.type == "binary_expression":
                        # 参数中包含字符串拼接
                        left_text = self._get_node_text(arg.children[0]) if arg.children else ""
                        if any(kw in (left_text or "").lower() for kw in ["select", "where", "insert", "update"]):
                            # 【Sanitizer 感知】检查拼接的右侧是否已被净化
                            if context.taint_graph or context.dataflow_tracker:
                                # 收集整个 binary_expression 中的变量/member_expression
                                rhs_ids = self._collect_identifiers_from_node(arg)
                                if rhs_ids and all(context.is_var_sanitized(v) for v in rhs_ids):
                                    return
                            line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
                            finding: Dict[str, Any] = {
                                "type": "SQL_INJECTION",
                                "rule_id": self.rule_id,
                                "severity": self.severity,
                                "line": line_no,
                                "details": f"检测到 {method_name}() 方法调用中包含 SQL 字符串拼接，存在 SQL 注入风险。",
                            }
                            finding.update(tree_sitter_node_to_range(node))
                            context.add_finding(finding)
                            return

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------
    def _collect_identifiers_from_node(self, node: Node) -> list[str]:
        """
        从 AST 节点子树中收集标识符和 member_expression 文本。

        对 member_expression（如 req.body.id）同时返回完整文本和末端 identifier，
        使净化检查能同时匹配 req.body.id 和 id 两种存储方式。
        """
        out: list[str] = []
        if node.type == "identifier":
            t = self._get_node_text(node)
            if t:
                out.append(t)
            return out
        if node.type == "member_expression":
            # 返回完整表达式（如 req.body.id），供 taint_graph 精确查询
            full = self._get_node_text(node)
            if full:
                out.append(full)
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

    @staticmethod
    def _looks_like_user_input(node: Node, context: "AnalysisContext | None" = None) -> bool:
        """
        判断节点是否来自用户输入（结构化检测）。

        使用 ``is_user_input_node`` 进行精确 AST 匹配，
        不再使用关键词子串模糊搜索。
        """
        return is_user_input_node(node, context, language="javascript")


__all__ = ["JavaScriptSQLInjectionAstRule"]
