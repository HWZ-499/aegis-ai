"""
deserialization.go_ast_rule

Go 反序列化风险 AST/污点规则。

检测目标：
1. Tree-sitter AST 节点级分析（visit）：
   - gob.NewDecoder(userInput).Decode(...) — 用户可控 reader 传入 gob 解码器
   - json.Unmarshal(userInput, ...) — 仅当第一个参数来自网络读取时报告
   - yaml.Unmarshal(userInput, ...) — 更危险，用户输入即报告
   - xml.Unmarshal(userInput, ...) — XXE 风险
2. TaintGraph 路径分析（after_file，兜底）。
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

# 高风险 Unmarshal — 用户输入即报告
_HIGH_RISK_UNMARSHAL_PKGS = frozenset(["yaml", "xml"])

# 中风险 Unmarshal — 仅当来源为网络读取时报告
_MEDIUM_RISK_UNMARSHAL_PKGS = frozenset(["json"])

# 网络读取指标（用于 json.Unmarshal 误报过滤）
_NETWORK_READ_INDICATORS = frozenset(
    [
        "ReadAll",
        "ReadBody",
        "r.Body",
        "req.Body",
        "request.Body",
        "ioutil.ReadAll",
        "io.ReadAll",
        "httputil.DumpRequest",
    ]
)

# 反序列化安全措施（sanitizer 关键词）
_SANITIZERS = frozenset(
    [
        "Validate",
        "validate",
        "sanitize",
        "Sanitize",
        "Schema",
        "schema",
    ]
)


class GoDeserializationAstRule(SecurityRule):
    """
    基于 Tree-sitter AST + TaintGraph 的 Go 反序列化风险检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="DESERIALIZATION_GO_TAINT",
            severity="High",
            languages=["go"],
        )
        self._reported_lines: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported_lines = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        if node.type == "call_expression":
            self._check_call_expression(node, context)

    # ------------------------------------------------------------------
    # visit 阶段检测逻辑
    # ------------------------------------------------------------------

    def _check_call_expression(self, node: Any, context: AnalysisContext) -> None:
        """分发反序列化 API 调用检测。"""
        func_name, pkg_name = self._get_qualified_name(node)
        if func_name is None:
            return

        # Case 1: yaml.Unmarshal / xml.Unmarshal — 高风险
        if func_name == "Unmarshal" and pkg_name in _HIGH_RISK_UNMARSHAL_PKGS:
            self._check_high_risk_unmarshal(node, context, pkg_name)
            return

        # Case 2: json.Unmarshal — 中风险，需额外检查网络来源
        if func_name == "Unmarshal" and pkg_name in _MEDIUM_RISK_UNMARSHAL_PKGS:
            self._check_json_unmarshal(node, context)
            return

        # Case 3: gob.NewDecoder(userInput).Decode(...) — 检测链式调用
        if func_name == "Decode":
            self._check_gob_decode(node, context)
            return

    def _check_high_risk_unmarshal(
        self,
        node: Any,
        context: AnalysisContext,
        pkg_name: str | None,
    ) -> None:
        """检测 yaml.Unmarshal(userInput, ...) / xml.Unmarshal(userInput, ...) 等高风险调用。"""
        args = self._get_arguments(node)
        if not args:
            return

        first_arg = args[0]
        if not self._subtree_has_user_input(first_arg, context):
            return

        # Sanitizer 感知
        identifiers = self._collect_identifiers(first_arg)
        if identifiers and (context.taint_graph or context.dataflow_tracker):
            if all(context.is_var_sanitized(v) for v in identifiers):
                return

        display = f"{pkg_name}.Unmarshal" if pkg_name else "Unmarshal"
        self._report(node, context, display)

    def _check_json_unmarshal(self, node: Any, context: AnalysisContext) -> None:
        """
        检测 json.Unmarshal(userInput, ...) — 仅当第一个参数来自网络读取时报告。

        json.Unmarshal 非常常见，因此需要额外检查：
        - 参数直接匹配用户输入模式（如 r.Body）；
        - 或参数文本包含网络读取指标（如 ioutil.ReadAll）；
        - 或 DataFlowTracker 已将变量标记为 tainted。
        """
        args = self._get_arguments(node)
        if not args:
            return

        first_arg = args[0]
        first_arg_text = self._get_node_text(first_arg) or ""

        # 方式 1：通过结构化检测（is_user_input_node / DataFlowTracker）识别
        is_user_controlled = self._subtree_has_user_input(first_arg, context)

        # 方式 2：文本中包含网络读取指标
        has_network_indicator = any(ind in first_arg_text for ind in _NETWORK_READ_INDICATORS)

        if not is_user_controlled and not has_network_indicator:
            return

        # Sanitizer 感知
        identifiers = self._collect_identifiers(first_arg)
        if identifiers and (context.taint_graph or context.dataflow_tracker):
            if all(context.is_var_sanitized(v) for v in identifiers):
                return

        self._report(node, context, "json.Unmarshal")

    def _check_gob_decode(self, node: Any, context: AnalysisContext) -> None:
        """
        检测 gob.NewDecoder(userInput).Decode(...) 模式。

        在 tree-sitter AST 中，链式调用的结构为：
        call_expression                         # .Decode(&msg)
          selector_expression
            call_expression                     # gob.NewDecoder(r.Body)
              selector_expression
                identifier: gob
                field_identifier: NewDecoder
              argument_list: (r.Body)
            field_identifier: Decode
          argument_list: (&msg)
        """
        for child in node.children:
            if child.type != "selector_expression":
                continue

            # 在 selector_expression 中查找内层 call_expression（即 gob.NewDecoder(...)）
            inner_call = None
            for sub in child.children:
                if sub.type == "call_expression":
                    inner_call = sub
                    break

            if inner_call is None:
                continue

            # 检查内层调用是否为 gob.NewDecoder
            inner_func, inner_pkg = self._get_qualified_name(inner_call)
            if inner_func != "NewDecoder" or inner_pkg != "gob":
                continue

            # 检查 NewDecoder 的参数是否包含用户输入
            inner_args = self._get_arguments(inner_call)
            for arg in inner_args:
                if self._subtree_has_user_input(arg, context):
                    # Sanitizer 感知
                    identifiers = self._collect_identifiers(arg)
                    if identifiers and (context.taint_graph or context.dataflow_tracker):
                        if all(context.is_var_sanitized(v) for v in identifiers):
                            return

                    self._report(node, context, "gob.NewDecoder.Decode")
                    return

    # ------------------------------------------------------------------
    # after_file: TaintGraph 兜底
    # ------------------------------------------------------------------

    def after_file(self, context: AnalysisContext) -> None:
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
            if category != "deserialization":
                continue

            line_no = getattr(sink, "line", 0) or 0
            # 跳过 visit 阶段已报告的行
            if line_no in self._reported_lines:
                continue

            reported_sinks.add(sink_id)

            src_expr = getattr(source, "name", "") or getattr(source, "code_snippet", "")
            sink_expr = getattr(sink, "name", "") or getattr(sink, "code_snippet", "")

            details = (
                "检测到 Go 代码中对不可信数据执行反序列化，建议在反序列化前对输入进行严格验证，或使用结构体字段白名单。"
            )

            finding: dict[str, Any] = {
                "type": "DESERIALIZATION",
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
    def _get_qualified_name(node: Any) -> tuple[str | None, str | None]:
        """从 call_expression 提取 (函数名, 包名)。"""
        for child in node.children:
            if child.type == "selector_expression":
                parts = []
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
        for child in node.children:
            if child.type == "argument_list":
                return [c for c in child.children if c.type not in ("(", ")", ",")]
        return []

    def _subtree_has_user_input(self, node: Any, context: AnalysisContext) -> bool:
        if is_user_input_node(node, context, language="go"):
            return True
        for child in getattr(node, "children", []) or []:
            if self._subtree_has_user_input(child, context):
                return True
        return False

    def _collect_identifiers(self, node: Any) -> list[str]:
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
        self._reported_lines.add(line)
        finding: dict[str, Any] = {
            "type": "DESERIALIZATION",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line,
            "details": (
                f"检测到 {func_desc}() 调用中包含用户可控输入，"
                "存在不安全的反序列化风险，建议对输入进行严格验证或使用结构体字段白名单。"
            ),
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)


__all__ = ["GoDeserializationAstRule"]
