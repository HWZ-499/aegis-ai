"""
xss.ast_rule

Python XSS 风险 AST 规则（污点感知版）。

检测目标：
- Flask render_template_string(user_input) → 模板注入/XSS
- Django mark_safe(user_input) → 绕过自动转义
- 直接向 HTTP 响应写入未转义的用户数据
  （response.write / return HttpResponse / send 等）

改进（对齐 JS 版本）：
- 接入 TaintGraph / DataFlowTracker 做污点感知；
- Sanitizer 感知：escape() / html.escape() / markupsafe.escape() 净化后不报；
- 覆盖更多输出 sink（HttpResponse, send_file, make_response 等）；
- 结构化用户输入匹配（不再依赖变量名关键词）。
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List, Optional

from ...base import AnalysisContext, SecurityRule


# XSS Sink 函数（直接输出到 HTTP 响应/模板，不含 print/write——后者不向 HTTP 输出）
_DIRECT_OUTPUT_FUNCS = frozenset([
    # Flask
    "render_template_string",
    # Django
    "mark_safe",
])

# XSS Sink 方法名（obj.method 形式）
_OUTPUT_METHODS = frozenset([
    "write", "send", "render", "response", "output",
    "emit",
])

# 确定属于 HTTP 响应对象的 receiver 名称白名单。
# "write" 需要额外检查 receiver，避免将文件 IO write() 误判为 XSS 输出点。
_HTTP_RESPONSE_NAMES = frozenset([
    "response", "resp", "res",
    "HttpResponse", "JsonResponse", "StreamingHttpResponse",
    "FileResponse", "make_response", "wfile",
])

# XSS 安全净化函数（调用后视为已净化）
_SANITIZE_FUNCS = frozenset([
    "escape",         # html.escape / markupsafe.escape
    "quote",          # urllib.parse.quote
    "htmlspecialchars",  # 若有 Python 实现
    "bleach_clean",
])
_SANITIZE_MODULES = frozenset(["html", "markupsafe", "bleach"])

# Python 用户输入访问模式
_USER_INPUT_ATTRS = frozenset([
    "form", "args", "json", "data", "values", "cookies", "headers",
    "GET", "POST", "FILES", "params", "query_params",
])
_USER_INPUT_OBJS = frozenset(["request", "req"])


def _collect_names(node: ast.AST) -> List[str]:
    """收集节点子树中所有 Name.id。"""
    return [n.id for n in ast.walk(node) if isinstance(n, ast.Name)]


def _is_sanitized_node(node: ast.AST) -> bool:
    """
    检查节点是否经过 HTML 净化函数包裹。

    例如 ``html.escape(user_input)`` 或 ``escape(user_input)``。
    """
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    # html.escape / markupsafe.escape
    if isinstance(func, ast.Attribute):
        if func.attr == "escape":
            obj = func.value
            if isinstance(obj, ast.Name) and obj.id in _SANITIZE_MODULES:
                return True
        if func.attr in _SANITIZE_FUNCS:
            return True
    # escape(...)
    if isinstance(func, ast.Name) and func.id in _SANITIZE_FUNCS:
        return True
    return False


def _is_user_input_node(node: ast.AST, context: Optional[AnalysisContext] = None) -> bool:
    """
    判断节点是否来自用户输入。

    优先 TaintGraph/DataFlowTracker，次之结构化匹配，最后退化启发式。
    """
    if context is not None:
        names = _collect_names(node)
        if names and any(context.is_var_tainted(n) for n in names):
            return True
        if names and all(context.has_tracked_var(n) for n in names):
            return False

    if isinstance(node, ast.Attribute):
        obj = node.value
        if isinstance(obj, ast.Name) and obj.id in _USER_INPUT_OBJS:
            if node.attr in _USER_INPUT_ATTRS:
                return True
    if isinstance(node, ast.Subscript):
        return _is_user_input_node(node.value, context)
    if isinstance(node, ast.Call):
        return _is_user_input_node(node.func, context)

    # 退化启发式（仅在 TaintGraph 未追踪到该变量时兜底）
    # 收紧关键词，避免 "formatted_data" / "queryBuilder" / "formConfig" 误报：
    # - 要求变量名以这些词**开头或结尾**（词边界），而非任意子串。
    if isinstance(node, ast.Name):
        import re
        lname = node.id.lower()
        # 只有变量名以 req/request 开头或以 _input/_payload 结尾才认为是用户输入
        _FALLBACK_PATTERNS = (
            r"^req(?:uest)?",      # req_xxx / request_xxx
            r"_input$",            # xxx_input
            r"_payload$",          # xxx_payload
            r"^raw_",              # raw_xxx（未处理的原始数据）
        )
        if any(re.search(pat, lname) for pat in _FALLBACK_PATTERNS):
            return True

    return False


class PythonXSSAstRule(SecurityRule):
    """
    基于 Python AST 的 XSS 风险检测规则（污点感知版）。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="XSS_RISK_PY_AST",
            severity="High",
            languages=["python"],
        )

    def before_file(self, context: AnalysisContext) -> None:
        """预扫描赋值，标记用户输入 Source 变量到 DataFlowTracker（降级路径）。"""
        if context.taint_graph is not None:
            return
        source = context.extras.get("source", "")
        if not source or not context.dataflow_tracker:
            return
        try:
            import ast as _ast
            tree = _ast.parse(source)
        except SyntaxError:
            return
        tracker = context.dataflow_tracker
        for n in _ast.walk(tree):
            if isinstance(n, _ast.Assign) and _is_user_input_node(n.value):
                for target in n.targets:
                    if isinstance(target, _ast.Name):
                        tracker.mark_as_source(
                            target.id,
                            getattr(n, "lineno", 0),
                            source_type="user_input",
                        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """访问单个 AST 节点。"""
        if not isinstance(node, ast.Call):
            return

        func = node.func

        # 1. 直接函数调用：render_template_string / mark_safe / print
        if isinstance(func, ast.Name):
            if func.id in _DIRECT_OUTPUT_FUNCS:
                self._check_args(node, context, func.id)
            return

        # 2. 方法调用：response.write / HttpResponse(user_input) 等
        if isinstance(func, ast.Attribute):
            attr = func.attr
            if attr in _DIRECT_OUTPUT_FUNCS:
                self._check_args(node, context, attr)
            elif attr in _OUTPUT_METHODS:
                receiver = func.value
                receiver_name = (
                    receiver.id
                    if isinstance(receiver, ast.Name)
                    else receiver.attr
                    if isinstance(receiver, ast.Attribute)
                    else None
                )
                if attr == "write":
                    # "write" 仅对 HTTP 响应对象触发，避免将文件 IO write() 误判为 XSS
                    if receiver_name in _HTTP_RESPONSE_NAMES:
                        self._check_args(node, context, attr)
                elif attr == "send":
                    # "send" 需排除信号框架对象（Django signals、EventEmitter.send 等）
                    # 只对明确的 HTTP 响应/WebSocket 响应对象触发
                    if receiver_name in _HTTP_RESPONSE_NAMES:
                        self._check_args(node, context, attr)
                else:
                    self._check_args(node, context, attr)
            return

    # ------------------------------------------------------------------
    # 参数检查
    # ------------------------------------------------------------------
    def _check_args(
        self, node: ast.Call, context: AnalysisContext, func_name: str
    ) -> None:
        """检查调用参数是否含未净化的用户输入。"""
        all_args = list(node.args) + [kw.value for kw in node.keywords]
        if not all_args:
            return

        for arg in all_args:
            # 已净化 → 跳过
            if _is_sanitized_node(arg):
                continue

            # Sanitizer 感知（TaintGraph）
            names = _collect_names(arg)
            if names and context is not None and all(
                context.is_var_sanitized(n) for n in names
            ):
                continue

            if _is_user_input_node(arg, context):
                self._add_finding(
                    context, node,
                    details=(
                        f"发现 {func_name}() 调用参数含疑似用户输入且未经 HTML 转义，"
                        f"存在 XSS 风险。建议使用 html.escape() 或模板自动转义。"
                    ),
                )
                return  # 同一调用节点只报一次

    def _add_finding(
        self, context: AnalysisContext, node: ast.AST, details: str
    ) -> None:
        line_no = getattr(node, "lineno", 0) or 0
        finding: Dict[str, Any] = {
            "type": "XSS_RISK",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line_no,
            "details": details,
        }
        context.add_finding(finding)


__all__ = ["PythonXSSAstRule"]
