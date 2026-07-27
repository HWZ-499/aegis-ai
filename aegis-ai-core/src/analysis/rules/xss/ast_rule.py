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
from typing import Any, cast

from ...base import AnalysisContext, SecurityRule

# XSS Sink 函数（直接输出到 HTTP 响应/模板，不含 print/write——后者不向 HTTP 输出）
_DIRECT_OUTPUT_FUNCS = frozenset(
    [
        # Flask
        "render_template_string",
        # Django
        "mark_safe",
    ]
)

_HTTP_RESPONSE_CONSTRUCTORS = frozenset(
    [
        "HttpResponse",
        "JsonResponse",
        "StreamingHttpResponse",
        "FileResponse",
        "make_response",
    ]
)

# XSS Sink 方法名（obj.method 形式）
_OUTPUT_METHODS = frozenset(
    [
        "write",
        "send",
        "render",
        "response",
        "output",
        "emit",
    ]
)

# 确定属于 HTTP 响应对象的 receiver 名称白名单。
# "write" 需要额外检查 receiver，避免将文件 IO write() 误判为 XSS 输出点。
_HTTP_RESPONSE_NAMES = frozenset(
    [
        "response",
        "resp",
        "res",
        "HttpResponse",
        "JsonResponse",
        "StreamingHttpResponse",
        "FileResponse",
        "make_response",
        "wfile",
    ]
)

_HTML_SANITIZER_QUALNAMES = frozenset(
    [
        "html.escape",
        "markupsafe.escape",
        "bleach.clean",
        "cgi.escape",
    ]
)
_HTML_SANITIZER_TAINT_NAMES = frozenset(
    [
        "html_escape_py",
        "markupsafe_escape",
        "bleach_clean",
        "html.escape",
        "markupsafe.escape",
        "bleach.clean",
        "cgi.escape",
    ]
)

# Python 用户输入访问模式
_USER_INPUT_ATTRS = frozenset(
    [
        "form",
        "args",
        "json",
        "data",
        "values",
        "cookies",
        "headers",
        "GET",
        "POST",
        "FILES",
        "params",
        "query_params",
    ]
)
_USER_INPUT_OBJS = frozenset(["request", "req"])


def _collect_names(node: ast.AST) -> list[str]:
    """收集节点子树中所有 Name.id。"""
    return [n.id for n in ast.walk(node) if isinstance(n, ast.Name)]


def _collect_import_aliases(tree: ast.AST) -> tuple[dict[str, str], dict[str, str]]:
    """收集当前文件导入别名，用于区分真实 sanitizer 和同名业务函数。"""
    module_aliases: dict[str, str] = {}
    function_aliases: dict[str, str] = {}

    for child in ast.walk(tree):
        if isinstance(child, ast.Import):
            for alias in child.names:
                local_name = alias.asname or alias.name.split(".", 1)[0]
                module_aliases[local_name] = alias.name
        elif isinstance(child, ast.ImportFrom) and child.module:
            for alias in child.names:
                if alias.name == "*":
                    continue
                local_name = alias.asname or alias.name
                function_aliases[local_name] = f"{child.module}.{alias.name}"

    return module_aliases, function_aliases


def _resolve_name_qualname(name: str, context: AnalysisContext | None = None) -> str:
    if context is None:
        return name
    module_aliases = cast(dict[str, str], context.extras.get("python_xss_module_aliases", {}))
    return module_aliases.get(name, name)


def _resolve_call_qualname(func: ast.AST, context: AnalysisContext | None = None) -> str | None:
    """解析调用目标的限定名，并应用 import alias。"""
    if isinstance(func, ast.Name):
        function_aliases = {}
        if context is not None:
            function_aliases = cast(dict[str, str], context.extras.get("python_xss_function_aliases", {}))
        return function_aliases.get(func.id, func.id)

    if isinstance(func, ast.Attribute):
        base = _resolve_call_qualname(func.value, context)
        if base is None:
            return func.attr
        return f"{base}.{func.attr}"

    return None


def _is_html_sanitized_node(node: ast.AST, context: AnalysisContext | None = None) -> bool:
    """
    检查节点是否经过 HTML 净化函数包裹。

    仅信任明确来自 HTML 安全库的 sanitizer；URL quoting 或任意同名业务方法
    不能证明 HTML 输出上下文安全。
    """
    if not isinstance(node, ast.Call):
        return False
    qualname = _resolve_call_qualname(node.func, context)
    if qualname is None:
        return False

    parts = qualname.split(".")
    if parts:
        parts[0] = _resolve_name_qualname(parts[0], context)
    return ".".join(parts) in _HTML_SANITIZER_QUALNAMES


def _is_context_html_sanitized(node: ast.AST, context: AnalysisContext | None = None) -> bool:
    if context is None or not isinstance(node, ast.Name):
        return False
    if not context.is_var_sanitized(node.id):
        return False
    sanitizer_name = context.get_sanitizer_name(node.id)
    return sanitizer_name in _HTML_SANITIZER_TAINT_NAMES


def _is_http_response_constructor(func: ast.AST, context: AnalysisContext | None = None) -> bool:
    qualname = _resolve_call_qualname(func, context)
    if qualname is None:
        return False
    parts = qualname.split(".")
    if parts:
        parts[0] = _resolve_name_qualname(parts[0], context)
    resolved = ".".join(parts)
    return resolved.rsplit(".", 1)[-1] in _HTTP_RESPONSE_CONSTRUCTORS


def _is_user_input_node(node: ast.AST, context: AnalysisContext | None = None) -> bool:
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
        if _is_user_input_node(node.func, context):
            return True
        return any(_is_user_input_node(arg, context) for arg in node.args) or any(
            _is_user_input_node(kw.value, context) for kw in node.keywords
        )

    # 退化启发式（仅在 TaintGraph 未追踪到该变量时兜底）
    # 收紧关键词，避免 "formatted_data" / "queryBuilder" / "formConfig" 误报：
    # - 要求变量名以这些词**开头或结尾**（词边界），而非任意子串。
    if isinstance(node, ast.Name):
        import re

        lname = node.id.lower()
        # 只有变量名以 req/request 开头或以 _input/_payload 结尾才认为是用户输入
        _FALLBACK_PATTERNS = (
            r"^req(?:uest)?",  # req_xxx / request_xxx
            r"_input$",  # xxx_input
            r"_payload$",  # xxx_payload
            r"^raw_",  # raw_xxx（未处理的原始数据）
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
        source = context.extras.get("source", "")
        parsed_tree: ast.AST | None = None
        module_aliases: dict[str, str] = {}
        function_aliases: dict[str, str] = {}
        if source:
            try:
                parsed_tree = ast.parse(source)
                module_aliases, function_aliases = _collect_import_aliases(parsed_tree)
            except SyntaxError:
                return

        context.extras["python_xss_module_aliases"] = module_aliases
        context.extras["python_xss_function_aliases"] = function_aliases

        if context.taint_graph is not None:
            return
        if parsed_tree is None or not context.dataflow_tracker:
            return
        tracker = context.dataflow_tracker
        for n in ast.walk(parsed_tree):
            if isinstance(n, ast.Assign) and _is_user_input_node(n.value, context):
                for target in n.targets:
                    if isinstance(target, ast.Name):
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
            if func.id in _DIRECT_OUTPUT_FUNCS or _is_http_response_constructor(func, context):
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
    def _check_args(self, node: ast.Call, context: AnalysisContext, func_name: str) -> None:
        """检查调用参数是否含未净化的用户输入。"""
        all_args = list(node.args) + [kw.value for kw in node.keywords]
        if not all_args:
            return

        for arg in all_args:
            # 已净化 → 跳过
            if _is_html_sanitized_node(arg, context):
                continue

            # Sanitizer 感知（TaintGraph）
            if _is_context_html_sanitized(arg, context):
                continue

            if _is_user_input_node(arg, context):
                self._add_finding(
                    context,
                    node,
                    details=(
                        f"发现 {func_name}() 调用参数含疑似用户输入且未经 HTML 转义，"
                        f"存在 XSS 风险。建议使用 html.escape() 或模板自动转义。"
                    ),
                )
                return  # 同一调用节点只报一次

    def _add_finding(self, context: AnalysisContext, node: ast.AST, details: str) -> None:
        line_no = getattr(node, "lineno", 0) or 0
        finding: dict[str, Any] = {
            "type": "XSS_RISK",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line_no,
            "details": details,
        }
        context.add_finding(finding)


__all__ = ["PythonXSSAstRule"]
