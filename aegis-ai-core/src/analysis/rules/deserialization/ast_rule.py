"""
deserialization.ast_rule

Python 反序列化风险 AST 规则（污点感知版）。

检测目标：
- ``pickle.loads(user_input)``                    → Critical
- ``pickle.load(f)`` 当 f 来自用户控制路径         → Critical
- ``marshal.loads(user_input)``                   → Critical
- ``shelve.open(user_input)``                     → High
- ``yaml.load(user_input)``                       → High（unsafe Loader）
- ``yaml.safe_load(user_input)``                  → Low（提示仍然检查数据来源）
- ``jsonpickle.decode(user_input)``               → Critical
- ``dill.loads(user_input)``                      → Critical
- 直接 ``eval(user_input)`` / ``exec(user_input)`` → Critical（反序列化场景常见）

改进（对齐 JS 版本）：
- 接入 DataFlowTracker / TaintGraph 做污点感知；
- ``before_file`` 预扫描赋值，标记 Source 变量；
- Sanitizer 感知：允许 ``json.loads`` 场景降级到 Low；
- 每个 Sink 携带独立的 severity / CWE 信息。
"""

from __future__ import annotations

import ast
from typing import Any, NamedTuple

from ...base import AnalysisContext, SecurityRule


# ── 反序列化 Sink 定义 ─────────────────────────────────────────────
class _SinkDef(NamedTuple):
    module: str | None  # None = 全局函数
    func: str
    severity: str  # Critical / High / Low
    detail: str
    cwe: str


_SINKS: list[_SinkDef] = [
    _SinkDef(
        "pickle",
        "loads",
        "Critical",
        "pickle.loads() 对不可信数据执行反序列化，可导致任意代码执行（RCE）。"
        "建议使用 JSON 替代，或在可信边界内使用 hmac 签名验证。",
        "CWE-502",
    ),
    _SinkDef("pickle", "load", "Critical", "pickle.load() 可能加载不可信文件流，导致任意代码执行。", "CWE-502"),
    _SinkDef(
        "marshal", "loads", "Critical", "marshal.loads() 不验证数据来源，反序列化不可信数据可导致 RCE。", "CWE-502"
    ),
    _SinkDef("marshal", "load", "Critical", "marshal.load() 存在不可信数据反序列化风险。", "CWE-502"),
    _SinkDef("dill", "loads", "Critical", "dill.loads() 与 pickle 等效，反序列化不可信数据可导致 RCE。", "CWE-502"),
    _SinkDef("dill", "load", "Critical", "dill.load() 反序列化不可信数据，存在 RCE 风险。", "CWE-502"),
    _SinkDef(
        "jsonpickle",
        "decode",
        "Critical",
        "jsonpickle.decode() 支持 Python 对象序列化，对不可信数据反序列化等同于 pickle。",
        "CWE-502",
    ),
    _SinkDef(
        "shelve", "open", "High", "shelve.open() 使用 pickle 作为后端，路径参数来自用户输入存在安全风险。", "CWE-502"
    ),
    _SinkDef(
        "yaml",
        "load",
        "High",
        "yaml.load() 未指定安全 Loader 时可执行任意代码。"
        "建议使用 yaml.safe_load() 或 yaml.load(data, Loader=yaml.SafeLoader)。",
        "CWE-502",
    ),
    _SinkDef("yaml", "safe_load", "Low", "yaml.safe_load() 参数来自用户输入，建议验证数据来源。", "CWE-20"),
    _SinkDef(None, "eval", "Critical", "eval() 执行用户输入内容，等同于任意代码执行。", "CWE-95"),
    _SinkDef(None, "exec", "Critical", "exec() 执行用户输入内容，等同于任意代码执行。", "CWE-95"),
]

# 按 (module, func) 索引快速查找
_SINK_INDEX: dict[tuple[str | None, str], _SinkDef] = {(s.module, s.func): s for s in _SINKS}

# Python 用户输入结构化模式
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
        "body",
    ]
)
_USER_INPUT_OBJS = frozenset(["request", "req"])


def _collect_names(node: ast.AST) -> list[str]:
    """收集节点子树中所有 Name.id。"""
    return [n.id for n in ast.walk(node) if isinstance(n, ast.Name)]


def _is_user_input_node(node: ast.AST, context: AnalysisContext | None = None) -> bool:
    """
    判断节点是否来自用户输入。

    优先 TaintGraph → 结构化匹配 → 退化启发式。
    """
    if context is not None:
        names = _collect_names(node)
        if names and any(context.is_var_tainted(n) for n in names):
            return True
        if names and all(context.has_tracked_var(n) for n in names):
            return False

    # 结构化匹配：request.form['key'] 等
    if isinstance(node, ast.Attribute):
        obj = node.value
        if isinstance(obj, ast.Name) and obj.id in _USER_INPUT_OBJS:
            if node.attr in _USER_INPUT_ATTRS:
                return True
    if isinstance(node, ast.Subscript):
        return _is_user_input_node(node.value, context)
    if isinstance(node, ast.Call):
        return _is_user_input_node(node.func, context)

    # 退化启发式（最后兜底）
    if isinstance(node, ast.Name):
        lname = node.id.lower()
        for kw in (
            "user",
            "input",
            "request",
            "param",
            "arg",
            "query",
            "form",
            "data",
            "body",
            "payload",
            "untrusted",
            "raw",
        ):
            if kw in lname:
                return True
    return False


class PythonDeserializationAstRule(SecurityRule):
    """
    基于 Python AST 的反序列化风险检测规则（污点感知版）。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="DESERIALIZATION_PY_AST",
            severity="High",  # 默认；实际由 _SinkDef 覆盖
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
            tree = ast.parse(source)
        except SyntaxError:
            return
        tracker = context.dataflow_tracker
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and _is_user_input_node(n.value):
                for target in n.targets:
                    if isinstance(target, ast.Name):
                        tracker.mark_as_source(
                            target.id,
                            getattr(n, "lineno", 0),
                            source_type="user_input",
                        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """仅关心函数调用节点。"""
        if not isinstance(node, ast.Call):
            return

        module, func_name = self._extract_module_func(node)
        if func_name is None:
            return

        sink = _SINK_INDEX.get((module, func_name))
        if sink is None and module is not None:
            # 也尝试 (None, func_name) 全局函数
            sink = _SINK_INDEX.get((None, func_name))
        if sink is None:
            return

        if not node.args:
            return

        first_arg = node.args[0]

        # 特殊：eval/exec 永远报告（无论参数来源）
        if func_name in ("eval", "exec"):
            if not _is_user_input_node(first_arg, context):
                return
            self._report(node, context, sink)
            return

        if not _is_user_input_node(first_arg, context):
            return

        # Sanitizer 感知：被标记为已净化的变量降级到 Low
        actual_severity = sink.severity
        names = _collect_names(first_arg)
        if names and any(context.is_var_sanitized(n) for n in names):
            actual_severity = "Low"

        self._report(node, context, sink, severity_override=actual_severity)

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_module_func(
        node: ast.Call,
    ) -> tuple[str | None, str | None]:
        """提取 (module, func_name) 对，例如 pickle.loads → ('pickle', 'loads')。"""
        func = node.func
        if isinstance(func, ast.Name):
            return None, func.id
        if isinstance(func, ast.Attribute):
            obj = func.value
            module = getattr(obj, "id", None)
            return module, func.attr
        return None, None

    def _report(
        self,
        node: ast.AST,
        context: AnalysisContext,
        sink: _SinkDef,
        severity_override: str | None = None,
    ) -> None:
        line_no = getattr(node, "lineno", 0) or 0
        finding: dict[str, Any] = {
            "type": "DESERIALIZATION",
            "rule_id": self.rule_id,
            "severity": severity_override or sink.severity,
            "line": line_no,
            "details": sink.detail,
            "cwe": sink.cwe,
        }
        context.add_finding(finding)


__all__ = ["PythonDeserializationAstRule"]
