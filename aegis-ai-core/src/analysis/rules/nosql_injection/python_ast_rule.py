"""
nosql_injection.python_ast_rule

Python NoSQL 注入 AST 规则（pymongo / motor）。

检测目标：
- pymongo / motor 的 find / find_one / update / delete / aggregate 等
  使用 request.json / request.form / request.data / request.POST 等作为查询条件，
  存在 $where / $ne / $regex 等操作符注入风险。

Source: Flask request.json, request.form；Django request.data, request.POST。
Sink: pymongo 的 find, find_one, update, update_one, update_many, delete_one, delete_many, aggregate；
      motor 异步版本同上。
净化: bson.ObjectId()、类型校验（isinstance）、白名单字段过滤。
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List

from ...base import AnalysisContext, SecurityRule


# ── 用户输入属性（Flask / Django）────────────────────────────────────
_USER_INPUT_OBJS = frozenset(["request", "req"])
_USER_INPUT_ATTRS = frozenset([
    "json", "form", "data", "values", "GET", "POST", "FILES",
    "params", "query_params", "args", "cookies", "headers",
])

# ── pymongo / motor 查询与更新方法（sink）────────────────────────────
_MONGO_SINK_METHODS = frozenset([
    "find", "find_one", "update", "update_one", "update_many",
    "delete_one", "delete_many", "aggregate", "count_documents",
    "find_one_and_update", "find_one_and_delete", "find_one_and_replace",
    "replace_one", "bulk_write",
])


def _collect_names(node: ast.AST) -> List[str]:
    """从节点子树收集所有 Name.id。"""
    return [n.id for n in ast.walk(node) if isinstance(n, ast.Name)]


def _is_user_input_node(node: ast.AST, context: AnalysisContext | None = None) -> bool:
    """
    判断节点是否来自用户输入（污点 + 结构化匹配）。
    """
    if context is not None:
        names = _collect_names(node)
        if names and any(context.is_var_tainted(n) for n in names):
            return True
        if names and all(context.has_tracked_var(n) for n in names):
            return False
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name) and node.value.id in _USER_INPUT_OBJS:
            if node.attr in _USER_INPUT_ATTRS:
                return True
    if isinstance(node, ast.Subscript):
        return _is_user_input_node(node.value, context)
    if isinstance(node, ast.Call):
        return _is_user_input_node(node.func, context)
    return False


def _is_objectid_call(node: ast.AST) -> bool:
    """判断是否为 ObjectId(...) 调用。"""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == "ObjectId"
    if isinstance(func, ast.Attribute):
        return func.attr == "ObjectId"
    return False


def _is_sanitized_node(node: ast.AST) -> bool:
    """
    判断是否经过常见净化（bson.ObjectId、类型校验等）。
    """
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr == "ObjectId":
                return True
            if func.attr == "isinstance":
                return True
        if isinstance(func, ast.Name):
            if func.id in ("ObjectId", "isinstance"):
                return True
    return False


class PythonNoSQLInjectionAstRule(SecurityRule):
    """
    基于 Python AST 的 NoSQL 注入检测规则（pymongo / motor）。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="NOSQL_INJECTION_PY_AST",
            severity="High",
            languages=["python"],
        )

    def before_file(self, context: AnalysisContext) -> None:
        """预扫描赋值：Source 变量标记到 DataFlowTracker；ObjectId(x) 赋值的变量记入 extras。"""
        source = context.extras.get("source", "")
        if not source:
            return
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return
        objectid_vars: set[str] = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and len(n.targets) == 1:
                target = n.targets[0]
                if isinstance(target, ast.Name) and _is_objectid_call(n.value):
                    objectid_vars.add(target.id)
        if objectid_vars:
            context.extras["objectid_vars"] = context.extras.get("objectid_vars", set()) | objectid_vars
        if context.taint_graph is not None:
            return
        if not context.dataflow_tracker:
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
        """检测 pymongo/motor 方法调用中查询参数来自用户输入。"""
        if not isinstance(node, ast.Call):
            return
        func = node.func
        if not isinstance(func, ast.Attribute):
            return
        method_name = func.attr
        if method_name not in _MONGO_SINK_METHODS:
            return
        args = node.args
        if not args:
            return
        query_arg = args[0]
        if _is_sanitized_node(query_arg):
            return
        # Dict 查询且仅 _id 且值为 ObjectId 赋值的变量（如 {"_id": oid}，oid = ObjectId(uid)）
        objectid_vars = context.extras.get("objectid_vars") or set()
        if isinstance(query_arg, ast.Dict) and objectid_vars:
            keys_vals = list(zip(query_arg.keys, query_arg.values))
            if len(keys_vals) == 1 and isinstance(keys_vals[0][0], ast.Constant) and keys_vals[0][0].value == "_id":
                v = keys_vals[0][1]
                if isinstance(v, ast.Name) and v.id in objectid_vars:
                    return
        names = _collect_names(query_arg)
        if context is not None and names and all(context.is_var_sanitized(n) for n in names):
            return
        if _is_user_input_node(query_arg, context):
            line_no = getattr(node, "lineno", 0)
            finding: Dict[str, Any] = {
                "type": "NOSQL_INJECTION",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": (
                    f"pymongo/motor 方法 {method_name}() 的查询参数来自用户输入（如 request.json），"
                    "可能存在 NoSQL 注入（$where/$ne/$regex 等）。建议使用 bson.ObjectId 或白名单字段过滤。"
                ),
            }
            context.add_finding(finding)


__all__ = ["PythonNoSQLInjectionAstRule"]
