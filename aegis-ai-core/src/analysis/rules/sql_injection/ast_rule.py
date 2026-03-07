"""
sql_injection.ast_rule

Python SQL 注入 AST 规则（污点感知版）。

检测目标：
- 字符串拼接构造 SQL：``cursor.execute("SELECT..." + user_input)``
- f-string 构造 SQL：``cursor.execute(f"SELECT...{user_input}")``
- % 格式化构造 SQL：``cursor.execute("SELECT...%s" % user_input)``

改进（对齐 JS 版本）：
- 接入 AnalysisContext.taint_graph / dataflow_tracker 做污点感知；
- 若变量已被追踪且已净化（sanitized），则不报；
- 检测模式覆盖 BinOp(Add)、JoinedStr（f-string）、BinOp(Mod)；
- 参数化查询（?, %s with params tuple）识别并跳过；
- 保守兜底：无 tracker 时仍按启发式报告（高召回）。
"""

from __future__ import annotations

import ast
from typing import Any

from ...base import AnalysisContext, SecurityRule

# SQL 关键词（用于识别 SQL 字符串）
_SQL_KEYWORDS = frozenset(["select", "insert", "update", "delete", "drop", "create", "alter", "where"])

# cursor 方法（sink）
_CURSOR_METHODS = frozenset(["execute", "executemany", "executescript"])

# 明确属于非数据库对象的 receiver 名称（排除误报）。
# 例如：task.execute(cmd)、workflow.execute()，receiver 不是 DB cursor。
_NON_DB_RECEIVERS = frozenset(
    [
        "task",
        "workflow",
        "executor",
        "runner",
        "cmd",
        "command",
        "process",
        "proc",
        "job",
        "handler",
        "action",
        "step",
    ]
)

# Python 用户输入访问模式（结构化，不做子串匹配）
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


def _get_str_value(node: ast.AST) -> str | None:
    """提取字符串节点的文本值。"""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Str):  # Python < 3.8
        return node.s
    return None


def _is_sql_str(node: ast.AST) -> bool:
    """节点是否包含 SQL 关键词。"""
    val = _get_str_value(node)
    if val:
        low = val.lower()
        return any(kw in low for kw in _SQL_KEYWORDS)
    return False


def _is_parameterized(call_node: ast.Call) -> bool:
    """
    判断 cursor.execute(...) 是否使用参数化查询（安全）。

    安全形式：
    - ``execute("SELECT...?", (uid,))``   # sqlite3 / PyMySQL
    - ``execute("SELECT...%s", [uid])``   # psycopg2
    - ``execute("SELECT...%(name)s", d)`` # psycopg2 named
    - 第一个参数是纯字符串字面量（不含拼接/插值）
    """
    args = call_node.args
    if not args:
        return False
    first = args[0]

    # 纯字符串字面量（无插值/拼接）且有第二个参数 → 参数化查询
    first_val = _get_str_value(first)
    if first_val is not None and len(args) >= 2:
        # 含占位符
        if any(ph in first_val for ph in ("?", "%s", "%(", ":")):
            return True

    # 第一个参数就是纯字面量（无用户数据）
    if first_val is not None and len(args) == 1:
        return True

    return False


def _is_sqlalchemy_text_bindparams(node: ast.AST) -> bool:
    """
    判断是否为 SQLAlchemy text(...).bindparams() 安全模式。
    """
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr != "bindparams":
        return False
    inner = func.value
    if not isinstance(inner, ast.Call):
        return False
    inner_func = inner.func
    if isinstance(inner_func, ast.Name) and inner_func.id == "text":
        return True
    if isinstance(inner_func, ast.Attribute) and inner_func.attr == "text":
        return True
    return False


def _collect_names(node: ast.AST) -> list[str]:
    """从节点子树中收集所有 Name.id。"""
    names: list[str] = []
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            names.append(n.id)
    return names


def _is_internal_config_node(node: ast.AST) -> bool:
    """
    判断节点是否为框架内部受控值（self.xxx 属性访问）。

    例如 Django ORM 内部的 ``self._table``、``self.db``、``self.cache_key``
    均来自框架配置，非用户可控输入，应豁免 SQL 注入检测。
    """
    if isinstance(node, ast.Attribute):
        return isinstance(node.value, ast.Name) and node.value.id == "self"
    return False


def _is_user_input_node(node: ast.AST, context: AnalysisContext | None = None) -> bool:
    """
    判断节点是否来自用户输入。

    优先级：
    1. DataFlowTracker / TaintGraph 标记（精确）
    2. 结构化匹配 request.GET / request.args 等（精确）
    3. 退化：变量名启发式（保守）
    """
    # ── 1. 污点追踪器查询 ──
    if context is not None:
        names = _collect_names(node)
        if names and any(context.is_var_tainted(n) for n in names):
            return True
        # 若所有变量均被追踪且均未污染，认为安全
        if names and all(context.has_tracked_var(n) for n in names):
            return False

    # ── 2. 结构化匹配：request.GET['x'] / request.args.get('x') ──
    # Attribute: request.GET → value=Name('request'), attr='GET'
    if isinstance(node, ast.Attribute):
        obj = node.value
        if isinstance(obj, ast.Name) and obj.id in _USER_INPUT_OBJS:
            if node.attr in _USER_INPUT_ATTRS:
                return True
    # Subscript: request.GET['x'] → value=Attribute(request.GET)
    if isinstance(node, ast.Subscript):
        return _is_user_input_node(node.value, context)
    # Call: request.args.get('x') → func=Attribute(request.args, 'get')
    if isinstance(node, ast.Call):
        return _is_user_input_node(node.func, context)

    # ── 3. 退化启发式（变量名关键词） ──
    if isinstance(node, ast.Name):
        lname = node.id.lower()
        for kw in ("uid", "user_id", "user", "query", "param", "input", "data", "payload", "form", "arg"):
            if kw in lname:
                return True

    return False


class PythonSQLInjectionAstRule(SecurityRule):
    """
    基于 Python AST 的 SQL 注入检测规则（污点感知版）。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="SQL_INJECTION_PY_AST",
            severity="High",
            languages=["python"],
        )

    def before_file(self, context: AnalysisContext) -> None:
        """
        文件级初始化：当 taint_graph 不可用时，降级预扫描赋值语句，
        将 Source 变量标记到 DataFlowTracker，使 ``is_var_tainted()`` 能识别
        ``uid = request.GET['id']`` 这类赋值。

        若 taint_graph 已由 PythonAnalyzer 构建，则跳过此步骤
        （TaintAnalyzer 已完成 Source 追踪）。
        """
        # taint_graph 已就绪，TaintAnalyzer 负责 Source 追踪，无需重复处理
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
        """
        检测 Python AST 中的 SQL 注入模式。

        1. Django ORM Model.objects.raw(user_input) → Critical
        2. cursor.execute(...) 参数化 / SQLAlchemy text().bindparams() → 安全
        3. cursor.execute("..." + var) / f-string / % 格式化 → 注入风险
        """
        if not isinstance(node, ast.Call):
            return
        # Django ORM .raw() 使用用户输入 → Critical
        if isinstance(node.func, ast.Attribute) and node.func.attr == "raw" and node.args:
            if _is_user_input_node(node.args[0], context):
                line_no = getattr(node, "lineno", 0) or 0
                context.add_finding(
                    {
                        "type": "SQL_INJECTION",
                        "rule_id": self.rule_id,
                        "severity": "Critical",
                        "line": line_no,
                        "details": "Django Model.objects.raw() 使用用户输入作为 SQL，存在严重 SQL 注入风险，请使用 ORM 或参数化查询。",
                    }
                )
                return
        self._check_execute_call(node, context)

    # ------------------------------------------------------------------
    # 子检测方法
    # ------------------------------------------------------------------
    def _check_execute_call(self, node: ast.Call, context: AnalysisContext) -> None:
        """检测 cursor.execute(...) 形式的 SQL 调用。"""
        func = node.func
        method_name = None
        if isinstance(func, ast.Attribute):
            method_name = func.attr
            # receiver 明确为非 DB 对象（如 task.execute）→ 跳过
            receiver = func.value
            if isinstance(receiver, ast.Name) and receiver.id in _NON_DB_RECEIVERS:
                return
        elif isinstance(func, ast.Name):
            method_name = func.id

        if method_name not in _CURSOR_METHODS:
            return

        # 参数化查询 → 安全
        if _is_parameterized(node):
            return

        if not node.args:
            return

        first_arg = node.args[0]
        self._check_sql_arg(first_arg, node, context)

    def _check_sql_arg(self, arg: ast.AST, call_node: ast.Call, context: AnalysisContext) -> None:
        """分析 execute() 第一个参数是否存在注入风险。"""
        # SQLAlchemy text().bindparams() 为安全模式
        if _is_sqlalchemy_text_bindparams(arg):
            return
        # BinOp：字符串拼接 ("SELECT..." + uid) 或 % 格式化
        if isinstance(arg, ast.BinOp):
            if isinstance(arg.op, (ast.Add, ast.Mod)):
                parts = self._flatten_binop(arg)
                has_sql = any(_is_sql_str(p) for p in parts)
                has_input = any(_is_user_input_node(p, context) for p in parts)
                if has_sql and has_input:
                    # 所有"疑似用户输入"的节点均来自 self.xxx（框架内部属性）→ 豁免
                    input_parts = [p for p in parts if _is_user_input_node(p, context)]
                    if all(_is_internal_config_node(p) for p in input_parts):
                        return
                    self._report(
                        arg,
                        context,
                        "检测到 execute() 参数中存在 SQL 字符串拼接且含用户输入，"
                        "存在 SQL 注入风险，建议使用参数化查询。",
                    )

        # JoinedStr：f-string（`f"SELECT...{uid}"`）
        elif isinstance(arg, ast.JoinedStr):
            # 提取 f-string 中的所有插值变量
            identifiers = [n.id for n in ast.walk(arg) if isinstance(n, ast.Name)]
            # 检查污点或启发式
            has_input = any(_is_user_input_node(ast.Name(id=n, ctx=ast.Load()), context) for n in identifiers)
            # Sanitizer 感知
            if has_input and context is not None:
                if all(context.is_var_sanitized(n) for n in identifiers if n):
                    return
            if has_input:
                self._report(
                    arg,
                    context,
                    "检测到 execute() 参数中使用 f-string 包含变量插值，存在 SQL 注入风险，建议使用参数化查询。",
                )

    def _check_raw_concat(self, node: ast.AST, context: AnalysisContext) -> None:
        """检测裸 BinOp/JoinedStr（不在 execute 调用内），启发式报告。"""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            parts = self._flatten_binop(node)
            has_sql = any(_is_sql_str(p) for p in parts)
            has_input = any(_is_user_input_node(p, context) for p in parts)
            if has_sql and has_input:
                self._report(node, context, "检测到 SQL 字符串拼接且含疑似用户输入，存在 SQL 注入风险。")

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------
    @staticmethod
    def _flatten_binop(node: ast.BinOp) -> list[ast.AST]:
        """展开连续的 + 拼接，返回所有叶节点。"""
        result: list[ast.AST] = []
        stack = [node]
        while stack:
            cur = stack.pop()
            if isinstance(cur, ast.BinOp) and isinstance(cur.op, (ast.Add, ast.Mod)):
                stack.append(cur.left)
                stack.append(cur.right)
            else:
                result.append(cur)
        return result

    def _report(self, node: ast.AST, context: AnalysisContext, details: str) -> None:
        line_no = getattr(node, "lineno", 0) or 0
        finding: dict[str, Any] = {
            "type": "SQL_INJECTION",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line_no,
            "details": details,
        }
        context.add_finding(finding)


__all__ = ["PythonSQLInjectionAstRule"]
