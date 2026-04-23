"""
path_traversal.ast_rule

Python 路径遍历（Path Traversal）AST 规则。

检测目标：
- open(user_input) / open(path, "w") 中 path 含用户输入
- os.path.join(..., user_input) / os.path.join(base, user_input)
- pathlib.Path(user_input)
- Flask send_file(user_input) / send_from_directory(dir, user_input)
- Django FileResponse(open(user_input))

净化器（Sanitizer）：
- os.path.basename(x)  — 移除目录部分，只保留文件名
- pathlib.Path.name     — 同上
- os.path.abspath(x) + 白名单校验（引擎暂不感知逻辑校验，保留作文档说明）

参考 CVE：
- CVE-2021-31542：Django FileField 文件名未净化导致路径遍历
"""

from __future__ import annotations

import ast
from typing import Any

from ...base import AnalysisContext, SecurityRule

# ── Sink 函数：直接以文件路径为参数的高危调用 ──────────────────────────
_DIRECT_SINK_FUNCS = frozenset(
    [
        # Python 内置
        "open",
        # Flask
        "send_file",
        "send_from_directory",
        # Django
        "FileResponse",
    ]
)

# ── Sink 方法（obj.method 形式） ────────────────────────────────────────
_SINK_METHODS = frozenset(
    [
        # pathlib
        "open",
        # os / shutil 等
        "rename",
        "remove",
        "unlink",
        "rmdir",
        "copy",
        "copyfile",
        "move",
    ]
)

# ── 路径构造函数（os.path.join / Path() 等） ────────────────────────────
_PATH_CONSTRUCT_FUNCS = frozenset(
    [
        "join",  # os.path.join
    ]
)
_PATH_CONSTRUCT_CLASSES = frozenset(
    [
        "Path",  # pathlib.Path
        "PurePath",
        "PurePosixPath",
        "PureWindowsPath",
        "PosixPath",
        "WindowsPath",
    ]
)

# ── 净化器：调用后视为已净化 ────────────────────────────────────────────
_SANITIZE_ATTR_METHODS = frozenset(
    [
        "basename",  # os.path.basename
        "abspath",  # os.path.abspath（仍需白名单校验，引擎仅降级）
        "realpath",  # os.path.realpath
    ]
)
_SANITIZE_ATTRS = frozenset(
    [
        "name",  # Path.name / PurePath.name
        "stem",  # Path.stem
    ]
)

# ── 用户输入来源 ────────────────────────────────────────────────────────
_USER_INPUT_OBJS = frozenset(["request", "req"])
_ENV_SOURCE_TYPES = frozenset(["os_environ", "process_env", "env", "environment"])
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
        "files",
    ]
)


def _is_os_path_join_call(func: ast.Attribute) -> bool:
    """
    仅识别 os.path.join(...)，避免把 "".join(...) 误判为路径构造。
    """
    if func.attr != "join":
        return False
    owner = func.value
    if not isinstance(owner, ast.Attribute):
        return False
    return isinstance(owner.value, ast.Name) and owner.value.id == "os" and owner.attr == "path"


def _collect_names(node: ast.AST) -> list[str]:
    """收集节点子树中所有 Name.id。"""
    return [n.id for n in ast.walk(node) if isinstance(n, ast.Name)]


def _is_env_taint_source(context: AnalysisContext, var_name: str) -> bool:
    """变量污点来源是否为环境变量。"""
    source = context.get_taint_source(var_name)
    source_type = getattr(source, "source_type", "") if source is not None else ""
    return source_type in _ENV_SOURCE_TYPES


def _is_sanitized_node(node: ast.AST) -> bool:
    """
    判断节点是否经过路径净化函数包裹。

    例如 ``os.path.basename(user_input)``、``Path(user_input).name``。
    """
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in _SANITIZE_ATTR_METHODS:
                return True
        if isinstance(func, ast.Name) and func.id in _SANITIZE_ATTR_METHODS:
            return True
    if isinstance(node, ast.Attribute):
        if node.attr in _SANITIZE_ATTRS:
            return True
    return False


def _is_user_input_node(node: ast.AST, context: AnalysisContext | None = None) -> bool:
    """
    判断节点是否来自用户输入（优先 TaintGraph，次之结构化匹配，最后启发式）。
    """
    if context is not None:
        names = _collect_names(node)
        if names:
            tainted_names = [n for n in names if context.is_var_tainted(n)]
            if tainted_names:
                # 运维环境变量来源不按远程用户输入处理。
                if all(_is_env_taint_source(context, n) for n in tainted_names):
                    return False
                return True
        if names and all(context.has_tracked_var(n) for n in names):
            return False

    # 结构化匹配：request.args / request.GET 等
    if isinstance(node, ast.Attribute):
        obj = node.value
        # 直接属性：request.args / request.GET
        if isinstance(obj, ast.Name) and obj.id in _USER_INPUT_OBJS:
            if node.attr in _USER_INPUT_ATTRS:
                return True
        # 嵌套属性：request.args.get → obj = request.args，attr = get → 检查 obj
        return _is_user_input_node(obj, context)
    if isinstance(node, ast.Subscript):
        return _is_user_input_node(node.value, context)
    if isinstance(node, ast.Call):
        # request.args.get('x') → func = request.args.get
        return _is_user_input_node(node.func, context)

    # 退化启发式：变量名含文件路径语义关键词
    if isinstance(node, ast.Name):
        import re

        lname = node.id.lower()
        _FALLBACK_PATTERNS = (
            r"^req(?:uest)?",  # req_xxx / request
            r"_input$",  # xxx_input
            r"_payload$",  # xxx_payload
            r"^raw_",  # raw_xxx
        )
        if any(re.search(pat, lname) for pat in _FALLBACK_PATTERNS):
            return True

    return False


class PythonPathTraversalAstRule(SecurityRule):
    """
    基于 Python AST 的路径遍历检测规则（污点感知版）。

    检测用户输入直接或间接用于文件路径构造/读写操作，
    且未经 os.path.basename() / Path.name 等净化。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="PATH_TRAVERSAL_PY_AST",
            severity="High",
            languages=["python"],
        )

    def before_file(self, context: AnalysisContext) -> None:
        """预扫描赋值，将 Source 变量标记到 DataFlowTracker（降级路径）。"""
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
        """访问单个 AST 节点，检测路径遍历 sink。"""
        if not isinstance(node, ast.Call):
            return

        func = node.func

        # 1. 直接函数调用：open() / send_file() / Path()
        if isinstance(func, ast.Name):
            if func.id in _DIRECT_SINK_FUNCS or func.id in _PATH_CONSTRUCT_CLASSES:
                self._check_path_args(node, context, func.id, arg_index=0)
            return

        # 2. 方法调用：os.path.join() / obj.open()
        if isinstance(func, ast.Attribute):
            attr = func.attr
            if attr in _PATH_CONSTRUCT_FUNCS:
                if not _is_os_path_join_call(func):
                    return
                # os.path.join(base, user_input) → 检查最后一个参数（目录遍历入口）
                self._check_path_args(node, context, f"os.path.{attr}", arg_index=-1)
            elif attr in _SINK_METHODS:
                self._check_path_args(node, context, attr, arg_index=0)
            return

    # ------------------------------------------------------------------
    # 参数检查
    # ------------------------------------------------------------------
    def _check_path_args(
        self,
        node: ast.Call,
        context: AnalysisContext,
        func_name: str,
        arg_index: int = 0,
    ) -> None:
        """
        检查调用指定位置的参数是否含未净化的用户输入。

        Args:
            arg_index: 0 表示第一个参数，-1 表示最后一个参数。
        """
        args = node.args
        if not args:
            return

        try:
            target_arg = args[arg_index]
        except IndexError:
            return

        self._check_single_arg(target_arg, node, context, func_name)

    def _check_single_arg(
        self,
        arg: ast.AST,
        call_node: ast.Call,
        context: AnalysisContext,
        func_name: str,
    ) -> None:
        """递归检查参数节点（处理字符串拼接/格式化/f-string 等复合节点）。"""
        # BinOp 拼接：'/uploads/' + filename
        if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):
            # 展平后检查各部分
            parts = self._flatten_binop(arg)
            for part in parts:
                if _is_sanitized_node(part):
                    continue
                names = _collect_names(part)
                if names and context is not None and all(context.is_var_sanitized(n) for n in names):
                    continue
                if _is_user_input_node(part, context):
                    self._add_finding(
                        context,
                        call_node,
                        func_name,
                        details=(
                            f"发现 {func_name}() 的路径参数含疑似用户输入且未经净化，"
                            f"存在路径遍历风险（../../../etc/passwd 等）。"
                            f"建议使用 os.path.basename() 提取文件名，或在白名单目录内校验。"
                        ),
                    )
                    return
            return

        # f-string
        if isinstance(arg, ast.JoinedStr):
            idents = [n.id for n in ast.walk(arg) if isinstance(n, ast.Name)]
            has_input = any(_is_user_input_node(ast.Name(id=n, ctx=ast.Load()), context) for n in idents)
            if has_input and context is not None:
                if all(context.is_var_sanitized(n) for n in idents if n):
                    return
            if has_input:
                self._add_finding(
                    context,
                    call_node,
                    func_name,
                    details=(f"发现 {func_name}() 的路径参数使用 f-string 包含用户变量，存在路径遍历风险。"),
                )
            return

        # 直接节点
        if _is_sanitized_node(arg):
            return
        names = _collect_names(arg)
        if names and context is not None and all(context.is_var_sanitized(n) for n in names):
            return
        if _is_user_input_node(arg, context):
            self._add_finding(
                context,
                call_node,
                func_name,
                details=(
                    f"发现 {func_name}() 的路径参数含疑似用户输入且未经净化，"
                    f"存在路径遍历风险（../../../etc/passwd 等）。"
                    f"建议使用 os.path.basename() 提取文件名，或在白名单目录内校验。"
                ),
            )

    @staticmethod
    def _flatten_binop(node: ast.AST) -> list[ast.AST]:
        """递归展平 BinOp 加法/取模链，收集所有叶子节点。"""
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return PythonPathTraversalAstRule._flatten_binop(node.left) + PythonPathTraversalAstRule._flatten_binop(
                node.right
            )
        return [node]

    def _add_finding(
        self,
        context: AnalysisContext,
        node: ast.AST,
        func_name: str,
        details: str,
    ) -> None:
        line_no = getattr(node, "lineno", 0) or 0
        finding: dict[str, Any] = {
            "type": "PATH_TRAVERSAL",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line_no,
            "details": details,
        }
        context.add_finding(finding)


__all__ = ["PythonPathTraversalAstRule"]
