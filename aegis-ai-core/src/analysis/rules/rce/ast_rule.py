"""
rce.ast_rule

Python RCE（远程代码执行 / 命令执行）AST 规则（污点感知版）。

检测目标：
- eval() / exec() / compile()
- os.system() / os.popen()
- subprocess.call / run / Popen / check_call / check_output
- os.execv / os.execve / os.execvp

改进（对齐 JS 版本）：
- 接入 AnalysisContext.taint_graph / dataflow_tracker 做污点感知；
- 若参数为纯常量字面量（无用户输入），则降级或跳过；
- 区分高危（用户输入直接流入）vs 中危（上下文中存在用户输入但未确认）；
- 业务上下文感知：setup/install 类脚本降级。
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...base import AnalysisContext, SecurityRule


# subprocess 危险方法
_SUBPROCESS_DANGEROUS = frozenset([
    "call", "run", "Popen", "check_call", "check_output",
])

# os 模块危险方法
_OS_DANGEROUS = frozenset([
    "system", "popen", "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe",
])

# 安装/初始化/工具脚本名前缀（业务上下文降级）
_SETUP_NAMES = frozenset([
    "setup", "install", "migrate", "upgrade", "seed",
    "bootstrap", "fixture", "deploy", "init",
    # 框架 CLI / REPL / 管理工具脚本（如 flask cli.py、django manage.py）
    "cli", "repl", "shell", "manage", "console", "wsgi", "asgi",
])

# Python 用户输入访问模式（结构化）
_USER_INPUT_ATTRS = frozenset([
    "form", "args", "json", "data", "values", "cookies", "headers",
    "GET", "POST", "FILES", "params", "query_params",
])
_USER_INPUT_OBJS = frozenset(["request", "req"])


def _collect_names(node: ast.AST) -> List[str]:
    """从节点子树中收集所有 Name.id。"""
    return [n.id for n in ast.walk(node) if isinstance(n, ast.Name)]


def _is_user_input_node(node: ast.AST, context: Optional[AnalysisContext] = None) -> bool:
    """
    判断节点是否来自用户输入。

    优先级：
    1. TaintGraph / DataFlowTracker（精确）
    2. 结构化匹配 request.GET 等（精确）
    3. 退化启发式
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

    if isinstance(node, ast.Name):
        lname = node.id.lower()
        for kw in ("cmd", "command", "user", "input", "param", "arg",
                   "query", "data", "payload"):
            if kw in lname:
                return True

    return False


def _is_constant_arg(node: ast.AST) -> bool:
    """节点是否为纯常量（字符串/数字），不含变量。"""
    if isinstance(node, (ast.Constant, ast.Str, ast.Num)):
        return True
    if isinstance(node, ast.List):
        return all(_is_constant_arg(e) for e in node.elts)
    return False


def _is_setup_script(file_path: Any) -> bool:
    """判断文件是否为安装/初始化/工具脚本。"""
    try:
        name = Path(str(file_path)).stem.lower()
        return any(name.startswith(n) or name == n for n in _SETUP_NAMES)
    except Exception:
        return False


def _is_env_var_source(node: ast.AST) -> bool:
    """
    判断节点是否来自环境变量读取（os.environ.get / os.getenv）。

    这类输入由运维/部署人员控制，风险等级低于 HTTP 请求输入，
    检测到时应降级而非无条件触发 Critical。
    """
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    # os.getenv(...)
    if isinstance(func, ast.Attribute):
        obj = getattr(func.value, "id", "")
        if obj == "os" and func.attr in ("getenv",):
            return True
        # os.environ.get(...)
        if isinstance(func.value, ast.Attribute):
            inner_obj = getattr(func.value.value, "id", "")
            if inner_obj == "os" and func.value.attr == "environ" and func.attr == "get":
                return True
    return False


class PythonRCEAstRule(SecurityRule):
    """
    基于 Python AST 的 RCE 检测规则（污点感知版）。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="RCE_COMMAND_EXEC_PY_AST",
            severity="Critical",
            languages=["python"],
        )

    def before_file(self, context: AnalysisContext) -> None:
        """
        预扫描赋值，标记用户输入 Source 变量到 DataFlowTracker（降级路径）。

        若 taint_graph 已由 PythonAnalyzer 构建，则跳过此步骤。
        """
        # taint_graph 已就绪，TaintAnalyzer 负责 Source 追踪
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

        # 1. eval / exec / compile（污点感知检测）
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in ("eval", "exec", "compile"):
                self._check_eval_exec(node, context, func_name)
                return

        if not isinstance(node.func, ast.Attribute):
            return

        module = getattr(node.func.value, "id", "") or ""
        method = node.func.attr

        # 2. os.system / os.popen 等
        if module == "os" and method in _OS_DANGEROUS:
            self._check_call_with_args(node, context, f"os.{method}")
            return

        # 3. subprocess.run / Popen 等
        if module == "subprocess" and method in _SUBPROCESS_DANGEROUS:
            self._check_call_with_args(node, context, f"subprocess.{method}")
            return

    # ------------------------------------------------------------------
    # eval / exec / compile 污点感知检查
    # ------------------------------------------------------------------
    def _check_eval_exec(
        self, node: ast.Call, context: AnalysisContext, func_name: str
    ) -> None:
        """
        污点感知版 eval/exec/compile 检测。

        判断优先级（高 → 低）：
        1. 无参数 → 跳过（不可能执行任意代码）
        2. 第一个参数是纯常量字面量 → 跳过
        3. 第一个参数来自用户输入（TaintGraph 或结构化匹配）→ Critical
        4. 第一个参数来自环境变量（os.environ.get / os.getenv）→ Medium
        5. 文件是工具/CLI/安装脚本且无污点确认 → Low
        6. 参数含变量但来源不明 → High（保守召回，降一级）
        """
        if not node.args and not node.keywords:
            return

        first_arg = node.args[0] if node.args else None
        if first_arg is None:
            return

        # 纯常量参数 → 安全（如 eval("1+1")）
        if _is_constant_arg(first_arg):
            return

        # 净化感知：shlex.quote / shlex.split / 白名单等
        names = _collect_names(first_arg)
        if context is not None and names and all(context.is_var_sanitized(n) for n in names):
            return

        # 用户输入直接流入
        if _is_user_input_node(first_arg, context):
            self._add_finding(
                context, node, "Critical",
                details=f"发现 {func_name}()，参数来自用户输入，存在代码注入风险。",
            )
            return

        # 环境变量来源：由运维控制，降级
        if _is_env_var_source(first_arg):
            self._add_finding(
                context, node, "Medium",
                details=f"发现 {func_name}()，参数来自环境变量，建议确认是否存在配置注入风险。",
            )
            return

        # 工具/CLI/安装脚本场景（如 flask cli.py、django manage.py）
        is_setup = _is_setup_script(context.file_path)
        if is_setup:
            self._add_finding(
                context, node, "Low",
                details=f"[工具脚本] 发现 {func_name}()，参数含变量，处于框架工具脚本上下文，已降级。",
            )
            return

        # 参数含变量但来源不明 → 保守召回，降一级
        if _collect_names(first_arg):
            self._add_finding(
                context, node, "High",
                details=f"发现 {func_name}()，参数含变量，建议确认参数来源是否可控。",
            )

    # ------------------------------------------------------------------
    # 参数污染检查
    # ------------------------------------------------------------------
    def _check_call_with_args(
        self, node: ast.Call, context: AnalysisContext, call_str: str
    ) -> None:
        """
        检查 RCE Sink 的参数是否存在用户输入。

        - 若参数是纯常量 → 不报（误报太高）
        - 业务上下文感知：setup 脚本降级
        - 有 TaintGraph → 精确污点判断
        - 无 TaintGraph → 启发式（变量名/结构化匹配）
        """
        if not node.args and not node.keywords:
            return

        first_arg = node.args[0] if node.args else None

        # 纯常量参数 → 安全
        if first_arg and _is_constant_arg(first_arg):
            return

        # 净化感知：shlex.quote / shlex.split / 白名单等
        names = _collect_names(first_arg) if first_arg else []
        if context is not None and names and all(context.is_var_sanitized(n) for n in names):
            return

        # subprocess 使用 shell=False 且首参为 list 时降级为 Low（安全用法）
        severity_override = None
        if "subprocess" in call_str and first_arg is not None and isinstance(first_arg, ast.List):
            severity_override = "Low"

        # 判断是否有用户输入
        has_user_input = False
        if first_arg:
            has_user_input = _is_user_input_node(first_arg, context)
        has_any_var = first_arg is not None and bool(_collect_names(first_arg))

        # 业务上下文：setup 脚本降级
        is_setup = _is_setup_script(context.file_path)
        if is_setup and not has_user_input:
            self._add_finding(
                context, node, "Low",
                details=f"[安装脚本] {call_str}() 调用，参数未检测到用户输入，已降级。",
            )
            return

        if has_user_input:
            sev = severity_override or "Critical"
            self._add_finding(
                context, node, sev,
                details=f"发现 {call_str}() 调用，参数来自用户输入，存在命令注入风险。",
            )
        elif has_any_var:
            sev = severity_override or "High"
            self._add_finding(
                context, node, sev,
                details=f"发现 {call_str}() 调用，参数含变量，建议确认是否可控。",
            )

    def _add_finding(
        self, context: AnalysisContext, node: ast.AST, severity: str, details: str
    ) -> None:
        line_no = getattr(node, "lineno", 0) or 0
        finding: Dict[str, Any] = {
            "type": "RCE_COMMAND_EXEC",
            "rule_id": self.rule_id,
            "severity": severity,
            "line": line_no,
            "details": details,
        }
        context.add_finding(finding)


__all__ = ["PythonRCEAstRule"]
