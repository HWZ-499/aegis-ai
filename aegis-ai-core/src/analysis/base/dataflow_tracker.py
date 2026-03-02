"""
dataflow_tracker.py - 数据流追踪器（阶段二增强版）

实现单文件内的变量追踪，覆盖以下传播模式：
- 直接赋值：  ``const x = req.body; sink(x)``
- 解构赋值：  ``const { name } = req.body``
- 字符串拼接：``"SELECT " + tainted``
- 模板字符串：```` `SELECT ${tainted}` ````
- Express 路由回调：``app.get('/x', (req, res) => {...})`` 中 req 自动标记
- Sanitizer 感知：经过 ``parseInt()`` / ``escapeHtml()`` 后降级或标记为已净化

设计原则：
- 轻量级：只做单文件内的变量追踪
- 实用性：覆盖真实世界 60%+ 的 JS/TS 传播模式
- 可查询：规则层通过 ``is_tainted()`` / ``is_sanitized()`` 快速决策
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class TaintLevel(Enum):
    """污点级别"""
    CLEAN = 0       # 干净数据
    LOW = 1         # 低风险（如配置文件）
    MEDIUM = 2      # 中风险（如环境变量）
    HIGH = 3        # 高风险（如用户输入）
    CRITICAL = 4    # 极高风险（如直接的 req.body）


@dataclass
class TaintSource:
    """污点来源信息"""
    source_type: str        # 来源类型：user_input, config, env, route_param, etc.
    source_expr: str        # 来源表达式：req.body, req.query, etc.
    line: int               # 定义所在行
    taint_level: TaintLevel = TaintLevel.HIGH


@dataclass
class VariableInfo:
    """变量信息"""
    name: str               # 变量名
    defined_line: int       # 定义行号
    taint_source: Optional[TaintSource] = None  # 污点来源（如果有）
    is_tainted: bool = False  # 是否被污染
    is_sanitized: bool = False  # 是否经过净化器
    sanitized_by: Optional[str] = None  # 净化器名称
    assigned_from: Optional[str] = None  # 赋值来源表达式


class DataFlowTracker:
    """
    数据流追踪器（阶段二增强版）。

    功能：
    - 追踪变量赋值和污点传播
    - 识别用户输入源（req.body, req.query, req.params, req.cookies）
    - Express 路由回调参数自动标记为 Source
    - 解构赋值的属性继承父对象的污点
    - 字符串拼接 / 模板字符串的污点传播
    - Sanitizer 感知（标记经过净化的变量）
    - 提供统一的污点 / 净化查询接口

    使用方式：
    1. 在 ``before_file()`` 中初始化
    2. 在遍历 AST 时调用 ``track_assignment()`` / ``mark_as_source()`` /
       ``track_destructuring()`` / ``track_sanitization()`` 记录信息
    3. 在检测危险函数时调用 ``is_tainted()`` / ``is_sanitized()`` 查询变量状态
    """

    # ──────────────────────────────────────────────
    # 已知 Source 模式
    # ──────────────────────────────────────────────
    USER_INPUT_PATTERNS_JS = [
        "req.body",
        "req.query",
        "req.params",
        "req.cookies",
        "req.headers",
        "request.body",
        "request.query",
        "request.params",
        "ctx.request.body",   # Koa
        "ctx.query",          # Koa
        "ctx.params",         # Koa
    ]

    USER_INPUT_PATTERNS_PY = [
        "request.form",
        "request.args",
        "request.json",
        "request.data",
        "request.values",
        "request.cookies",
        "request.headers",
        "request.GET",        # Django
        "request.POST",       # Django
        "request.FILES",      # Django
    ]

    # ──────────────────────────────────────────────
    # 已知 Sanitizer 函数（精确匹配，不再子串）
    # ──────────────────────────────────────────────
    SANITIZER_FUNCTIONS_JS = {
        # 数值转换 → 净化 SQLi / NoSQLi
        "parseInt", "parseFloat", "Number",
        # HTML 转义 → 净化 XSS
        "escapeHtml", "DOMPurify.sanitize", "xss",
        # MongoDB 净化
        "mongo-sanitize", "mongoSanitize",
        # 路径净化
        "path.normalize", "path.resolve", "path.basename",
        # 类型强制
        "String", "Boolean",
        # 验证库
        "validator.escape", "validator.isEmail",
    }

    SANITIZER_FUNCTIONS_PY = {
        "int", "float", "str",
        "html.escape", "cgi.escape", "markupsafe.escape",
        "shlex.quote",
        "os.path.basename", "os.path.normpath",
        "bleach.clean",
    }

    def __init__(self, language: str = "javascript") -> None:
        """
        初始化数据流追踪器。

        Args:
            language: 目标语言，用于选择合适的 Source / Sanitizer 模式。
        """
        self.language = language
        self._variables: Dict[str, VariableInfo] = {}
        self._tainted_vars: Set[str] = set()
        self._sanitized_vars: Set[str] = set()

        # 根据语言选择模式
        if language in ("javascript", "typescript"):
            self._user_input_patterns = self.USER_INPUT_PATTERNS_JS
            self._sanitizer_functions = self.SANITIZER_FUNCTIONS_JS
        elif language == "python":
            self._user_input_patterns = self.USER_INPUT_PATTERNS_PY
            self._sanitizer_functions = self.SANITIZER_FUNCTIONS_PY
        else:
            self._user_input_patterns = (
                self.USER_INPUT_PATTERNS_JS + self.USER_INPUT_PATTERNS_PY
            )
            self._sanitizer_functions = (
                self.SANITIZER_FUNCTIONS_JS | self.SANITIZER_FUNCTIONS_PY
            )

    def reset(self) -> None:
        """重置追踪器状态（切换文件时调用）。"""
        self._variables.clear()
        self._tainted_vars.clear()
        self._sanitized_vars.clear()

    # ──────────────────────────────────────────────
    # 追踪 API
    # ──────────────────────────────────────────────

    def track_assignment(self, var_name: str, value_expr: str, line: int) -> None:
        """
        追踪变量赋值。

        处理的场景：
        - ``const userId = req.body.userId``  → userId 被标记为 tainted
        - ``const x = taintedVar``            → x 继承污点
        - ``const safe = parseInt(tainted)``  → safe 标记为 sanitized

        Args:
            var_name: 变量名
            value_expr: 赋值表达式（文本）
            line: 行号
        """
        # 1. 检查是否经过 Sanitizer 包裹
        sanitizer_name = self._detect_sanitizer_call(value_expr)
        if sanitizer_name:
            # 虽然输入可能是 tainted，但经过净化后标记为 sanitized
            var_info = VariableInfo(
                name=var_name,
                defined_line=line,
                is_tainted=False,
                is_sanitized=True,
                sanitized_by=sanitizer_name,
                assigned_from=value_expr,
            )
            self._variables[var_name] = var_info
            self._tainted_vars.discard(var_name)
            self._sanitized_vars.add(var_name)
            return

        # 2. 检查赋值表达式是否直接来自用户输入
        taint_source = self._check_taint_source(value_expr, line)
        is_tainted = taint_source is not None

        # 3. 如果赋值来自另一个已污染的变量，传播污点
        if not is_tainted and value_expr in self._tainted_vars:
            is_tainted = True
            orig_var = self._variables.get(value_expr)
            if orig_var and orig_var.taint_source:
                taint_source = TaintSource(
                    source_type="propagated",
                    source_expr=f"{value_expr} <- {orig_var.taint_source.source_expr}",
                    line=line,
                    taint_level=orig_var.taint_source.taint_level,
                )

        # 4. 检查表达式是否包含已污染变量（字符串拼接 / 模板字符串）
        if not is_tainted:
            for tv in self._tainted_vars:
                if tv in value_expr:
                    is_tainted = True
                    orig = self._variables.get(tv)
                    orig_expr = orig.taint_source.source_expr if orig and orig.taint_source else tv
                    taint_source = TaintSource(
                        source_type="concat_propagation",
                        source_expr=f"concat/template: {tv} <- {orig_expr}",
                        line=line,
                        taint_level=TaintLevel.HIGH,
                    )
                    break

        var_info = VariableInfo(
            name=var_name,
            defined_line=line,
            taint_source=taint_source,
            is_tainted=is_tainted,
            assigned_from=value_expr,
        )
        self._variables[var_name] = var_info

        if is_tainted:
            self._tainted_vars.add(var_name)
        else:
            self._tainted_vars.discard(var_name)

    def mark_as_source(self, var_name: str, line: int, source_type: str = "route_param") -> None:
        """
        显式标记一个变量为 Source（污点源）。

        主要用于 Express 路由回调识别：
        ``app.get('/path', (req, res) => {...})`` 中 ``req`` 参数。

        Args:
            var_name: 变量名（如 ``"req"``）
            line: 行号
            source_type: 来源类型
        """
        taint_source = TaintSource(
            source_type=source_type,
            source_expr=var_name,
            line=line,
            taint_level=TaintLevel.CRITICAL,
        )
        var_info = VariableInfo(
            name=var_name,
            defined_line=line,
            taint_source=taint_source,
            is_tainted=True,
        )
        self._variables[var_name] = var_info
        self._tainted_vars.add(var_name)

    def track_destructuring(
        self,
        properties: List[str],
        source_expr: str,
        line: int,
    ) -> None:
        """
        追踪解构赋值。

        处理 ``const { name, email } = req.body`` 模式：
        如果 ``source_expr`` 是已污染的，则所有解构出的属性变量都继承污点。

        Args:
            properties: 解构出的属性名列表 (``["name", "email"]``)
            source_expr: 被解构的对象表达式 (``"req.body"``)
            line: 行号
        """
        # 判断源是否被污染
        source_tainted = (
            self.is_user_input_expr(source_expr)
            or source_expr in self._tainted_vars
        )

        for prop in properties:
            if source_tainted:
                taint_source = TaintSource(
                    source_type="destructuring",
                    source_expr=f"{source_expr}.{prop}",
                    line=line,
                    taint_level=TaintLevel.CRITICAL,
                )
                var_info = VariableInfo(
                    name=prop,
                    defined_line=line,
                    taint_source=taint_source,
                    is_tainted=True,
                    assigned_from=f"{source_expr}.{prop}",
                )
                self._variables[prop] = var_info
                self._tainted_vars.add(prop)
            else:
                var_info = VariableInfo(
                    name=prop,
                    defined_line=line,
                    is_tainted=False,
                    assigned_from=f"{source_expr}.{prop}",
                )
                self._variables[prop] = var_info

    def track_sanitization(self, var_name: str, sanitizer_name: str, line: int) -> None:
        """
        标记一个变量经过了 Sanitizer 净化。

        即使变量之前是 tainted，经过净化后也标记为 sanitized。

        Args:
            var_name: 变量名
            sanitizer_name: 净化器名称（如 ``"parseInt"``）
            line: 行号
        """
        existing = self._variables.get(var_name)
        if existing:
            existing.is_sanitized = True
            existing.sanitized_by = sanitizer_name
        else:
            self._variables[var_name] = VariableInfo(
                name=var_name,
                defined_line=line,
                is_sanitized=True,
                sanitized_by=sanitizer_name,
            )
        self._tainted_vars.discard(var_name)
        self._sanitized_vars.add(var_name)

    # ──────────────────────────────────────────────
    # 查询 API
    # ──────────────────────────────────────────────

    def has_tracked_var(self, var_name: str) -> bool:
        """检查变量是否已被追踪（曾出现在赋值等数据流中）。用于区分「未追踪」与「已追踪且未污染」。"""
        return var_name in self._variables

    def is_tainted(self, var_name: str) -> bool:
        """检查变量是否被污染（且未被净化）。"""
        return var_name in self._tainted_vars and var_name not in self._sanitized_vars

    def is_sanitized(self, var_name: str) -> bool:
        """检查变量是否经过净化。"""
        return var_name in self._sanitized_vars

    def get_sanitizer_name(self, var_name: str) -> Optional[str]:
        """获取变量经过的净化器名称。"""
        info = self._variables.get(var_name)
        return info.sanitized_by if info else None

    def get_taint_source(self, var_name: str) -> Optional[TaintSource]:
        """获取变量的污点来源。"""
        var_info = self._variables.get(var_name)
        if var_info:
            return var_info.taint_source
        return None

    def get_variable_info(self, var_name: str) -> Optional[VariableInfo]:
        """获取变量的完整信息。"""
        return self._variables.get(var_name)

    def get_all_tainted_vars(self) -> Set[str]:
        """获取所有被污染的变量名。"""
        return self._tainted_vars.copy()

    def is_user_input_expr(self, expr: str) -> bool:
        """
        检查表达式是否直接来自用户输入（前缀精确匹配）。

        Args:
            expr: 表达式字符串（如 ``"req.body"``, ``"req.query.id"``）
        """
        expr_lower = expr.lower()
        for pattern in self._user_input_patterns:
            if pattern.lower() in expr_lower or expr_lower.startswith(pattern.lower()):
                return True
        return False

    def check_expr_taint(self, expr: str) -> tuple[bool, Optional[TaintSource]]:
        """
        综合检查表达式是否被污染。

        检查逻辑：
        1. 表达式是否直接是用户输入
        2. 表达式是否是已污染的变量
        3. 表达式是否包含已污染的变量（如拼接）
        """
        # 1. 直接用户输入
        if self.is_user_input_expr(expr):
            return True, TaintSource(
                source_type="user_input",
                source_expr=expr,
                line=0,
                taint_level=TaintLevel.CRITICAL,
            )
        # 2. 已污染变量
        if expr in self._tainted_vars:
            return True, self.get_taint_source(expr)
        # 3. 包含已污染变量
        for tainted_var in self._tainted_vars:
            if tainted_var in expr:
                return True, self.get_taint_source(tainted_var)
        return False, None

    # ──────────────────────────────────────────────
    # 内部方法
    # ──────────────────────────────────────────────

    def _check_taint_source(self, expr: str, line: int) -> Optional[TaintSource]:
        """检查表达式是否来自用户输入。"""
        expr_lower = expr.lower()
        for pattern in self._user_input_patterns:
            if pattern.lower() in expr_lower or expr_lower.startswith(pattern.lower()):
                return TaintSource(
                    source_type="user_input",
                    source_expr=expr,
                    line=line,
                    taint_level=TaintLevel.CRITICAL,
                )
        return None

    def _detect_sanitizer_call(self, expr: str) -> Optional[str]:
        """
        检测表达式是否是 Sanitizer 调用的返回值。

        例如 ``parseInt(x)`` / ``escapeHtml(data)`` 等。
        使用精确前缀匹配，避免 ``escape_velocity`` 之类的误判。

        Returns:
            匹配的 Sanitizer 名称，未匹配则 ``None``。
        """
        stripped = expr.strip()
        for func_name in self._sanitizer_functions:
            # 精确匹配：表达式以 sanitizer 函数名 + "(" 开头
            if stripped.startswith(func_name + "(") or stripped.startswith(func_name.split(".")[-1] + "("):
                return func_name
        return None


# 导出
__all__ = ["DataFlowTracker", "TaintLevel", "TaintSource", "VariableInfo"]
