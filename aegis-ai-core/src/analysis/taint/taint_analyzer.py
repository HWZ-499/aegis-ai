"""
taint_analyzer.py - 污点分析器

实现完整的 Source → Sink 污点分析：
1. 解析 AST
2. 识别 Source（用户输入）
3. 追踪数据流传播
4. 识别 Sink（危险函数）
5. 构建污点路径
6. 检查净化器

支持 JavaScript/TypeScript 和 Python。
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

logger = logging.getLogger(__name__)

from .source_sink_registry import (
    SourceSinkRegistry,
    get_default_registry,
)
from .taint_graph import EdgeType, NodeType, TaintGraph, TaintNode, TaintPath

# Tree-sitter 导入
try:
    from tree_sitter import Node, Parser
    from tree_sitter_languages import get_language  # type: ignore[import-untyped]

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Parser = None  # type: ignore[misc,assignment]
    Node = None  # type: ignore[misc,assignment]
    get_language = None


@dataclass
class TaintFinding:
    """
    污点分析发现。

    表示一个潜在的安全漏洞。
    """

    # 漏洞信息
    vuln_type: str  # 漏洞类型
    severity: str  # 严重级别
    confidence: float  # 置信度

    # 位置信息
    file_path: str  # 文件路径
    line: int  # 行号（Sink 位置）

    # 污点路径
    taint_path: TaintPath  # 完整污点路径

    # 详情
    source_expr: str  # Source 表达式
    sink_expr: str  # Sink 表达式
    description: str  # 描述
    cwe: str  # CWE 编号

    # 修复建议
    remediation: str = ""  # 修复建议

    def to_dict(self) -> dict[str, Any]:
        """转换为字典格式"""
        return {
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "file_path": self.file_path,
            "line": self.line,
            "source": self.source_expr,
            "sink": self.sink_expr,
            "description": self.description,
            "cwe": self.cwe,
            "remediation": self.remediation,
            "path": self.taint_path.to_dict() if self.taint_path else None,
        }


class TaintAnalyzer:
    """
    污点分析器。

    实现完整的 Source → Sink 污点分析。

    使用示例：
        analyzer = TaintAnalyzer(language="javascript")
        findings = analyzer.analyze_file(Path("app.js"))

        for finding in findings:
            logger.info("[%s] %s at line %s", finding.severity, finding.vuln_type, finding.line)
            logger.info("  Path: %s", finding.taint_path.to_string())
    """

    def __init__(
        self,
        language: str = "javascript",
        registry: SourceSinkRegistry | None = None,
    ):
        """
        初始化污点分析器。

        Args:
            language: 目标语言（javascript, typescript, python）
            registry: Source/Sink 注册表（默认使用全局注册表）
        """
        self.language = language.lower()
        self.registry = registry or get_default_registry()

        # 污点图
        self.graph = TaintGraph()

        # 当前文件信息
        self._current_file: str = ""
        self._current_code: str = ""

        # 变量追踪
        self._variables: dict[str, TaintNode] = {}  # name -> node

        # 函数摘要追踪（JS 跨函数污点传播）
        # {func_name: {"first_param": str, "tainted": bool}}
        # 当发现 function foo(req, ...) 且 req 匹配已知 Source 时注册
        self._tainted_functions: dict[str, dict[str, Any]] = {}

        # 动态 Express Router 实例追踪
        # 存储通过 express.Router() / Router() 创建的变量名
        # 使得 apiRouter.get(...)、v1Router.post(...) 等模式也能被识别为路由
        self._express_router_vars: set[str] = set()

        # CFG / 支配树（用于 Guard Clause 精确分析）
        # 在 _analyze_from_root 中构建，供 _check_guard_clause 使用
        self._guard_if_nodes: list[Any] = []  # 收集的 if 语句节点
        self._dominator_tree: Any = None  # DominatorTree 实例（延迟构建）

        # 初始化 Tree-sitter parser
        self._parser: Parser | None = None
        if TREE_SITTER_AVAILABLE:
            try:
                if self.language in ("javascript", "typescript"):
                    lang = get_language("javascript")
                elif self.language == "python":
                    lang = get_language("python")
                elif self.language == "php":
                    lang = get_language("php")
                elif self.language == "java":
                    lang = get_language("java")
                elif self.language == "go":
                    lang = get_language("go")
                else:
                    lang = get_language("javascript")

                self._parser = Parser()
                self._parser.set_language(lang)
            except (ImportError, RuntimeError, OSError):
                self._parser = None

    def analyze_file(self, file_path: Path) -> list[TaintFinding]:
        """
        分析单个文件。

        Args:
            file_path: 文件路径

        Returns:
            发现的漏洞列表
        """
        try:
            code = file_path.read_text(encoding="utf-8", errors="ignore")
            return self.analyze_code(code, str(file_path))
        except (OSError, RuntimeError, ValueError) as e:
            logger.warning("污点分析文件失败 %s: %s", file_path, e)
            return []

    def analyze_code(self, code: str, file_path: str = "") -> list[TaintFinding]:
        """
        分析代码字符串。

        Args:
            code: 源代码
            file_path: 文件路径（可选）

        Returns:
            发现的漏洞列表
        """
        self._current_file = file_path
        self._current_code = code
        self.graph.reset()
        self._variables.clear()
        self._tainted_functions.clear()
        self._express_router_vars.clear()
        self._guard_if_nodes.clear()
        self._dominator_tree = None

        if not self._parser:
            return []

        try:
            # 1. 解析 AST
            tree = self._parser.parse(bytes(code, "utf8"))
            root = tree.root_node
            return self._analyze_from_root(root, file_path, code)
        except (RuntimeError, ValueError) as e:
            logger.warning("污点分析代码失败 [%s]: %s", file_path or "<inline>", e)
            return []

    def analyze_tree(self, root_node: Any, file_path: str, code: str = "") -> None:
        """
        基于已有 AST 根节点构建污点图（2.1 统一污点系统）。
        不解析、不返回 findings，仅填充 self.graph 供规则层查询。
        """
        self._current_file = file_path
        self._current_code = code or ""
        self.graph.reset()
        self._variables.clear()
        self._tainted_functions.clear()
        self._express_router_vars.clear()
        self._guard_if_nodes.clear()
        self._dominator_tree = None
        if not TREE_SITTER_AVAILABLE or not isinstance(root_node, Node):
            return
        try:
            self._collect_assignments(root_node)
            self._identify_sources_and_sinks(root_node)
            self._build_dataflow_edges()
            self._build_and_apply_dominator_tree()
        except (RuntimeError, ValueError) as e:
            logger.warning("analyze_tree 构建污点图失败 [%s]: %s", file_path, e)

    def _analyze_from_root(self, root: Any, file_path: str, code: str) -> list[TaintFinding]:
        """共用逻辑：从根节点收集 + 识别 + 建边 + 支配树增强 + 查路径 + 生成 findings。"""
        self._collect_assignments(root)
        self._identify_sources_and_sinks(root)
        self._build_dataflow_edges()
        # 构建 Dominator Tree 并增强 Guard Clause 净化精度
        self._build_and_apply_dominator_tree()
        paths = self.graph.find_paths_to_sinks()
        return self._generate_findings(paths)

    def _collect_assignments(self, node: Any) -> None:
        """
        收集变量声明和赋值。

        遍历 AST 找到所有变量赋值，建立变量到值的映射。

        节点类型差异：
        - JS/TS : variable_declaration / lexical_declaration, assignment_expression, call_expression
        - Python : assignment, call（注意 Python tree-sitter 与 JS 节点名不同）
        """
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        # JavaScript 变量声明（含解构）
        if node.type in ("variable_declaration", "lexical_declaration"):
            self._process_js_var_declaration(node)

        # Java 变量声明与赋值
        elif self.language == "java" and node.type in ("local_variable_declaration", "assignment_expression"):
            self._process_java_assignment(node)

        # Go 变量声明与赋值
        elif self.language == "go" and node.type in ("short_var_declaration", "assignment_statement"):
            self._process_go_assignment(node)

        # JavaScript / PHP 赋值表达式
        elif node.type == "assignment_expression":
            if self.language == "php":
                self._process_php_assignment(node)
            else:
                self._process_js_assignment(node)

        # Express 路由回调：app.get('/path', (req, res) => ...) 中 req 标记为 Source
        elif node.type == "call_expression" and self.language in ("javascript", "typescript"):
            self._check_express_route(node)

        # 具名函数定义：function foo(req, res) { ... }
        # 若首参数名匹配已知 Source（req/request），注册为"污点处理函数摘要"
        elif node.type == "function_declaration" and self.language in ("javascript", "typescript"):
            self._register_named_handler_function(node)

        # Python 赋值（tree-sitter Python 用 "assignment"，子节点用 "=" 分隔）
        elif node.type == "assignment":
            self._process_py_assignment(node)

        # PHP 变量赋值（部分 grammar 使用 expression_statement 包裹 assignment_expression）
        elif node.type == "expression_statement" and self.language == "php":
            for child in node.children:
                if child.type == "assignment_expression":
                    self._process_php_assignment(child)
                    break

        # Guard Clause / Early Return 净化传播
        # 识别 if (!valid) return; / if (!isNum) { throw ...; } 等模式
        # 这类防御性代码意味着后续代码中被检查的变量已通过验证
        elif node.type == "if_statement":
            self._check_guard_clause(node)

        # 递归处理子节点
        for child in node.children:
            self._collect_assignments(child)

    # Guard Clause 早返回动词：检测到这些节点时认为是提前退出
    _GUARD_EXIT_TYPES = frozenset(
        {
            "return_statement",
            "throw_statement",
            "break_statement",
            # Python
            "raise_statement",
        }
    )

    # 具有验证语义的函数名前缀/后缀（这类函数的返回值一旦为假则早返回，意味着参数已被"验证"）
    _GUARD_FUNC_PREFIXES = frozenset(
        {
            "is",
            "has",
            "can",
            "should",
            "check",
            "valid",
            "verify",
            "assert",
            "ensure",
            "validate",
            "sanitize",
            "parse",
            "test",
        }
    )

    def _check_guard_clause(self, if_node: Any) -> None:
        """
        识别 Guard Clause（早返回）模式，将被检查的变量标记为净化状态。

        覆盖模式（JS/TS/Python）：
        1. ``if (!valid) return;``
        2. ``if (!isNum) { throw new Error(...); }``
        3. ``if (typeof id !== 'string') return res.status(400).send(...);``
        4. ``if (!is_numeric(id)) { die(...); }``         ← PHP-like（Python 中用 raise）
        5. ``if (id === null || id === undefined) return;``
        6. ``if (err) return next(err);``

        判断逻辑：
        - if 的 consequence（then 块）只含退出语句（return/throw/raise/break）
        - 条件表达式中包含对某个变量的否定性检查
        - 则将该变量标记为净化（Guard 通过后后续代码已确认其安全性）

        Args:
            if_node: Tree-sitter if_statement 节点
        """
        if not TREE_SITTER_AVAILABLE or not isinstance(if_node, Node):
            return

        # 提取子节点：condition 和 consequence
        condition_node: Any | None = None
        consequence_node: Any | None = None
        has_else: bool = False

        for child in if_node.children:
            ctype = child.type
            if ctype in ("parenthesized_expression", "condition"):
                condition_node = child
            elif ctype in ("statement_block", "block", "suite", "compound_statement"):
                if consequence_node is None:
                    consequence_node = child
                else:
                    has_else = True  # 第二个块是 else
            elif ctype == "else_clause":
                has_else = True
            # Python: 直接跟 return_statement / raise_statement（无 block 包裹）
            elif ctype in self._GUARD_EXIT_TYPES and consequence_node is None:
                consequence_node = child

        # 如果有 else 分支，不视为简单 guard clause（可能是 if-else 净化分支）
        if has_else:
            return

        if condition_node is None:
            return

        # 检查 consequence 是否只包含退出语句
        if not self._is_exit_only_block(consequence_node):
            return

        # 从条件表达式中提取被检查的变量名
        guard_vars = self._extract_guard_vars(condition_node)
        if not guard_vars:
            return

        line = if_node.start_point[0] + 1 if hasattr(if_node, "start_point") else 0

        # 收集此 if 节点用于 Dominator Tree 构建（后续批量处理）
        self._guard_if_nodes.append(if_node)

        for var_name in guard_vars:
            # 已经净化的变量不重复处理
            if self.graph.is_var_sanitized(var_name):
                continue

            # 路径 1：简单变量在 _variables 中追踪
            if var_name in self._variables:
                existing_node = self._variables[var_name]
                self.graph.mark_sanitized(var_name, "guard_clause_validation")
                existing_node.is_tainted = False
                logger.debug(
                    "Guard Clause 净化(变量): '%s' 在 if-early-return 后标记为已净化（行 %d）",
                    var_name,
                    line,
                )
                continue

            # 路径 2：member_expression（如 req.body.id）直接存在于 taint_graph 中
            # 同时将以该表达式为前缀的所有子路径一并净化（req.body.id / req.body 等）
            matched_in_graph = False
            for node_name in list(self.graph._nodes.keys()):
                graph_node = self.graph._nodes[node_name]
                # node_name 是节点 id（hash），用 graph_node.name 比较
                if graph_node.name == var_name or graph_node.name.startswith(var_name + "."):
                    self.graph.mark_sanitized(graph_node.name, "guard_clause_validation")
                    graph_node.is_tainted = False
                    matched_in_graph = True
                    logger.debug(
                        "Guard Clause 净化(graph): '%s' 在 if-early-return 后标记为已净化（行 %d）",
                        graph_node.name,
                        line,
                    )
            if not matched_in_graph:
                # 变量未被追踪，可能是尚未遇到的标识符，预先注册净化以防后续污点扩散
                self.graph.mark_sanitized(var_name, "guard_clause_validation")
                logger.debug(
                    "Guard Clause 净化(预登记): '%s' 预先标记为已净化（行 %d）",
                    var_name,
                    line,
                )

    def _is_exit_only_block(self, block_node: Any | None) -> bool:
        """
        判断块（statement_block / suite）是否只包含退出语句。

        空块也视为退出（等价于 ``if (x) {}``，虽然不常见但不误判）。
        """
        if block_node is None:
            return False

        # 直接是退出语句节点（Python 无 block 包裹的情况）
        if block_node.type in self._GUARD_EXIT_TYPES:
            return True

        exit_found = False
        for child in block_node.children:
            ctype = child.type
            if ctype in ("{", "}", ":", "\n", "comment"):
                continue
            if ctype in self._GUARD_EXIT_TYPES:
                exit_found = True
            else:
                # 块中有非退出语句 → 不是纯 guard clause
                return False

        return exit_found

    def _extract_guard_vars(self, condition_node: Any) -> list[str]:
        """
        从 Guard Clause 的条件节点中提取被验证的变量名。

        模式：
        - ``!x``                       → x
        - ``!check(x)``                → x（check 具有验证语义）
        - ``x === null``               → x
        - ``x == undefined``           → x
        - ``typeof x !== 'string'``    → x
        - ``!x || !y``                 → [x, y]
        - ``x``                        → x（err 等直接真值检查）
        """
        vars_found: list[str] = []
        self._extract_guard_vars_recursive(condition_node, vars_found)
        return vars_found

    def _extract_guard_vars_recursive(self, node: Any, result: list[str]) -> None:
        """递归从条件节点提取变量名。"""
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        ntype = node.type

        # 括号表达式：(cond) → 穿透
        if ntype == "parenthesized_expression":
            for child in node.children:
                if child.type not in ("(", ")"):
                    self._extract_guard_vars_recursive(child, result)
            return

        # 逻辑非：!x 或 !check(x)
        if ntype == "unary_expression":
            children = [c for c in node.children if c.type not in ("!",)]
            for child in children:
                self._extract_guard_vars_recursive(child, result)
            return

        # 直接标识符
        if ntype == "identifier":
            name = self._get_node_text(node) or ""
            if name:
                result.append(name)
            return

        # member_expression：req.body.id / req.query.name 等
        # 提取完整表达式文本作为变量名（用于 taint_graph 精确匹配）
        if ntype == "member_expression":
            full_text = self._get_node_text(node)
            if full_text:
                result.append(full_text)
            return

        # 函数调用：check(x) → 提取参数中的标识符（仅限验证语义函数）
        if ntype in ("call_expression", "call"):
            callee_name = ""
            for child in node.children:
                if child.type in ("identifier", "member_expression", "attribute"):
                    callee_name = self._get_node_text(child) or ""
                    break
            # 检查是否具有验证语义
            lower_callee = callee_name.lower().split(".")[-1]
            is_validator = any(lower_callee.startswith(p) for p in self._GUARD_FUNC_PREFIXES)
            if is_validator:
                for child in node.children:
                    if child.type in ("arguments", "argument_list"):
                        for arg in child.children:
                            if arg.type not in (",", "(", ")"):
                                self._extract_guard_vars_recursive(arg, result)
            return

        # 二元表达式：x === null / x !== undefined / typeof x !== 'string'
        if ntype in ("binary_expression",):
            op_text = ""
            for child in node.children:
                if child.type in ("===", "!==", "==", "!=", "||", "&&"):
                    op_text = child.type
                    break
            # null/undefined 检查
            null_check_ops = {"===", "!==", "==", "!="}
            if op_text in null_check_ops:
                for child in node.children:
                    if child.type == "identifier":
                        name = self._get_node_text(child) or ""
                        if name and name not in ("null", "undefined", "None", "true", "false"):
                            result.append(name)
                return
            # 逻辑或/与：递归两侧（!x || !y）
            if op_text in ("||", "&&"):
                for child in node.children:
                    if child.type not in ("||", "&&"):
                        self._extract_guard_vars_recursive(child, result)
                return

        # typeof 表达式
        if ntype == "unary_expression":
            op_children = [c for c in node.children if c.type not in ("typeof", "void", "delete")]
            for child in op_children:
                self._extract_guard_vars_recursive(child, result)
            return

        # Python 比较：x is None / x is not None
        if ntype == "comparison_operator":
            for child in node.children:
                if child.type == "identifier":
                    name = self._get_node_text(child) or ""
                    if name and name not in ("None", "True", "False"):
                        result.append(name)
            return

        # Python not 表达式
        if ntype == "not_operator":
            for child in node.children:
                if child.type != "not":
                    self._extract_guard_vars_recursive(child, result)
            return

        # Python boolean_operator：x or y / x and y
        if ntype == "boolean_operator":
            for child in node.children:
                if child.type not in ("or", "and"):
                    self._extract_guard_vars_recursive(child, result)

    _ROUTE_METHODS = {"get", "post", "put", "delete", "patch", "all", "use", "options", "head"}
    # 静态白名单：常见约定变量名，动态部分见 _express_router_vars
    _ROUTE_OBJECTS = {"app", "router", "route", "server"}

    # Express Router 创建模式：匹配 express.Router() / Router() 调用
    _ROUTER_CREATION_RE = re.compile(
        r"""
        (?:express\.Router|Router)\s*\(   # express.Router( 或 Router(
        """,
        re.VERBOSE,
    )

    def _check_express_route(self, node: Any) -> None:
        """
        识别路由注册调用并将回调的第一个参数（req）标记为 Source。

        覆盖模式：
        - app.get('/path', (req, res) => ...)          — 静态白名单
        - router.post('/path', handler)                 — 静态白名单
        - apiRouter.put('/path', (req, res) => ...)     — 动态追踪（express.Router()）
        - v1.use('/path', middleware)                    — 动态追踪（express.Router()）
        """
        method_name = None
        object_name = None
        for child in node.children:
            if child.type == "member_expression":
                for subchild in child.children:
                    if subchild.type == "identifier":
                        object_name = self._get_node_text(subchild)
                    elif subchild.type == "property_identifier":
                        method_name = self._get_node_text(subchild)
        if not method_name or not object_name:
            return
        # 对象名必须是静态白名单或动态追踪到的 Router 实例
        is_route_object = object_name.lower() in self._ROUTE_OBJECTS or object_name in self._express_router_vars
        if method_name.lower() not in self._ROUTE_METHODS or not is_route_object:
            return
        line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
        for child in node.children:
            if child.type != "arguments":
                continue
            for arg in child.children:
                if arg.type in ("arrow_function", "function_expression", "function"):
                    req_param = self._extract_first_param(arg)
                    if req_param:
                        n = self.graph.add_node(
                            name=req_param,
                            node_type=NodeType.SOURCE,
                            file_path=self._current_file,
                            line=line,
                            source_pattern="express_route_callback",
                            code_snippet=req_param,
                        )
                        self._variables[req_param] = n
                    return

    def _extract_first_param(self, func_node: Any) -> str | None:
        """提取函数第一个参数名。(req, res) => {} -> 'req'"""
        for child in func_node.children:
            if child.type == "formal_parameters":
                for param in child.children:
                    if param.type == "identifier":
                        return self._get_node_text(param)
        return None

    # 已知的 HTTP 请求对象参数名（Express / Koa / Fastify 等常见约定）
    _KNOWN_REQUEST_PARAMS = frozenset(
        {
            "req",
            "request",
            "ctx",
            "context",
            "event",
            "e",
        }
    )

    def _register_named_handler_function(self, node: Any) -> None:
        """
        识别具名函数定义 ``function foo(req, res, next) { ... }``。

        若第一个参数名匹配已知 HTTP 请求对象约定（req/request/ctx 等），
        则将该函数注册为"污点处理函数"摘要，并将第一个参数在图中标记为 Source。

        后续 ``_process_js_var_declaration`` 遇到 ``const result = foo(req, ...)``
        时，若传入参数已 tainted，则结果变量也继承污点。

        这是过程摘要（function summary）的最小实现，覆盖 Express 中典型的
        ``function validate(req, res, next) { ... }`` 中间件模式。

        Args:
            node: tree-sitter ``function_declaration`` 节点
        """
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        # 提取函数名
        func_name: str | None = None
        for child in node.children:
            if child.type == "identifier":
                func_name = self._get_node_text(child)
                break

        if not func_name:
            return

        # 提取参数列表
        params: list[str] = []
        for child in node.children:
            if child.type == "formal_parameters":
                for param in child.children:
                    if param.type == "identifier":
                        pname = self._get_node_text(param)
                        if pname:
                            params.append(pname)

        if not params:
            return

        first_param = params[0]

        # 判断第一个参数是否匹配已知 Source 参数名约定
        is_tainted_handler = first_param in self._KNOWN_REQUEST_PARAMS

        # 也检查该参数名是否已被外部调用点标记为 tainted
        if not is_tainted_handler and first_param in self._variables:
            existing = self._variables[first_param]
            if existing.is_tainted or existing.node_type == NodeType.SOURCE:
                is_tainted_handler = True

        if not is_tainted_handler:
            return

        line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0

        # 注册函数摘要
        self._tainted_functions[func_name] = {
            "first_param": first_param,
            "tainted": True,
            "line": line,
        }

        # 将函数内的 first_param 标记为 Source 节点（使函数体内的分析可见）
        if first_param not in self._variables:
            n = self.graph.add_node(
                name=first_param,
                node_type=NodeType.SOURCE,
                file_path=self._current_file,
                line=line,
                source_pattern="named_handler_first_param",
                code_snippet=f"function {func_name}({', '.join(params)})",
            )
            self._variables[first_param] = n

        logger.debug(
            "函数摘要注册: %s(%s, ...) → first_param '%s' 标记为 tainted",
            func_name,
            first_param,
            first_param,
        )

    def _register_arrow_function_as_handler(
        self,
        var_name: str,
        func_node: Any,
        line: int,
    ) -> None:
        """
        识别箭头函数/函数表达式赋值 ``const handler = (req, res) => { ... }``。

        若第一个参数名匹配已知 HTTP 请求对象约定（req/request/ctx 等），
        则：
        1. 将该函数注册到 ``_tainted_functions``（函数名为变量名）
        2. 将第一个参数在图中标记为 Source 节点

        这补全了 ``_register_named_handler_function`` 只处理 ``function_declaration``
        而漏掉箭头函数赋值的盲区。

        Args:
            var_name:  赋值目标变量名（函数摘要的函数名）
            func_node: tree-sitter ``arrow_function`` 或 ``function_expression`` 节点
            line:      行号
        """
        if not TREE_SITTER_AVAILABLE or not isinstance(func_node, Node):
            return

        first_param = self._extract_first_param(func_node)
        if not first_param:
            # 若首参数是解构模式 ({ body, query })，提取其内部属性
            first_param = self._extract_first_destructured_param(func_node)

        if not first_param:
            return

        if first_param not in self._KNOWN_REQUEST_PARAMS:
            return

        # 注册函数摘要（以变量名作为函数名）
        self._tainted_functions[var_name] = {
            "first_param": first_param,
            "tainted": True,
            "line": line,
        }

        # 将首参数标记为 Source 节点
        if first_param not in self._variables:
            n = self.graph.add_node(
                name=first_param,
                node_type=NodeType.SOURCE,
                file_path=self._current_file,
                line=line,
                source_pattern="arrow_function_first_param",
                code_snippet=f"const {var_name} = ({first_param}, ...) => {{...}}",
            )
            self._variables[first_param] = n

        logger.debug(
            "箭头函数摘要注册: const %s = (%s, ...) => {...}，first_param '%s' 标记为 tainted",
            var_name,
            first_param,
            first_param,
        )

    def _extract_first_destructured_param(self, func_node: Any) -> str | None:
        """
        提取函数第一个参数为解构模式时的内部第一个属性名。

        ``(({ body, query }) => {})`` → ``'body'``

        这使得 ``function foo({ body, query })`` 也能被感知为污点处理函数。
        """
        if not TREE_SITTER_AVAILABLE or not isinstance(func_node, Node):
            return None
        for child in func_node.children:
            if child.type == "formal_parameters":
                for param in child.children:
                    if param.type == "object_pattern":
                        props = self._extract_destructured_properties(param)
                        return props[0] if props else None
        return None

    def _process_js_var_declaration(self, node: Any) -> None:
        """
        处理 JavaScript 变量声明。

        覆盖场景：
        - 普通赋值 ``const x = req.query.id``
        - 解构赋值 ``const { body, query } = req``
        - 箭头函数赋值 ``const handler = (req, res) => { ... }``
        - 函数表达式赋值 ``const handler = function(req, res) { ... }``
        """
        for child in node.children:
            if child.type != "variable_declarator":
                continue
            left_node = None
            value_node = None
            for subchild in child.children:
                if subchild.type == "identifier":
                    left_node = subchild
                elif subchild.type == "object_pattern":
                    left_node = subchild
                elif subchild.type not in ("=",):
                    value_node = subchild
            if left_node is None or value_node is None:
                continue
            line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
            value_text = self._get_node_text(value_node) or ""
            if left_node.type == "object_pattern":
                props = self._extract_destructured_properties(left_node)
                if props:
                    self._process_js_destructuring(props, value_text, line)
            elif left_node.type == "identifier":
                var_name = self._get_node_text(left_node)
                if not var_name:
                    continue
                # 箭头函数/函数表达式赋值：const handler = (req, res) => {}
                # 将首参数匹配已知 Source 名的函数注册为 handler 摘要
                if value_node.type in ("arrow_function", "function_expression"):
                    self._register_arrow_function_as_handler(var_name, value_node, line)
                elif value_text:
                    # 动态追踪 Express Router 实例：
                    # const apiRouter = express.Router() / const v1 = Router()
                    if self._ROUTER_CREATION_RE.search(value_text):
                        self._express_router_vars.add(var_name)
                        logger.debug(
                            "Express Router 实例追踪: %s = %s",
                            var_name,
                            value_text[:60],
                        )
                    self._register_variable(var_name, value_text, line)

    def _extract_destructured_properties(self, pattern_node: Any) -> list[str]:
        """
        从 object_pattern 提取属性名（取局部变量名，即别名）。

        ``{ name, email }``        → ``['name', 'email']``（shorthand）
        ``{ age: userAge }``       → ``['userAge']``（取别名，不取 key）
        ``{ body: { id } }``       → ``['id']``（嵌套解构，取最内层 identifier）
        """
        props: list[str] = []
        for child in pattern_node.children:
            if child.type == "shorthand_property_identifier_pattern":
                name = self._get_node_text(child)
                if name:
                    props.append(name)
            elif child.type == "pair_pattern":
                # pair_pattern: key : value_pattern
                # 取最后一个 identifier 作为别名（value 侧），而非 key 侧
                identifiers: list[str] = []
                for subchild in child.children:
                    if subchild.type == "identifier":
                        n = self._get_node_text(subchild)
                        if n:
                            identifiers.append(n)
                if identifiers:
                    props.append(identifiers[-1])
        return props

    def _process_js_destructuring(self, properties: list[str], source_expr: str, line: int) -> None:
        """解构赋值：若 source_expr 为 Source 或已污染变量，则解构出的属性继承污点。"""
        src_node = self.graph.get_node_by_name(source_expr, self._current_file) or self._variables.get(source_expr)
        source_pattern = self.registry.find_source(source_expr, self.language)
        source_tainted = source_pattern is not None or (src_node is not None and src_node.is_tainted)
        if source_tainted and src_node is None and source_pattern is not None:
            src_node = self.graph.add_node(
                name=source_expr,
                node_type=NodeType.SOURCE,
                file_path=self._current_file,
                line=line,
                source_pattern=source_pattern.name,
                code_snippet=source_expr,
            )
            self._variables[source_expr] = src_node
        for prop in properties:
            if source_tainted:
                node = self.graph.add_node(
                    name=prop,
                    node_type=NodeType.VARIABLE,
                    file_path=self._current_file,
                    line=line,
                    code_snippet=f"{prop} = {source_expr}.{prop}",
                )
                node.is_tainted = True
                node.taint_level = 4
                self._variables[prop] = node
                if src_node:
                    self.graph.add_edge(
                        src_node.id,
                        node.id,
                        EdgeType.PROPAGATION,
                        line=line,
                        description=f"destructuring: {source_expr} -> {prop}",
                    )
            else:
                node = self.graph.add_node(
                    name=prop,
                    node_type=NodeType.VARIABLE,
                    file_path=self._current_file,
                    line=line,
                    code_snippet=f"{prop} = {source_expr}.{prop}",
                )
                self._variables[prop] = node

    def _process_js_assignment(self, node: Any) -> None:
        """处理 JavaScript 赋值表达式"""
        left_text = None
        right_text = None

        for i, child in enumerate(node.children):
            if i == 0:  # 左侧
                left_text = self._get_node_text(child)
            elif child.type == "=":
                continue
            else:  # 右侧
                right_text = self._get_node_text(child)

        if left_text and right_text:
            line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
            # 动态追踪 Express Router 实例赋值（非 const/let/var 形式）
            if self._ROUTER_CREATION_RE.search(right_text):
                self._express_router_vars.add(left_text)
                logger.debug(
                    "Express Router 实例追踪（赋值）: %s = %s",
                    left_text,
                    right_text[:60],
                )
            self._register_variable(left_text, right_text, line)

    def _process_php_assignment(self, node: Any) -> None:
        """
        处理 PHP 赋值表达式。

        节点结构：assignment_expression 含 left（variable_name 等）、operator、right。
        将 $var 名与右值文本注册到污点图，供 Source/Sink 匹配使用。
        """
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return
        left_text: str | None = None
        right_text: str | None = None
        for child in node.children:
            if child.type in ("=", ".=", "+=", "-="):
                continue
            if left_text is None:
                left_text = self._get_node_text(child)
            else:
                right_text = self._get_node_text(child)
                break
        if left_text and right_text:
            line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
            self._register_variable(left_text, right_text, line)

    def _process_java_assignment(self, node: Any) -> None:
        """
        处理 Java 赋值与局部变量声明。

        支持：
        - local_variable_declaration: String id = request.getParameter("id");
        - assignment_expression: id = request.getParameter("id");
        """
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        # 局部变量声明：可能包含多个 variable_declarator
        if node.type == "local_variable_declaration":
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node: Node | None = None
                    value_node: Node | None = None
                    for sub in child.children:
                        if sub.type == "identifier" and name_node is None:
                            name_node = sub
                        elif sub.type in ("=",):
                            continue
                        else:
                            value_node = sub
                            break
                    if name_node is None or value_node is None:
                        continue
                    name = self._get_node_text(name_node) or ""
                    value = self._get_node_text(value_node) or ""
                    if not name or not value:
                        continue
                    line = child.start_point[0] + 1 if hasattr(child, "start_point") else 0
                    self._register_variable(name, value, line)
            return

        # 一般赋值表达式：left op right
        if node.type == "assignment_expression":
            left_text: str | None = None
            right_text: str | None = None
            for child in node.children:
                if child.type in ("=", "+=", "-=", "*=", "/=", "&=", "|=", "^=", "%=", "<<=", ">>="):
                    continue
                if left_text is None:
                    left_text = self._get_node_text(child)
                else:
                    right_text = self._get_node_text(child)
                    break
            if left_text and right_text:
                line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
                self._register_variable(left_text, right_text, line)

    def _process_go_assignment(self, node: Any) -> None:
        """
        处理 Go 赋值与短变量声明。

        支持：
        - short_var_declaration: id := r.FormValue("id")
        - assignment_statement: id = r.FormValue("id")

        为降低复杂度，当前实现主要覆盖单变量 + 单表达式场景，
        多重赋值在后续需要时再扩展。
        """
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        # 短变量声明：expression_list ':=' expression_list（如 `a := f()` / `a, b := g()`）
        if node.type == "short_var_declaration":
            expr_lists = [c for c in node.children if c.type == "expression_list"]
            if len(expr_lists) < 2:
                return

            left_nodes = [c for c in expr_lists[0].children if c.type == "identifier"]
            right_nodes = [c for c in expr_lists[1].children if c.type != ","]
            if not left_nodes or not right_nodes:
                return

            line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
            for idx, left in enumerate(left_nodes):
                if idx >= len(right_nodes):
                    break
                name = self._get_node_text(left) or ""
                right_text = self._get_node_text(right_nodes[idx]) or ""
                if name and right_text:
                    self._register_variable(name, right_text, line)
            return

        # 一般赋值语句：expression_list op expression_list
        if node.type == "assignment_statement":
            left_names: list[str] = []
            right_exprs: list[Node] = []
            saw_op = False
            for child in node.children:
                if child.type == "expression_list" and not saw_op:
                    for expr in child.children:
                        if expr.type == "identifier":
                            name = self._get_node_text(expr) or ""
                            if name:
                                left_names.append(name)
                elif child.type in ("=", "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "|=", "^="):
                    saw_op = True
                elif child.type == "expression_list" and saw_op:
                    for expr in child.children:
                        if expr.type in (",",):
                            continue
                        right_exprs.append(expr)
            if len(left_names) == 1 and len(right_exprs) == 1:
                right_text = self._get_node_text(right_exprs[0]) or ""
                if right_text:
                    line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
                    self._register_variable(left_names[0], right_text, line)

    def _process_py_assignment(self, node: Any) -> None:
        """
        处理 Python 赋值。

        支持：
        - 简单赋值：``uid = request.GET['id']``
        - 多目标赋值：``a = b = expr``
        - 元组解包（单层）：``a, b = func()``
        """
        children = list(node.children)
        if len(children) < 3:
            return

        right_node = children[-1]
        right_text = self._get_node_text(right_node) or ""
        line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0

        # 收集左侧所有标识符（支持元组解包）
        left_names: list[str] = []
        for child in children[:-2]:  # 排除 "=" 和右值
            if child.type == "identifier":
                n = self._get_node_text(child)
                if n:
                    left_names.append(n)
            elif child.type == "pattern_list":
                # 元组解包：a, b = ...
                for sub in child.children:
                    if sub.type == "identifier":
                        n = self._get_node_text(sub)
                        if n:
                            left_names.append(n)

        if not left_names or not right_text:
            return

        # normalize right_text：去掉下标/调用后缀再做 Source 匹配
        # 例如 request.GET['id'] → request.GET，request.args.get('x') → request.args
        normalized_right = self._normalize_py_source_expr(right_text)

        for var_name in left_names:
            # 优先用 normalized 匹配 source；注册时保留原始 right_text 作 code_snippet
            self._register_variable_py(var_name, normalized_right, right_text, line)

    # ------------------------------------------------------------------
    # Python 专属辅助
    # ------------------------------------------------------------------
    _PY_SOURCE_STRIP_RE = re.compile(
        r"""
        (\[['"][^'"]*['"]\]   # ['key'] 或 ["key"]
        |\[\w+\]              # [varname]
        |\.get\s*\([^)]*\)   # .get(...)
        |\.\w+\s*\([^)]*\)   # 任意 .method(...)
        )+
        $
        """,
        re.VERBOSE,
    )

    def _normalize_py_source_expr(self, expr: str) -> str:
        """
        将 ``request.GET['id']``、``request.args.get('x', '')`` 等还原为
        ``request.GET``、``request.args``，方便与注册表中的字符串前缀做匹配。
        """
        return self._PY_SOURCE_STRIP_RE.sub("", expr).strip()

    def _register_variable_py(self, name: str, normalized_value: str, raw_value: str, line: int) -> None:
        """
        Python 专用变量注册。

        - 先以 *normalized_value* 查 source registry（去掉了下标/调用后缀）。
        - Sanitizer 检查仍用 *raw_value*（更精确）。
        - code_snippet 使用 ``name = raw_value``。
        """
        # Sanitizer 检查
        sanitizer_pattern = self.registry.find_sanitizer(raw_value, self.language)
        if sanitizer_pattern:
            node = self.graph.add_node(
                name=name,
                node_type=NodeType.VARIABLE,
                file_path=self._current_file,
                line=line,
                code_snippet=f"{name} = {raw_value}",
            )
            node.is_tainted = False
            self._variables[name] = node
            self.graph.mark_sanitized(name, sanitizer_pattern.name)
            return

        # Source 检查（normalized）
        source_pattern = self.registry.find_source(normalized_value, self.language)
        if source_pattern:
            node = self.graph.add_node(
                name=name,
                node_type=NodeType.SOURCE,
                file_path=self._current_file,
                line=line,
                source_pattern=source_pattern.name,
                code_snippet=f"{name} = {raw_value}",
            )
        else:
            node = self.graph.add_node(
                name=name,
                node_type=NodeType.VARIABLE,
                file_path=self._current_file,
                line=line,
                code_snippet=f"{name} = {raw_value}",
            )

        self._variables[name] = node

        # 污点传播：右值中引用了已知污染变量
        for var_name, var_node in list(self._variables.items()):
            if var_name != name and var_node.is_tainted and var_name in raw_value:
                self.graph.add_edge(
                    var_node.id,
                    node.id,
                    EdgeType.PROPAGATION,
                    line=line,
                    description=f"Taint propagation: {var_name} -> {name}",
                )

    def _register_variable(self, name: str, value: str, line: int) -> None:
        """注册变量到污点图。2.1 增加：Sanitizer 感知（parseInt/escapeHtml 等标记为已净化）。"""
        # 检查值是否经过 Sanitizer（如 parseInt(x)、escapeHtml(x)）
        sanitizer_pattern = self.registry.find_sanitizer(value, self.language)
        if sanitizer_pattern:
            node = self.graph.add_node(
                name=name,
                node_type=NodeType.VARIABLE,
                file_path=self._current_file,
                line=line,
                code_snippet=f"{name} = {value}",
            )
            node.is_tainted = False
            self._variables[name] = node
            self.graph.mark_sanitized(name, sanitizer_pattern.name)
            return

        # 检查值是否是 Source
        source_pattern = self.registry.find_source(value, self.language)

        if source_pattern:
            # 创建 Source 节点
            node = self.graph.add_node(
                name=name,
                node_type=NodeType.SOURCE,
                file_path=self._current_file,
                line=line,
                source_pattern=source_pattern.name,
                code_snippet=f"{name} = {value}",
            )
        else:
            # 创建普通变量节点
            node = self.graph.add_node(
                name=name,
                node_type=NodeType.VARIABLE,
                file_path=self._current_file,
                line=line,
                code_snippet=f"{name} = {value}",
            )

        # 记录变量映射
        self._variables[name] = node

        # 函数摘要传播：若右值是对已注册"污点处理函数"的调用
        # 例如：const result = validate(req, res) 且 validate 在 _tainted_functions 中
        # 则将 result 也标记为 tainted
        self._propagate_taint_from_function_call(name, value, node, line)

        # 检查值是否引用了已知变量（污点传播：拼接/模板字符串等）
        for var_name, var_node in self._variables.items():
            if var_name != name and var_name in value:
                # 添加传播边
                self.graph.add_edge(
                    var_node.id,
                    node.id,
                    EdgeType.PROPAGATION,
                    line=line,
                    description=f"Taint propagation: {var_name} -> {name}",
                )

    # 函数调用模式：捕获 funcName(...)
    _FUNC_CALL_RE = re.compile(r"^([\w$]+)\s*\(")

    def _propagate_taint_from_function_call(
        self,
        var_name: str,
        value: str,
        node: TaintNode,
        line: int,
    ) -> None:
        """
        函数摘要传播：若右值是对已注册污点处理函数的调用，
        且传入参数中包含已 tainted 的变量，则将赋值目标也标记为 tainted。

        场景：``const sanitized = validate(req, input)``
        若 ``validate`` 已在 ``_tainted_functions`` 中（首参数 req 为 tainted），
        则 ``sanitized`` 也继承污点，后续流入 Sink 时能被正确检出。

        Args:
            var_name: 赋值目标变量名
            value:    赋值右值文本
            node:     赋值目标在污点图中的节点
            line:     行号
        """
        if not self._tainted_functions:
            return

        m = self._FUNC_CALL_RE.match(value.strip())
        if not m:
            return

        called_func = m.group(1)
        func_summary = self._tainted_functions.get(called_func)
        if not func_summary or not func_summary.get("tainted"):
            return

        # 校验函数防护：若赋值目标变量名或被调函数名具有"校验/布尔判断"语义，
        # 则不传播 taint 到返回值，避免 `const isValid = validate(req)` 误报。
        # 这类变量通常是布尔值，不会直接流入 Sink。
        _VALIDATOR_PREFIXES = ("is", "has", "can", "should", "check", "valid", "verify", "assert")
        _VALIDATOR_SUFFIXES = ("valid", "check", "result", "ok", "flag", "bool")
        lower_var = var_name.lower()
        lower_func = called_func.lower()
        if (
            any(lower_var.startswith(p) for p in _VALIDATOR_PREFIXES)
            or any(lower_var.endswith(s) for s in _VALIDATOR_SUFFIXES)
            or any(lower_func.startswith(p) for p in _VALIDATOR_PREFIXES)
        ):
            logger.debug(
                "函数摘要传播跳过（校验函数）: %s = %s(...) 具有校验语义",
                var_name,
                called_func,
            )
            return

        # 检查调用参数中是否包含已 tainted 的变量
        call_args_text = value[m.end() :]  # 取括号内的参数文本
        arg_tainted = any(
            tvar in call_args_text
            for tvar, tnode in self._variables.items()
            if tnode.is_tainted or tnode.node_type == NodeType.SOURCE
        )

        if not arg_tainted:
            # 也检查首参数是否是已知 Source 名（如 req 直接传入）
            first_param = func_summary.get("first_param", "")
            arg_tainted = first_param and first_param in call_args_text

        if arg_tainted:
            node.is_tainted = True
            node.taint_level = max(node.taint_level, 3)
            # 尝试连接到 tainted 的源节点
            for tvar, tnode in list(self._variables.items()):
                if (tnode.is_tainted or tnode.node_type == NodeType.SOURCE) and tvar in call_args_text:
                    self.graph.add_edge(
                        tnode.id,
                        node.id,
                        EdgeType.PROPAGATION,
                        line=line,
                        description=f"function summary: {tvar} -> {called_func}() -> {var_name}",
                    )
                    break
            logger.debug(
                "函数摘要污点传播: %s = %s(...) 中参数 tainted，%s 标记为 tainted",
                var_name,
                called_func,
                var_name,
            )

    def _identify_sources_and_sinks(self, node: Any) -> None:
        """
        识别 Source 和 Sink。

        节点类型差异：
        - JS/TS : call_expression, member_expression
        - Python : call, attribute
        """
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        # 函数调用（JS: call_expression，Python: call，PHP: function_call_expression，Java: method_invocation/object_creation_expression）
        if node.type in (
            "call_expression",
            "call",
            "function_call_expression",
            "method_invocation",
            "object_creation_expression",
        ):
            self._check_call_expression(node)

        # 成员/属性表达式（JS: member_expression，Python: attribute，PHP: member_access_expression / object_member_expression，Java: field_access，Go: selector_expression）
        elif node.type in (
            "member_expression",
            "attribute",
            "member_access_expression",
            "object_member_expression",
            "field_access",
            "selector_expression",
        ):
            self._check_member_expression(node)

        # 递归处理子节点
        for child in node.children:
            self._identify_sources_and_sinks(child)

    def _check_call_expression(self, node: Any) -> None:
        """
        检查函数调用是否是 Sink 或 Sanitizer。

        Python 的 ``call`` 节点结构：
            call
              attribute   (cur.execute / os.system / subprocess.run)
              argument_list

        为了让 Sink 注册表的模式（``cursor.execute(``）能匹配到
        ``cur.execute(...)`` 这类变量名不固定的调用，
        这里对 Python 额外提取 **callee 部分**（attribute 文本 + "("）
        与完整 call_text 同时做匹配。
        """
        call_text = self._get_node_text(node) or ""
        line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0

        # 提取 callee 文本（即函数/方法名部分）
        # JS: node.children[0] 通常为 identifier / member_expression
        # Python: node.children[0] 通常为 attribute（"cur.execute"）或 identifier
        # PHP: function_call_expression 可能为 name 或 object_member_expression
        # Java: method_invocation / object_creation_expression，可能包含 field_access
        # Go: call_expression 中的 selector_expression / identifier
        callee_text = ""
        for child in node.children:
            if child.type in (
                "identifier",
                "member_expression",
                "attribute",
                "name",
                "object_member_expression",
                "field_access",
                "selector_expression",
            ):
                callee_text = self._get_node_text(child) or ""
                break

        # 构建用于 sink 匹配的候选文本列表
        # 用 callee_text + "(" 可匹配 ``cursor.execute(`` 模式，
        # 同时保留 call_text 完整形式兜底。
        candidates = []
        if callee_text:
            candidates.append(callee_text + "(")  # 最精确：仅方法签名
            # 对 Python attribute（如 cur.execute），额外提取末段（execute(）
            if "." in callee_text:
                tail = callee_text.rsplit(".", 1)[-1]
                candidates.append("." + tail + "(")  # .execute(
        # Go 语言中 call_text 可能包含回调函数体，使用完整文本会把嵌套调用误识别为当前 sink。
        if self.language != "go" or not callee_text:
            candidates.append(call_text)  # 兜底：完整调用文本

        # 逐个候选尝试匹配 Sink
        sink_pattern = None
        for cand in candidates:
            sink_pattern = self.registry.find_sink(cand, self.language)
            if sink_pattern:
                break

        if sink_pattern:
            # SQL Sink：检测参数化查询（安全形式不报告）
            if sink_pattern.category.value == "sql_injection" and self._is_parameterized_query(node):
                pass  # 参数化查询，忽略
            else:
                sink_node = self.graph.add_node(
                    name=call_text,
                    node_type=NodeType.SINK,
                    file_path=self._current_file,
                    line=line,
                    sink_pattern=sink_pattern.name,
                    code_snippet=call_text,
                    category=sink_pattern.category.value,
                    severity=sink_pattern.severity,
                    cwe=sink_pattern.cwe,
                )
                self._check_call_arguments(node, sink_node)

        # Sanitizer 检查
        sanitizer_pattern = None
        for cand in candidates:
            sanitizer_pattern = self.registry.find_sanitizer(cand, self.language)
            if sanitizer_pattern:
                break

        if sanitizer_pattern:
            self.graph.add_node(
                name=call_text,
                node_type=NodeType.SANITIZER,
                file_path=self._current_file,
                line=line,
                code_snippet=call_text,
            )

    _PARAM_PLACEHOLDER_RE = re.compile(r"\?|%s|%\([\w]+\)s|:\w+", re.IGNORECASE)

    def _is_parameterized_query(self, call_node: Any) -> bool:
        """
        判断 SQL 调用是否使用参数化查询（安全形式）。

        安全条件（满足其一）：
        1. 第一个字符串参数包含 ``?``、``%s``、``%(name)s``、``:name`` 占位符，
           且存在第二个参数（params tuple/list）；
        2. 第一个参数是纯字面量字符串（不含任何变量插值）且不含 ``+`` 拼接。
        """
        if not TREE_SITTER_AVAILABLE or not isinstance(call_node, Node):
            return False

        arg_nodes = []
        for child in call_node.children:
            if child.type in ("arguments", "argument_list"):
                for arg in child.children:
                    if arg.type not in (",", "(", ")"):
                        arg_nodes.append(arg)
                break

        if not arg_nodes:
            return False

        first_arg = arg_nodes[0]
        first_text = self._get_node_text(first_arg) or ""

        # 含占位符且有第二个参数（params）
        if self._PARAM_PLACEHOLDER_RE.search(first_text) and len(arg_nodes) >= 2:
            return True

        # 纯字面量（string 节点，无 binary_operator / identifier 子节点）
        if first_arg.type == "string":
            return True

        return False

    def _check_member_expression(self, node: Any) -> None:
        """检查成员表达式"""
        expr_text = self._get_node_text(node)
        if not expr_text:
            return

        line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0

        # 检查是否是 Source（如 req.body）
        source_pattern = self.registry.find_source(expr_text, self.language)
        if source_pattern:
            self.graph.add_node(
                name=expr_text,
                node_type=NodeType.SOURCE,
                file_path=self._current_file,
                line=line,
                source_pattern=source_pattern.name,
                code_snippet=expr_text,
            )

    def _check_call_arguments(self, call_node: Any, sink_node: TaintNode) -> None:
        """
        检查函数调用的参数是否被污染。

        覆盖三种模式：
        1. 直接变量：``execute(uid)`` → uid 在 ``_variables`` 中且已污染
        2. 字符串拼接：``execute("SELECT..."+uid)`` → binary_operator/binary_expression，递归提取操作数
        3. f-string/模板：``execute(f"SELECT...{uid}")`` → Python formatted_string，提取插值变量

        节点类型差异：
        - JS arguments；Python argument_list
        """
        for child in call_node.children:
            # JS 用 "arguments"，Python 用 "argument_list"
            if child.type not in ("arguments", "argument_list"):
                continue
            for arg in child.children:
                if arg.type in (",", "(", ")"):
                    continue
                self._check_single_argument(arg, sink_node)

    def _check_single_argument(self, arg_node: Any, sink_node: TaintNode) -> None:
        """
        检查单个参数节点是否携带污点，并在图中建立参数传递边。

        递归处理：
        - identifier          → 直接查 _variables
        - binary_expression   → "str" + var 拼接，递归两侧
        - formatted_string    → Python f"...{var}..."，提取插值表达式
        - call_expression     → 直接 Source（如 request.GET.get(...)）
        - member_expression   → 直接 Source（如 request.GET）
        """
        if not TREE_SITTER_AVAILABLE or not isinstance(arg_node, Node):
            return

        atype = arg_node.type

        # ── identifier / variable_name（PHP $var）：查已知变量表 ──
        if atype in ("identifier", "variable_name"):
            var_name = self._get_node_text(arg_node) or ""
            if var_name in self._variables:
                var_node = self._variables[var_name]
                if var_node.is_tainted:
                    self.graph.add_edge(
                        var_node.id,
                        sink_node.id,
                        EdgeType.PARAMETER_PASS,
                        line=sink_node.line,
                        description=f"Tainted argument: {var_name}",
                    )
            return

        # ── binary_expression（JS）/ binary_operator（Python）：递归两侧 ──
        if atype in ("binary_expression", "binary_operator"):
            for child in arg_node.children:
                # 跳过运算符本身（+、%、.、//等）
                if child.type in (
                    "+",
                    ".",
                    "%",
                    "//",
                    "**",
                    "~",
                    "|",
                    "&",
                    "^",
                    "binary_operator",
                    "augmented_assignment",
                ):
                    continue
                self._check_single_argument(child, sink_node)
            return

        # ── Python f-string：formatted_string，提取 interpolation 子节点 ──
        if atype == "formatted_string":
            for child in arg_node.children:
                if child.type == "interpolation":
                    for sub in child.children:
                        if sub.type not in ("{", "}"):
                            self._check_single_argument(sub, sink_node)
            return

        # ── call / call_expression / member_expression / attribute / method_invocation 等：直接 Source 匹配 ──
        if atype in (
            "call_expression",
            "call",
            "member_expression",
            "attribute",
            "method_invocation",
            "field_access",
            "selector_expression",
        ):
            arg_text = self._get_node_text(arg_node) or ""
            normalized = self._normalize_py_source_expr(arg_text) if self.language == "python" else arg_text
            source_pattern = self.registry.find_source(normalized, self.language)
            if source_pattern:
                src_node = self.graph.add_node(
                    name=arg_text,
                    node_type=NodeType.SOURCE,
                    file_path=self._current_file,
                    line=sink_node.line,
                    source_pattern=source_pattern.name,
                    code_snippet=arg_text,
                )
                self.graph.add_edge(
                    src_node.id,
                    sink_node.id,
                    EdgeType.PARAMETER_PASS,
                    line=sink_node.line,
                    description=f"Direct source to sink: {arg_text}",
                )
            return

        # ── 其它节点：递归子节点（兼容 parenthesized_expression 等）──
        for child in arg_node.children:
            self._check_single_argument(child, sink_node)

    def _build_dataflow_edges(self) -> None:
        """
        构建补充数据流边。

        主要传播已在 ``_register_variable`` / ``_register_variable_py`` 中完成。
        此处做二次扫描：将 ``_variables`` 中已污染但尚未连接到任何 Sink 的节点，
        尝试匹配 Sink 注册表（针对隐式使用，如直接 return 给 Sink 的情况）。
        目前保持轻量级——后续可在此扩展 CFG 级跨块传播。
        """

    def _build_and_apply_dominator_tree(self) -> None:
        """
        基于已收集的 Guard Clause if 节点构建 CFG 和支配树，
        然后用支配关系增强 Guard Clause 净化的精确度。

        增强逻辑：
        1. 对每个 Guard 块，计算其严格支配的所有后继块
        2. 在这些块的行号范围内出现的 Sink，即使变量在 Guard 之前看似污染，
           也因为 Guard 的支配关系而被视为已净化
        3. 将被 Guard 支配范围内但已知已净化的变量，在 Sink 的所有路径上标记净化

        注意：当前实现为最小可用版本（MVP），主要验证架构可行性。
        完整实现需要将函数体内所有基础块都纳入 CFG。
        """
        if not self._guard_if_nodes:
            return

        try:
            from ..cfg.dominator_tree import DominatorTree, build_cfg_from_ast_if_statements

            # 用收集到的 Guard if 节点构建简化 CFG
            cfg = build_cfg_from_ast_if_statements(self._guard_if_nodes)
            if cfg is None or cfg.entry is None:
                return

            dom_tree = DominatorTree(cfg)
            self._dominator_tree = dom_tree

            # 收集所有 Guard 块的行号范围
            guard_line_ranges: list[tuple] = []
            for block in cfg.blocks:
                if block.is_guard and block.start_line > 0:
                    protected_ids = dom_tree.get_guard_protected_range(block.block_id)
                    for pid in protected_ids:
                        pblock = cfg.get_block(pid)
                        if pblock and pblock.start_line > 0:
                            guard_line_ranges.append((block.start_line, pblock.start_line, pblock.end_line))

            if not guard_line_ranges:
                return

            # 对在 Guard 保护范围内的 Sink 节点进行净化标记增强
            # 收集所有已被 Guard Clause 标记净化的变量名
            sanitized_by_guard = {
                var_name
                for var_name in self._variables
                if self.graph.is_var_sanitized(var_name)
                and self.graph.get_sanitizer_name(var_name) == "guard_clause_validation"
            }

            if not sanitized_by_guard:
                return

            # 对污点图中的 Sink 节点，检查其是否位于被 Guard 支配的行范围内
            # 若是，则将流向该 Sink 的已净化变量的污点路径标记为净化
            for node_id, node in list(self.graph._nodes.items()):  # type: ignore[attr-defined]
                from .taint_graph import NodeType

                if node.node_type != NodeType.SINK:
                    continue
                sink_line = node.line or 0
                for guard_start, protected_start, protected_end in guard_line_ranges:
                    if guard_start < sink_line:
                        # Sink 在 Guard 之后，检查流向此 Sink 的边中是否有已净化变量
                        # 如有，在 TaintGraph 层面标记路径净化（防止误报）
                        for var_name in sanitized_by_guard:
                            var_node = self._variables.get(var_name)
                            if var_node and not self.graph.is_var_sanitized(var_name):
                                self.graph.mark_sanitized(var_name, "dominator_guard")
                                var_node.is_tainted = False

            logger.debug(
                "Dominator Tree 应用完成: %d 个 Guard 块, %d 个净化变量",
                len(self._guard_if_nodes),
                len(sanitized_by_guard),
            )

        except (RuntimeError, ValueError) as e:
            logger.debug("Dominator Tree 构建或应用失败: %s", e)

    def _generate_findings(self, paths: list[TaintPath]) -> list[TaintFinding]:
        """从污点路径生成漏洞报告"""
        findings = []

        for path in paths:
            # 跳过已净化的路径
            if path.is_sanitized:
                continue

            # 获取 Sink 信息
            sink_node = path.sink_node
            if not sink_node:
                continue

            # 确定漏洞类型
            category = sink_node.extras.get("category", "unknown")
            severity = sink_node.extras.get("severity", "High")
            cwe = sink_node.extras.get("cwe", "")

            # 创建漏洞报告
            finding = TaintFinding(
                vuln_type=category,
                severity=severity,
                confidence=path.confidence,
                file_path=self._current_file,
                line=sink_node.line,
                taint_path=path,
                source_expr=path.source_node.name if path.source_node else "",
                sink_expr=sink_node.name,
                description=self._generate_description(path),
                cwe=cwe,
                remediation=self._generate_remediation(category),
            )
            findings.append(finding)

        return findings

    def _generate_description(self, path: TaintPath) -> str:
        """生成漏洞描述"""
        source = path.source_node.name if path.source_node else "unknown"
        sink = path.sink_node.name if path.sink_node else "unknown"
        length = len(path)

        return f"用户可控的输入 `{source}` 流向敏感函数 `{sink}`，经过 {length - 2} 个中间变量传播。"

    def _generate_remediation(self, category: str) -> str:
        """生成修复建议"""
        remediation_map = {
            "rce": "避免将用户输入传递给 eval()、exec() 等危险函数。使用白名单验证或沙箱执行。",
            "sql_injection": "使用参数化查询或 ORM 框架，避免直接拼接 SQL 语句。",
            "nosql_injection": "对用户输入进行类型检查，使用 mongo-sanitize 等库过滤危险操作符。",
            "xss": "对用户输入进行 HTML 编码，使用 DOMPurify 等库净化 HTML。",
            "path_traversal": "使用 path.normalize() 规范化路径，验证路径不包含 '..' 序列。",
            "deserialization": "避免反序列化不受信任的数据，使用 JSON 等安全格式。",
            "ssrf": "使用白名单限制可访问的 URL，验证 URL 协议和域名。",
        }
        return remediation_map.get(category, "对用户输入进行验证和过滤。")

    @staticmethod
    def _get_node_text(node: Any) -> str | None:
        """提取节点的文本内容"""
        if hasattr(node, "text"):
            return cast(bytes, node.text).decode("utf-8")
        return None

    def get_graph(self) -> TaintGraph:
        """获取污点图"""
        return self.graph

    def reset(self) -> None:
        """重置分析器状态"""
        self.graph = TaintGraph()
        self._variables.clear()
        self._tainted_functions.clear()
        self._express_router_vars.clear()
        self._guard_if_nodes.clear()
        self._dominator_tree = None
        self._current_file = ""
        self._current_code = ""


__all__ = ["TaintAnalyzer", "TaintFinding"]
