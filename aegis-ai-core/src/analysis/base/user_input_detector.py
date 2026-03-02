"""
user_input_detector.py - 结构化用户输入检测器

核心改进：
- **不再** 使用 ``any(keyword in text for keyword in keywords)`` 做子串匹配
  （旧方式会把 userProfile、formatQuery、bodyParser 全部误判为用户输入）。
- 改为 **AST 结构化检查**：精确匹配 ``req.body.*``、``req.query.*`` 等模式。
- 对于 identifier 节点，只在 DataFlowTracker 已标记其为 tainted 时才判定。

所有安全规则都应统一调用本模块，避免各自重复实现。
"""

from __future__ import annotations

from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .dataflow_tracker import DataFlowTracker

# Tree-sitter Node 类型
try:
    from tree_sitter import Node
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any  # type: ignore[misc,assignment]


# ──────────────────────────────────────────────
# Express / Koa / Django 等框架的用户输入入口
# ──────────────────────────────────────────────
#
# 每项为 (object_chain, property) 的元组：
#   - object_chain: 调用对象路径，如 ("req",)
#   - property:     属性名，如 "body"
# 匹配 ``req.body`` / ``req.body.userId`` / ``request.query.id`` 等
#
_JS_USER_INPUT_ROOTS: list[tuple[tuple[str, ...], str]] = [
    # Express
    (("req",), "body"),
    (("req",), "query"),
    (("req",), "params"),
    (("req",), "cookies"),
    (("req",), "headers"),
    (("request",), "body"),
    (("request",), "query"),
    (("request",), "params"),
    (("request",), "cookies"),
    (("request",), "headers"),
    # Koa
    (("ctx", "request"), "body"),
    (("ctx",), "query"),
    (("ctx",), "params"),
]

_PY_USER_INPUT_ROOTS: list[tuple[tuple[str, ...], str]] = [
    (("request",), "form"),
    (("request",), "args"),
    (("request",), "json"),
    (("request",), "data"),
    (("request",), "values"),
    (("request",), "cookies"),
    (("request",), "headers"),
    (("request",), "GET"),
    (("request",), "POST"),
    (("request",), "FILES"),
]


def _get_node_text(node: Any) -> str:
    """
    提取 Tree-sitter 节点的文本内容。

    Returns:
        节点文本，不可用时返回空字符串。
    """
    if hasattr(node, "text"):
        raw = node.text
        return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
    return ""


def _extract_member_chain(node: Any) -> list[str]:
    """
    递归展开 member_expression，返回属性链。

    例如 ``req.body.userId`` → ``["req", "body", "userId"]``
    """
    if not TREE_SITTER_AVAILABLE:
        return []

    if node.type == "identifier":
        return [_get_node_text(node)]

    if node.type == "property_identifier":
        return [_get_node_text(node)]

    if node.type == "member_expression":
        parts: list[str] = []
        for child in node.children:
            if child.type in ("identifier", "property_identifier"):
                parts.append(_get_node_text(child))
            elif child.type == "member_expression":
                parts = _extract_member_chain(child) + parts
            # 跳过 "." 等标点
        return parts

    return []


def _chain_matches_any_root(
    chain: list[str],
    roots: list[tuple[tuple[str, ...], str]],
) -> bool:
    """
    检查属性链是否以某个已知用户输入根开头。

    ``chain = ["req", "body", "userId"]``
    对比 ``(("req",), "body")`` → 前缀为 ``["req", "body"]`` → 命中。
    """
    for obj_chain, prop in roots:
        prefix = list(obj_chain) + [prop]
        if len(chain) >= len(prefix) and chain[:len(prefix)] == prefix:
            return True
    return False


# ──────────────────────────────────────────────
# 公共 API
# ──────────────────────────────────────────────

def is_user_input_node(
    node: Any,
    context: Optional[Any] = None,
    *,
    language: str = "javascript",
) -> bool:
    """
    判断一个 AST 节点是否代表用户输入。

    优先进行 **结构化匹配**（精确匹配 ``req.body.*`` 等模式），
    仅在 ``context`` 中存在 ``DataFlowTracker`` 时才对普通标识符做
    污点查询。不再使用关键词子串匹配。

    Args:
        node: Tree-sitter AST 节点。
        context: ``AnalysisContext`` 实例（可选），用于污点查询。
        language: 当前语言 (``"javascript"`` / ``"python"`` 等)。

    Returns:
        ``True`` 如果该节点可判定为来自用户输入。
    """
    if not TREE_SITTER_AVAILABLE or node is None:
        return False

    # 根据语言选择匹配规则
    if language in ("javascript", "typescript"):
        roots = _JS_USER_INPUT_ROOTS
    elif language == "python":
        roots = _PY_USER_INPUT_ROOTS
    else:
        roots = _JS_USER_INPUT_ROOTS + _PY_USER_INPUT_ROOTS

    # ── Case 1: member_expression（如 req.body.userId）──
    if node.type == "member_expression":
        chain = _extract_member_chain(node)
        if chain and _chain_matches_any_root(chain, roots):
            return True
        # member_expression 不匹配已知根时，不盲目报 True
        return False

    # ── Case 2: identifier（如 userId）──
    if node.type == "identifier":
        var_name = _get_node_text(node)
        if not var_name:
            return False
        # 精确匹配：变量名恰好是 "req" 或 "request"（整体传递）
        if var_name in ("req", "request"):
            return True
        # 通过 DataFlowTracker 判断变量是否被标记为 tainted
        if context is not None:
            if hasattr(context, "is_var_tainted") and context.is_var_tainted(var_name):
                return True
        return False

    # ── Case 3: 其他节点类型 ──
    # 对于 string / template_string / call_expression 等，不做猜测
    return False


def is_user_input_expr(
    expr_text: str,
    *,
    language: str = "javascript",
) -> bool:
    """
    纯文本模式：判断一个表达式字符串是否指向用户输入。

    仅做 **前缀精确匹配**，不做子串模糊搜索。

    Args:
        expr_text: 表达式文本（如 ``"req.body.userId"``）。
        language: 当前语言。

    Returns:
        ``True`` 如果是已知用户输入模式。
    """
    if not expr_text:
        return False

    if language in ("javascript", "typescript"):
        roots = _JS_USER_INPUT_ROOTS
    elif language == "python":
        roots = _PY_USER_INPUT_ROOTS
    else:
        roots = _JS_USER_INPUT_ROOTS + _PY_USER_INPUT_ROOTS

    for obj_chain, prop in roots:
        prefix = ".".join(list(obj_chain) + [prop])
        # 精确前缀：``req.body`` 或 ``req.body.xxx``
        if expr_text == prefix or expr_text.startswith(prefix + "."):
            return True

    return False


__all__ = [
    "is_user_input_node",
    "is_user_input_expr",
]
