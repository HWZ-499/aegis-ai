"""
test_user_input_detector.py - 用户输入检测器的正向 / 反向测试

核心验证：
- 正向：req.body.*, req.query.*, req.params.* 等真实用户输入必须命中
- 反向：userProfile, formatQuery, bodyParser, arguments 等绝不能误报
"""

import pytest

from src.analysis.base.user_input_detector import (
    _extract_member_chain,
    is_user_input_expr,
    is_user_input_node,
)

# ═══════════════════════════════════════════════════════════
# 1. is_user_input_expr — 纯文本前缀精确匹配
# ═══════════════════════════════════════════════════════════


class TestIsUserInputExpr:
    """测试基于字符串的用户输入判断。"""

    # ── 正向用例（必须返回 True）──
    @pytest.mark.parametrize(
        "expr",
        [
            "req.body",
            "req.body.userId",
            "req.body.password",
            "req.query.id",
            "req.params.slug",
            "req.cookies.session",
            "req.headers.authorization",
            "request.body",
            "request.query.search",
            "request.params.id",
            "request.cookies.token",
        ],
    )
    def test_positive_js(self, expr: str) -> None:
        """JavaScript 真实用户输入表达式必须命中。"""
        assert is_user_input_expr(expr, language="javascript") is True

    @pytest.mark.parametrize(
        "expr",
        [
            "request.form.username",
            "request.args.page",
            "request.json",
            "request.data",
            "request.cookies.session_id",
            "request.GET.q",
            "request.POST.token",
        ],
    )
    def test_positive_python(self, expr: str) -> None:
        """Python 真实用户输入表达式必须命中。"""
        assert is_user_input_expr(expr, language="python") is True

    # ── 反向用例（必须返回 False）──
    @pytest.mark.parametrize(
        "expr",
        [
            # 变量名恰好包含 "user" / "body" / "query" / "param" 等关键词
            "userProfile",
            "getUserName",
            "formatQuery",
            "bodyParser",
            "bodyContent",
            "queryString",
            "paramCount",
            "arguments",
            "requestId",  # 不是 request.xxx 模式
            "formValidator",
            "inputElement",
            "require",  # Node.js require() 绝不是用户输入
            "requiredFields",
            # 空或无意义值
            "",
            "undefined",
            "null",
            # 常见安全工具名
            "sanitizeInput",
            "validateParams",
        ],
    )
    def test_negative_should_not_match(self, expr: str) -> None:
        """这些表达式绝不能被判定为用户输入。"""
        assert is_user_input_expr(expr, language="javascript") is False


# ═══════════════════════════════════════════════════════════
# 2. is_user_input_node — 基于 AST 结构
# ═══════════════════════════════════════════════════════════


class TestIsUserInputNode:
    """
    测试基于 Tree-sitter AST 节点的用户输入判断。

    因为 tree_sitter 可能未安装，这里使用 Mock 节点来隔离逻辑。
    """

    @staticmethod
    def _make_node(node_type: str, text: str, children: list | None = None):
        """创建一个 Mock Tree-sitter 节点。"""

        class MockNode:
            def __init__(self, ntype, ntext, nchildren=None):
                self.type = ntype
                self.text = ntext.encode("utf-8") if isinstance(ntext, str) else ntext
                self.children = nchildren or []

        return MockNode(node_type, text, children)

    def _make_member_expr(self, parts: list[str]):
        """
        构造 member_expression 链。

        例如 ``["req", "body", "userId"]`` →
        member_expression(member_expression(identifier("req"), property_identifier("body")), property_identifier("userId"))
        """
        if len(parts) == 0:
            return None
        if len(parts) == 1:
            return self._make_node("identifier", parts[0])

        # 构建从左到右嵌套的 member_expression
        current = self._make_node("identifier", parts[0])
        for part in parts[1:]:
            prop = self._make_node("property_identifier", part)
            current = self._make_node("member_expression", ".".join(parts[: parts.index(part) + 1]), [current, prop])
        # 由于 _extract_member_chain 递归解析，实际文本并不重要，
        # 它靠 children 的 type 和 text 来分解。
        # 但节点顶层 type 必须是 member_expression
        return current

    # ── 正向 ──
    @pytest.mark.parametrize(
        "parts",
        [
            ["req", "body"],
            ["req", "body", "userId"],
            ["req", "query", "search"],
            ["req", "params", "id"],
            ["req", "cookies", "session"],
            ["request", "body"],
            ["request", "query", "page"],
        ],
    )
    def test_member_expression_positive(self, parts: list[str]) -> None:
        """member_expression 形式的用户输入必须被识别。"""
        node = self._make_member_expr(parts)
        assert is_user_input_node(node, language="javascript") is True

    # ── 反向 ──
    @pytest.mark.parametrize(
        "parts",
        [
            ["db", "users"],
            ["User", "findOne"],
            ["config", "body"],  # config.body 不是用户输入
            ["console", "query"],  # console.query 不是
            ["document", "body"],  # DOM body 不是
            ["response", "body"],  # response.body 不是
            ["Math", "random"],
        ],
    )
    def test_member_expression_negative(self, parts: list[str]) -> None:
        """这些 member_expression 绝不能误报为用户输入。"""
        node = self._make_member_expr(parts)
        assert is_user_input_node(node, language="javascript") is False

    # ── identifier 节点 ──
    def test_identifier_req(self) -> None:
        """单独的 'req' 标识符应被视为用户输入（整体传递）。"""
        node = self._make_node("identifier", "req")
        assert is_user_input_node(node, language="javascript") is True

    @pytest.mark.parametrize(
        "name",
        [
            "userProfile",
            "formatQuery",
            "bodyParser",
            "arguments",
            "paramCount",
            "requestId",
            "inputElement",
            "require",
            "db",
            "config",
        ],
    )
    def test_identifier_negative(self, name: str) -> None:
        """普通标识符绝不能误报为用户输入。"""
        node = self._make_node("identifier", name)
        assert is_user_input_node(node, language="javascript") is False


# ═══════════════════════════════════════════════════════════
# 3. _extract_member_chain 内部函数
# ═══════════════════════════════════════════════════════════


class TestExtractMemberChain:
    """测试 AST 属性链提取。"""

    @staticmethod
    def _make_node(ntype, ntext, children=None):
        class MockNode:
            def __init__(self, t, tx, c=None):
                self.type = t
                self.text = tx.encode("utf-8") if isinstance(tx, str) else tx
                self.children = c or []

        return MockNode(ntype, ntext, children)

    def test_simple_identifier(self) -> None:
        node = self._make_node("identifier", "req")
        assert _extract_member_chain(node) == ["req"]

    def test_member_two_levels(self) -> None:
        """req.body → ["req", "body"]"""
        inner_id = self._make_node("identifier", "req")
        prop = self._make_node("property_identifier", "body")
        node = self._make_node("member_expression", "req.body", [inner_id, prop])
        assert _extract_member_chain(node) == ["req", "body"]

    def test_member_three_levels(self) -> None:
        """req.body.userId → ["req", "body", "userId"]"""
        inner_id = self._make_node("identifier", "req")
        prop1 = self._make_node("property_identifier", "body")
        inner_member = self._make_node("member_expression", "req.body", [inner_id, prop1])
        prop2 = self._make_node("property_identifier", "userId")
        node = self._make_node("member_expression", "req.body.userId", [inner_member, prop2])
        assert _extract_member_chain(node) == ["req", "body", "userId"]
