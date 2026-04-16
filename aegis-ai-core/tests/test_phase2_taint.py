"""
test_phase2_taint.py - 阶段二污点分析增强功能测试

覆盖：
- DataFlowTracker 解构赋值追踪
- DataFlowTracker Sanitizer 感知
- DataFlowTracker mark_as_source（Express 路由回调）
- DataFlowTracker 字符串拼接 / 模板字符串的污点传播
- JavaScriptDataFlowCollector Express 路由回调识别
- JavaScriptDataFlowCollector 解构赋值收集
- SourceSinkRegistry 精确 Sanitizer 匹配
- 端到端：规则层 Sanitizer 降级
"""

import sys
from pathlib import Path

import pytest

# 确保项目根目录在 sys.path 中
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analysis.base.analysis_context import AnalysisContext
from src.analysis.base.dataflow_tracker import DataFlowTracker

# SourceSinkRegistry
from src.analysis.taint.source_sink_registry import (
    SourceSinkRegistry,
)

# ── Tree-sitter 可选 ──
try:
    from tree_sitter import Parser
    from tree_sitter_languages import get_language

    JS_LANGUAGE = get_language("javascript")
    _parser = Parser()
    _parser.set_language(JS_LANGUAGE)
    TREE_SITTER_AVAILABLE = True
except Exception:
    TREE_SITTER_AVAILABLE = False
    _parser = None


# =====================================================================
# 辅助函数
# =====================================================================


def _parse_js(code: str):
    """用 Tree-sitter 解析 JavaScript 代码，返回 root_node。"""
    if not TREE_SITTER_AVAILABLE:
        pytest.skip("tree-sitter 不可用")
    tree = _parser.parse(bytes(code, "utf-8"))
    return tree.root_node


def _scan_js_with_collector(code: str):
    """
    用 DataFlowCollector + 指定规则扫描 JS 代码，返回 (context, findings)。
    会先运行 DataFlowCollector 再运行传入的规则。
    """
    if not TREE_SITTER_AVAILABLE:
        pytest.skip("tree-sitter 不可用")

    from src.analysis.base.js_dataflow_collector import JavaScriptDataFlowCollector

    root = _parse_js(code)
    ctx = AnalysisContext(file_path=Path("test.js"), language="javascript")

    collector = JavaScriptDataFlowCollector()

    def walk(node):
        collector.visit(node, ctx)
        for child in node.children:
            walk(child)

    walk(root)
    return ctx


def _scan_js_full(code: str, rule_cls):
    """
    完整扫描：DataFlowCollector → 指定规则。返回 findings 列表。
    """
    if not TREE_SITTER_AVAILABLE:
        pytest.skip("tree-sitter 不可用")

    from src.analysis.base.js_dataflow_collector import JavaScriptDataFlowCollector

    root = _parse_js(code)
    ctx = AnalysisContext(file_path=Path("test.js"), language="javascript")

    collector = JavaScriptDataFlowCollector()
    rule = rule_cls()

    def walk(node):
        collector.visit(node, ctx)
        rule.visit(node, ctx)
        for child in node.children:
            walk(child)

    walk(root)
    return ctx.findings


# =====================================================================
# 1. DataFlowTracker 单元测试
# =====================================================================


class TestDataFlowTrackerDestructuring:
    """解构赋值追踪测试。"""

    def test_destructuring_from_tainted_source(self):
        """const { name, email } = req.body → name/email 都应该被污染。"""
        tracker = DataFlowTracker(language="javascript")
        tracker.track_destructuring(["name", "email"], "req.body", line=5)

        assert tracker.is_tainted("name")
        assert tracker.is_tainted("email")

    def test_destructuring_from_tainted_variable(self):
        """data = req.body; { name } = data → name 被污染。"""
        tracker = DataFlowTracker(language="javascript")
        tracker.track_assignment("data", "req.body", line=1)
        tracker.track_destructuring(["name"], "data", line=2)

        assert tracker.is_tainted("name")

    def test_destructuring_from_clean_source(self):
        """const { name } = config → name 不应该被污染。"""
        tracker = DataFlowTracker(language="javascript")
        tracker.track_destructuring(["name"], "config", line=5)

        assert not tracker.is_tainted("name")

    def test_destructuring_source_info(self):
        """解构出的变量应该有正确的 source 信息。"""
        tracker = DataFlowTracker(language="javascript")
        tracker.track_destructuring(["name"], "req.body", line=5)

        source = tracker.get_taint_source("name")
        assert source is not None
        assert source.source_type == "destructuring"
        assert "req.body.name" in source.source_expr


class TestDataFlowTrackerSanitizer:
    """Sanitizer 感知测试。"""

    def test_sanitizer_call_detection(self):
        """const safe = parseInt(tainted) → safe 应该被标记为 sanitized。"""
        tracker = DataFlowTracker(language="javascript")
        tracker.track_assignment("tainted", "req.body.id", line=1)
        tracker.track_assignment("safe", "parseInt(tainted)", line=2)

        assert not tracker.is_tainted("safe")
        assert tracker.is_sanitized("safe")

    def test_sanitizer_escape_html(self):
        """const clean = escapeHtml(dirty) → clean 应该是 sanitized。"""
        tracker = DataFlowTracker(language="javascript")
        tracker.track_assignment("dirty", "req.body.html", line=1)
        tracker.track_assignment("clean", "escapeHtml(dirty)", line=2)

        assert not tracker.is_tainted("clean")
        assert tracker.is_sanitized("clean")

    def test_non_sanitizer_function(self):
        """const x = formatData(tainted) → x 不应该被标记为 sanitized。"""
        tracker = DataFlowTracker(language="javascript")
        tracker.track_assignment("tainted", "req.body.data", line=1)
        # formatData 不是已知的 Sanitizer
        tracker.track_assignment("x", "formatData(tainted)", line=2)

        # x 应该被污染（因为 tainted 在 formatData(tainted) 的文本中）
        # 但不应该被标记为 sanitized
        assert not tracker.is_sanitized("x")

    def test_track_sanitization_explicit(self):
        """显式调用 track_sanitization 后变量标记为已净化。"""
        tracker = DataFlowTracker(language="javascript")
        tracker.track_assignment("data", "req.body", line=1)
        assert tracker.is_tainted("data")

        tracker.track_sanitization("data", "parseInt", line=2)
        assert not tracker.is_tainted("data")
        assert tracker.is_sanitized("data")
        assert tracker.get_sanitizer_name("data") == "parseInt"

    def test_sanitizer_no_false_positive_escape_velocity(self):
        """escape_velocity 不应该被识别为 Sanitizer。"""
        tracker = DataFlowTracker(language="javascript")
        tracker.track_assignment("tainted", "req.body.v", line=1)
        tracker.track_assignment("x", "escape_velocity(tainted)", line=2)

        # escape_velocity 不在 Sanitizer 列表中
        assert not tracker.is_sanitized("x")

    def test_python_sanitizer_int(self):
        """Python: safe = int(tainted) → safe 是 sanitized。"""
        tracker = DataFlowTracker(language="python")
        tracker.track_assignment("tainted", "request.form.get('id')", line=1)
        tracker.track_assignment("safe", "int(tainted)", line=2)

        assert not tracker.is_tainted("safe")
        assert tracker.is_sanitized("safe")


class TestDataFlowTrackerMarkAsSource:
    """mark_as_source 测试（Express 路由回调参数）。"""

    def test_mark_as_source(self):
        """显式标记 req 为 Source 后，req 被污染。"""
        tracker = DataFlowTracker(language="javascript")
        tracker.mark_as_source("req", line=1, source_type="express_route_callback")

        assert tracker.is_tainted("req")

    def test_source_propagation(self):
        """标记 req 为 Source → const data = req.body → data 被污染。"""
        tracker = DataFlowTracker(language="javascript")
        tracker.mark_as_source("req", line=1, source_type="express_route_callback")
        tracker.track_assignment("data", "req.body", line=2)

        assert tracker.is_tainted("data")


class TestDataFlowTrackerConcatPropagation:
    """字符串拼接 / 模板字符串的污点传播。"""

    def test_string_concat_propagation(self):
        """query = "SELECT " + tainted → query 应该被污染。"""
        tracker = DataFlowTracker(language="javascript")
        tracker.track_assignment("tainted", "req.body.name", line=1)
        tracker.track_assignment("query", '"SELECT * FROM users WHERE name = " + tainted', line=2)

        assert tracker.is_tainted("query")

    def test_template_literal_propagation(self):
        """query = `SELECT ${tainted}` → query 应该被污染。"""
        tracker = DataFlowTracker(language="javascript")
        tracker.track_assignment("tainted", "req.body.name", line=1)
        tracker.track_assignment("query", "`SELECT * FROM users WHERE name = ${tainted}`", line=2)

        assert tracker.is_tainted("query")

    def test_clean_concat_not_tainted(self):
        """query = "Hello " + name → 如果 name 不是 tainted，query 也不是。"""
        tracker = DataFlowTracker(language="javascript")
        tracker.track_assignment("name", "'World'", line=1)
        tracker.track_assignment("query", '"Hello " + name', line=2)

        assert not tracker.is_tainted("query")


# =====================================================================
# 2. AnalysisContext 便捷方法测试
# =====================================================================


class TestAnalysisContextSanitizer:
    """AnalysisContext Sanitizer 便捷方法测试。"""

    def test_is_var_sanitized(self):
        ctx = AnalysisContext(file_path=Path("test.js"), language="javascript")
        ctx.dataflow_tracker.track_assignment("x", "req.body.id", line=1)
        ctx.dataflow_tracker.track_assignment("safe", "parseInt(x)", line=2)

        assert not ctx.is_var_tainted("safe")
        assert ctx.is_var_sanitized("safe")
        assert ctx.get_sanitizer_name("safe") == "parseInt"


# =====================================================================
# 3. SourceSinkRegistry 精确 Sanitizer 匹配测试
# =====================================================================


class TestRegistrySanitizers:
    """SourceSinkRegistry Sanitizer 匹配精度测试。"""

    def setup_method(self):
        self.registry = SourceSinkRegistry()
        self.registry.load_defaults()

    def test_escape_html_matches(self):
        """escapeHtml( 应该匹配 XSS Sanitizer。"""
        s = self.registry.find_sanitizer("escapeHtml(data)", "javascript")
        assert s is not None

    def test_dom_purify_matches(self):
        """DOMPurify.sanitize( 应该匹配。"""
        s = self.registry.find_sanitizer("DOMPurify.sanitize(html)", "javascript")
        assert s is not None

    def test_parse_int_matches(self):
        """parseInt( 应该匹配 SQLi/NoSQLi Sanitizer。"""
        s = self.registry.find_sanitizer("parseInt(x)", "javascript")
        assert s is not None

    def test_escape_velocity_no_match(self):
        """escape_velocity 不应该匹配任何 Sanitizer。"""
        s = self.registry.find_sanitizer("escape_velocity", "javascript")
        assert s is None

    def test_encode_uri_component_no_match(self):
        """encodeURIComponent 不应该被当作 XSS Sanitizer。"""
        s = self.registry.find_sanitizer("encodeURIComponent(x)", "javascript")
        # 不应该匹配任何 Sanitizer（它不在列表中）
        assert s is None

    def test_python_html_escape(self):
        """html.escape( 应该匹配 Python XSS Sanitizer。"""
        s = self.registry.find_sanitizer("html.escape(data)", "python")
        assert s is not None

    def test_python_shlex_quote(self):
        """shlex.quote( 应该匹配 Python RCE Sanitizer。"""
        s = self.registry.find_sanitizer("shlex.quote(cmd)", "python")
        assert s is not None


# =====================================================================
# 4. JavaScriptDataFlowCollector 集成测试
# =====================================================================


@pytest.mark.skipif(not TREE_SITTER_AVAILABLE, reason="tree-sitter 不可用")
class TestCollectorExpressRoute:
    """Express 路由回调识别测试。"""

    def test_app_get_route(self):
        """app.get('/path', (req, res) => {...}) → req 标记为 Source。"""
        code = """
app.get('/users', (req, res) => {
    const data = req.body;
    res.json(data);
});
"""
        ctx = _scan_js_with_collector(code)
        assert ctx.dataflow_tracker.is_tainted("req")

    def test_app_post_route(self):
        """app.post('/path', (request, response) => {...}) → request 标记为 Source。"""
        code = """
app.post('/api/data', (request, response) => {
    const data = request.body;
});
"""
        ctx = _scan_js_with_collector(code)
        assert ctx.dataflow_tracker.is_tainted("request")

    def test_router_use_middleware(self):
        """router.use((req, res, next) => {...}) → req 标记为 Source。"""
        code = """
router.use((req, res, next) => {
    console.log(req.path);
    next();
});
"""
        ctx = _scan_js_with_collector(code)
        assert ctx.dataflow_tracker.is_tainted("req")

    def test_non_route_call_no_source(self):
        """普通函数调用不应该标记参数为 Source。"""
        code = """
utils.get('/path', (data, callback) => {
    callback(data);
});
"""
        ctx = _scan_js_with_collector(code)
        assert not ctx.dataflow_tracker.is_tainted("data")


@pytest.mark.skipif(not TREE_SITTER_AVAILABLE, reason="tree-sitter 不可用")
class TestCollectorDestructuring:
    """解构赋值收集测试。"""

    def test_destructuring_from_req_body(self):
        """const { name, email } = req.body → name/email 被污染。"""
        code = """
const { name, email } = req.body;
"""
        ctx = _scan_js_with_collector(code)
        assert ctx.dataflow_tracker.is_tainted("name")
        assert ctx.dataflow_tracker.is_tainted("email")

    def test_destructuring_from_clean_object(self):
        """const { host, port } = config → host/port 不被污染。"""
        code = """
const { host, port } = config;
"""
        ctx = _scan_js_with_collector(code)
        assert not ctx.dataflow_tracker.is_tainted("host")
        assert not ctx.dataflow_tracker.is_tainted("port")


# =====================================================================
# 5. 端到端：规则层 Sanitizer 感知
# =====================================================================


@pytest.mark.skipif(not TREE_SITTER_AVAILABLE, reason="tree-sitter 不可用")
class TestNoSQLRuleSanitizerAware:
    """NoSQL 注入规则应该尊重 Sanitizer 标记。"""

    def test_sanitized_variable_no_finding(self):
        """const id = parseInt(req.body.id); db.users.findOne({_id: id}) → 不应该报。"""
        from src.analysis.rules.nosql_injection.javascript_ast_rule import (
            JavaScriptNoSQLInjectionAstRule,
        )

        code = """
const rawId = req.body.id;
const id = parseInt(rawId);
db.users.findOne(id);
"""
        findings = _scan_js_full(code, JavaScriptNoSQLInjectionAstRule)
        # id 经过 parseInt 净化，不应该报 Critical/High
        nosql_findings = [f for f in findings if f["type"] == "NOSQL_INJECTION"]
        # 如果有 findings，它们不应该是 High 级别的（因为 id 是 sanitized）
        high_findings = [f for f in nosql_findings if f["severity"] in ("Critical", "High")]
        assert len(high_findings) == 0, f"不应该有 High 级别的 NoSQL 注入 findings: {high_findings}"

    def test_unsanitized_variable_has_finding(self):
        """const data = req.body; db.users.findOne(data) → 应该报。"""
        from src.analysis.rules.nosql_injection.javascript_ast_rule import (
            JavaScriptNoSQLInjectionAstRule,
        )

        code = """
const data = req.body;
db.users.findOne(data);
"""
        findings = _scan_js_full(code, JavaScriptNoSQLInjectionAstRule)
        nosql_findings = [f for f in findings if f["type"] == "NOSQL_INJECTION"]
        assert len(nosql_findings) >= 1


@pytest.mark.skipif(not TREE_SITTER_AVAILABLE, reason="tree-sitter 不可用")
class TestDestructuringTaintPropagation:
    """解构赋值 + 规则检测的端到端测试。"""

    def test_destructured_tainted_var_in_query(self):
        """const { userId } = req.body; db.users.findOne({_id: userId}) → 应该报。"""
        from src.analysis.rules.nosql_injection.javascript_ast_rule import (
            JavaScriptNoSQLInjectionAstRule,
        )

        code = """
const { userId } = req.body;
db.users.findOne(userId);
"""
        findings = _scan_js_full(code, JavaScriptNoSQLInjectionAstRule)
        nosql_findings = [f for f in findings if f["type"] == "NOSQL_INJECTION"]
        assert len(nosql_findings) >= 1


# =====================================================================
# 6. DataFlowTracker reset 测试
# =====================================================================


class TestDataFlowTrackerReset:
    """重置后状态应该干净。"""

    def test_reset_clears_all(self):
        tracker = DataFlowTracker(language="javascript")
        tracker.track_assignment("x", "req.body", line=1)
        tracker.track_sanitization("y", "parseInt", line=2)
        assert tracker.is_tainted("x")
        assert tracker.is_sanitized("y")

        tracker.reset()
        assert not tracker.is_tainted("x")
        assert not tracker.is_sanitized("y")
        assert tracker.get_all_tainted_vars() == set()
