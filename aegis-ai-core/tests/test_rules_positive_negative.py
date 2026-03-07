"""
test_rules_positive_negative.py - 规则正向 / 反向测试

每条规则必须通过两类测试：
- 正向（True Positive）: 真实漏洞代码必须触发告警
- 反向（True Negative）: 安全代码、变量名碰巧含关键词的代码绝不能误报

使用 Tree-sitter 解析真实代码片段，端到端验证规则引擎。
"""

import pytest
from pathlib import Path

# 尝试导入 Tree-sitter；不可用则跳过
TREE_SITTER_AVAILABLE = False
JS_LANGUAGE = None

try:
    from tree_sitter import Parser
    # 优先尝试 tree_sitter_languages（旧 API，项目已使用）
    try:
        from tree_sitter_languages import get_language
        JS_LANGUAGE = get_language("javascript")
        TREE_SITTER_AVAILABLE = True
    except ImportError:
        pass

    # 备选：tree-sitter-javascript 新 API (tree-sitter >= 0.22)
    if not TREE_SITTER_AVAILABLE:
        try:
            import tree_sitter_javascript  # type: ignore
            from tree_sitter import Language
            JS_LANGUAGE = Language(tree_sitter_javascript.language())
            TREE_SITTER_AVAILABLE = True
        except (ImportError, TypeError):
            pass
except ImportError:
    pass

from src.analysis.base import AnalysisContext
from src.analysis.rule_engine import analyze_javascript

# 各规则
from src.analysis.rules.nosql_injection.javascript_ast_rule import JavaScriptNoSQLInjectionAstRule
from src.analysis.rules.xss.javascript_ast_rule import JavaScriptXSSAstRule
from src.analysis.rules.rce.javascript_ast_rule import JavaScriptRCEAstRule
from src.analysis.rules.hardcoded_credentials.javascript_ast_rule import JavaScriptHardcodedCredentialsAstRule
from src.analysis.rules.sql_injection.javascript_ast_rule import JavaScriptSQLInjectionAstRule
from src.analysis.rules.path_traversal.javascript_ast_rule import JavaScriptPathTraversalAstRule
from src.analysis.rules.deserialization.javascript_ast_rule import JavaScriptDeserializationAstRule


# ─────────────────────────────────────────────
# 测试基础设施
# ─────────────────────────────────────────────

def _scan_js(code: str, rule) -> list[dict]:
    """
    用指定规则扫描一段 JavaScript 代码，返回 findings。

    使用 Tree-sitter 解析代码并遍历 AST。
    """
    if not TREE_SITTER_AVAILABLE or JS_LANGUAGE is None:
        pytest.skip("tree-sitter JavaScript 解析器未安装")

    parser = Parser()
    parser.set_language(JS_LANGUAGE)
    tree = parser.parse(code.encode("utf-8"))

    ctx = AnalysisContext(
        file_path=Path("test.js"),
        language="javascript",
    )

    def _walk(node):
        rule.visit(node, ctx)
        for child in node.children:
            _walk(child)

    _walk(tree.root_node)
    return ctx.findings


# ═══════════════════════════════════════════════════════════
# NoSQL Injection
# ═══════════════════════════════════════════════════════════

class TestNoSQLInjection:
    """NoSQL 注入检测规则测试。"""

    rule = JavaScriptNoSQLInjectionAstRule()

    # ── 正向：真实漏洞代码 ──

    def test_direct_req_body(self) -> None:
        """db.findOne(req.body) 必须被检测。"""
        code = 'db.findOne(req.body);'
        findings = _scan_js(code, self.rule)
        assert len(findings) > 0
        assert any("NOSQL_INJECTION" in f["type"] for f in findings)

    def test_req_body_property(self) -> None:
        """users.find({ user: req.body.user }) 必须被检测。"""
        code = 'users.find({ user: req.body.user });'
        findings = _scan_js(code, self.rule)
        assert len(findings) > 0

    def test_where_operator(self) -> None:
        """使用 $where 操作符应被检测。"""
        code = 'db.find({ $where: req.body.code });'
        findings = _scan_js(code, self.rule)
        assert len(findings) > 0

    def test_dao_update_pattern(self) -> None:
        """allocationsDAO.update(query) 应被检测。"""
        code = 'allocationsDAO.update(query);'
        findings = _scan_js(code, self.rule)
        assert len(findings) > 0

    # ── 反向：安全代码 ──

    def test_array_find(self) -> None:
        """[1,2,3].find(x => x > 2) 不能误报。"""
        code = '[1, 2, 3].find(x => x > 2);'
        findings = _scan_js(code, self.rule)
        nosql_findings = [f for f in findings if f["type"] == "NOSQL_INJECTION"]
        assert len(nosql_findings) == 0

    def test_string_find(self) -> None:
        """str.find('hello') 不能误报。"""
        code = 'const result = str.find("hello");'
        findings = _scan_js(code, self.rule)
        nosql_findings = [f for f in findings if f["type"] == "NOSQL_INJECTION"]
        assert len(nosql_findings) == 0

    def test_variable_named_user(self) -> None:
        """变量名叫 userProfile 不能因为包含 'user' 就误报。"""
        code = '''
const userProfile = { name: "Alice", age: 30 };
console.log(userProfile);
'''
        findings = _scan_js(code, self.rule)
        nosql_findings = [f for f in findings if f["type"] == "NOSQL_INJECTION"]
        assert len(nosql_findings) == 0

    def test_safe_findone(self) -> None:
        """db.findOne({ _id: sanitizedId }) 使用安全变量不应误报为 Critical。"""
        code = '''
const sanitizedId = validateId(someInput);
db.findOne({ _id: sanitizedId });
'''
        findings = _scan_js(code, self.rule)
        # 可能有 Medium 级别的告警（因为变量来源未知），但不应是 Critical
        critical = [f for f in findings if f.get("severity") == "Critical"]
        assert len(critical) == 0

    def test_constant_identifier_in_object(self) -> None:
        """db.find({ limit: PAGE_SIZE }) 使用全大写常量不应误报。"""
        code = 'db.find({ limit: PAGE_SIZE });'
        findings = _scan_js(code, self.rule)
        nosql_findings = [f for f in findings if f["type"] == "NOSQL_INJECTION"]
        assert len(nosql_findings) == 0, (
            "PAGE_SIZE 是全大写常量，不应被当作用户输入"
        )

    def test_user_service_not_db_object(self) -> None:
        """userService.find({ id: 1 }) 中 userService 不是 DB 对象，不应报 NoSQL。"""
        code = 'userService.find({ id: 1 });'
        findings = _scan_js(code, self.rule)
        nosql_findings = [f for f in findings if f["type"] == "NOSQL_INJECTION"]
        assert len(nosql_findings) == 0, (
            "userService 词边界切分后为 ['user','Service']，均不在 DB 白名单中"
        )

    def test_view_model_find_not_db_object(self) -> None:
        """viewModel.find({ key: 'x' }) 不应被误报为 NoSQL 注入。"""
        code = "viewModel.find({ key: 'x' });"
        findings = _scan_js(code, self.rule)
        nosql_findings = [f for f in findings if f["type"] == "NOSQL_INJECTION"]
        assert len(nosql_findings) == 0

    def test_protocol_col_not_db_object(self) -> None:
        """'protocol' 含 'col' 子串但词元切分后不等于 'col'，不应误报。"""
        code = "protocol.find({ id: 1 });"
        findings = _scan_js(code, self.rule)
        nosql_findings = [f for f in findings if f["type"] == "NOSQL_INJECTION"]
        assert len(nosql_findings) == 0


# ═══════════════════════════════════════════════════════════
# XSS
# ═══════════════════════════════════════════════════════════

class TestXSS:
    """XSS 检测规则测试。"""

    rule = JavaScriptXSSAstRule()

    def test_innerhtml_assignment(self) -> None:
        """el.innerHTML = data 必须被检测。"""
        code = 'element.innerHTML = userData;'
        findings = _scan_js(code, self.rule)
        assert len(findings) > 0
        assert any("XSS" in f["type"] for f in findings)

    def test_dangerously_set_inner_html(self) -> None:
        """React dangerouslySetInnerHTML 必须被检测。"""
        code = 'const el = { dangerouslySetInnerHTML: { __html: data } };'
        findings = _scan_js(code, self.rule)
        assert len(findings) > 0

    def test_safe_textcontent(self) -> None:
        """el.textContent = data 不能误报。"""
        code = 'element.textContent = userData;'
        findings = _scan_js(code, self.rule)
        xss_findings = [f for f in findings if f["type"] == "XSS_RISK"]
        assert len(xss_findings) == 0

    def test_safe_console_log(self) -> None:
        """console.log(userInput) 不能误报。"""
        code = 'console.log(userInput);'
        findings = _scan_js(code, self.rule)
        assert len(findings) == 0

    def test_innerhtml_hardcoded_string(self) -> None:
        """element.innerHTML = '<b>Hello</b>' 硬编码字符串不应误报。"""
        code = "element.innerHTML = '<b>Hello</b>';"
        findings = _scan_js(code, self.rule)
        xss_findings = [f for f in findings if f["type"] == "XSS_RISK"]
        assert len(xss_findings) == 0, (
            "硬编码字符串字面量赋值不含动态用户数据，不应报 XSS"
        )

    def test_innerhtml_domPurify_sanitize(self) -> None:
        """element.innerHTML = DOMPurify.sanitize(data) 经净化不应误报。"""
        code = 'element.innerHTML = DOMPurify.sanitize(userInput);'
        findings = _scan_js(code, self.rule)
        xss_findings = [f for f in findings if f["type"] == "XSS_RISK"]
        assert len(xss_findings) == 0, (
            "DOMPurify.sanitize() 是已知净化函数，不应报 XSS"
        )

    def test_innerhtml_escape_html(self) -> None:
        """element.innerHTML = escapeHtml(data) 经净化不应误报。"""
        code = 'element.innerHTML = escapeHtml(userInput);'
        findings = _scan_js(code, self.rule)
        xss_findings = [f for f in findings if f["type"] == "XSS_RISK"]
        assert len(xss_findings) == 0

    def test_innerhtml_dynamic_should_warn(self) -> None:
        """element.innerHTML = userInput 动态值必须告警。"""
        code = 'element.innerHTML = userInput;'
        findings = _scan_js(code, self.rule)
        xss_findings = [f for f in findings if f["type"] == "XSS_RISK"]
        assert len(xss_findings) > 0, (
            "未净化的动态变量赋给 innerHTML 必须被检测"
        )


# ═══════════════════════════════════════════════════════════
# RCE (Remote Code Execution)
# ═══════════════════════════════════════════════════════════

class TestRCE:
    """RCE 检测规则测试。"""

    rule = JavaScriptRCEAstRule()

    def test_eval(self) -> None:
        """eval(input) 必须被检测。"""
        code = 'eval(userInput);'
        findings = _scan_js(code, self.rule)
        assert len(findings) > 0
        assert any("RCE" in f["type"] for f in findings)

    def test_function_constructor(self) -> None:
        """new Function(code) 必须被检测。"""
        code = 'Function(code)();'
        findings = _scan_js(code, self.rule)
        assert len(findings) > 0

    def test_child_process_exec(self) -> None:
        """child_process.exec(cmd) 必须被检测。"""
        code = 'child_process.exec(command);'
        findings = _scan_js(code, self.rule)
        assert len(findings) > 0

    def test_regex_exec(self) -> None:
        """/pattern/.exec(str) 不能误报为 RCE。"""
        code = '/^test/.exec(inputString);'
        findings = _scan_js(code, self.rule)
        rce_findings = [f for f in findings if f["type"] == "RCE_COMMAND_EXEC"]
        assert len(rce_findings) == 0

    def test_array_map(self) -> None:
        """arr.map(fn) 不能误报。"""
        code = '[1,2,3].map(x => x * 2);'
        findings = _scan_js(code, self.rule)
        assert len(findings) == 0


# ═══════════════════════════════════════════════════════════
# Hardcoded Credentials
# ═══════════════════════════════════════════════════════════

class TestHardcodedCredentials:
    """硬编码凭证检测规则测试。"""

    rule = JavaScriptHardcodedCredentialsAstRule()

    def test_hardcoded_password(self) -> None:
        """const password = 'abc123' 必须被检测。"""
        code = "const password = 'abc123';"
        findings = _scan_js(code, self.rule)
        assert len(findings) > 0
        assert any("HARDCODED_CREDENTIALS" in f["type"] for f in findings)

    def test_hardcoded_api_key(self) -> None:
        """const apiKey = 'sk-xxx' 必须被检测。"""
        code = "const apiKey = 'sk-live-1234567890';"
        findings = _scan_js(code, self.rule)
        assert len(findings) > 0

    def test_env_variable_password(self) -> None:
        """const password = process.env.DB_PASSWORD 不应被检测（值不是字面量）。"""
        code = "const password = process.env.DB_PASSWORD;"
        findings = _scan_js(code, self.rule)
        cred_findings = [f for f in findings if f["type"] == "HARDCODED_CREDENTIALS"]
        assert len(cred_findings) == 0

    def test_error_message_variable(self) -> None:
        """const passwordError = 'Invalid password' 不应被检测（变量名含 Error）。"""
        code = "const passwordError = 'Invalid password';"
        findings = _scan_js(code, self.rule)
        cred_findings = [f for f in findings if f["type"] == "HARDCODED_CREDENTIALS"]
        assert len(cred_findings) == 0

    def test_error_message_variable2(self) -> None:
        """const invalidPasswordMessage = '...' 不应被检测（变量名含 Message）。"""
        code = "const invalidPasswordMessage = 'Your password is incorrect';"
        findings = _scan_js(code, self.rule)
        cred_findings = [f for f in findings if f["type"] == "HARDCODED_CREDENTIALS"]
        assert len(cred_findings) == 0

    def test_placeholder_value(self) -> None:
        """const password = '' 不应被检测（空字符串视为占位符）。"""
        code = "const password = '';"
        findings = _scan_js(code, self.rule)
        cred_findings = [f for f in findings if f["type"] == "HARDCODED_CREDENTIALS"]
        assert len(cred_findings) == 0


# ═══════════════════════════════════════════════════════════
# SQL Injection
# ═══════════════════════════════════════════════════════════

class TestSQLInjection:
    """SQL 注入检测规则测试。"""

    rule = JavaScriptSQLInjectionAstRule()

    def test_string_concatenation_sql(self) -> None:
        """'SELECT * FROM users WHERE id=' + req.body.id 必须被检测。"""
        code = '''const q = "SELECT * FROM users WHERE id=" + req.body.id;'''
        findings = _scan_js(code, self.rule)
        assert len(findings) > 0
        assert any("SQL_INJECTION" in f["type"] for f in findings)

    def test_template_literal_sql(self) -> None:
        """`SELECT * FROM users WHERE id=${userId}` 必须被检测。"""
        code = 'const q = `SELECT * FROM users WHERE id=${userId}`;'
        findings = _scan_js(code, self.rule)
        assert len(findings) > 0

    def test_safe_parameterized_query(self) -> None:
        """db.query('SELECT * FROM users WHERE id=?', [id]) 不应误报为拼接注入。"""
        code = """db.query('SELECT * FROM users WHERE id=?', [id]);"""
        findings = _scan_js(code, self.rule)
        # 参数化查询不应被标记为 SQL_INJECTION
        concat_findings = [f for f in findings if "拼接" in f.get("details", "")]
        assert len(concat_findings) == 0

    def test_string_concat_no_sql(self) -> None:
        """'Hello ' + userName 不是 SQL 拼接，不应误报。"""
        code = '''const greeting = "Hello " + userName;'''
        findings = _scan_js(code, self.rule)
        sql_findings = [f for f in findings if f["type"] == "SQL_INJECTION"]
        assert len(sql_findings) == 0


# ═══════════════════════════════════════════════════════════
# Path Traversal
# ═══════════════════════════════════════════════════════════

class TestPathTraversal:
    """路径遍历检测规则测试。"""

    rule = JavaScriptPathTraversalAstRule()

    def test_fs_readfile_with_user_input(self) -> None:
        """fs.readFile(req.params.file) 必须被检测。"""
        code = 'fs.readFile(req.params.file, callback);'
        findings = _scan_js(code, self.rule)
        assert len(findings) > 0
        assert any("PATH_TRAVERSAL" in f["type"] for f in findings)

    def test_window_open(self) -> None:
        """window.open(url) 不是文件操作，不能误报。"""
        code = 'window.open(userUrl);'
        findings = _scan_js(code, self.rule)
        path_findings = [f for f in findings if f["type"] == "PATH_TRAVERSAL"]
        assert len(path_findings) == 0

    def test_fs_readfile_safe(self) -> None:
        """fs.readFile('./config.json') 使用硬编码路径不应误报。"""
        code = "fs.readFile('./config.json', callback);"
        findings = _scan_js(code, self.rule)
        path_findings = [f for f in findings if f["type"] == "PATH_TRAVERSAL"]
        assert len(path_findings) == 0

    def test_snackbar_open(self) -> None:
        """snackBar.open(message) 不是文件操作，不能误报。"""
        code = 'snackBar.open(errorMessage);'
        findings = _scan_js(code, self.rule)
        assert len(findings) == 0


# ═══════════════════════════════════════════════════════════
# Deserialization
# ═══════════════════════════════════════════════════════════

class TestDeserialization:
    """反序列化检测规则测试。"""

    rule = JavaScriptDeserializationAstRule()

    def test_json_parse_user_input(self) -> None:
        """JSON.parse(req.body.data) 必须被检测（完整管道含污点分析）。"""
        code = "const obj = JSON.parse(req.body.data);"
        findings = analyze_javascript(code, Path("test.js"))
        assert len(findings) > 0, "完整扫描应检出反序列化风险"
        assert any(
            "DESERIALIZATION" in f.get("type", "")
            for f in findings
        ), f"应有 DESERIALIZATION 类型，实际: {[f.get('type') for f in findings]}"

    def test_json_parse_safe_string(self) -> None:
        """JSON.parse('{"key":"value"}') 使用常量字符串不应误报。"""
        code = '''JSON.parse('{"key":"value"}');'''
        findings = _scan_js(code, self.rule)
        deser_findings = [f for f in findings if f["type"] == "DESERIALIZATION"]
        assert len(deser_findings) == 0

    def test_json_parse_localstorage(self) -> None:
        """JSON.parse(localStorage.getItem('key')) 不应误报（localStorage 是客户端存储）。"""
        code = "JSON.parse(localStorage.getItem('key'));"
        findings = _scan_js(code, self.rule)
        deser_findings = [f for f in findings if f["type"] == "DESERIALIZATION"]
        assert len(deser_findings) == 0

    def test_json_parse_variable_named_body(self) -> None:
        """
        反向测试：变量名叫 bodyContent 不应仅因包含 'body' 就误报。
        
        这是 P0 修复的核心验证 —— 旧版 _looks_like_user_input 会在此误报。
        """
        code = '''
const bodyContent = document.body.textContent;
JSON.parse(bodyContent);
'''
        findings = _scan_js(code, self.rule)
        deser_findings = [f for f in findings if f["type"] == "DESERIALIZATION"]
        assert len(deser_findings) == 0, (
            "变量名 bodyContent 不应因包含 'body' 就被误判为用户输入"
        )
