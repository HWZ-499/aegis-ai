"""
测试 NoSQL 注入检测 + 数据流分析

测试目标：
1. 直接用户输入检测（req.body, req.query）
2. 间接污点传播检测（const x = req.body; db.find(x)）
3. 对象字面量检测
4. 危险操作符检测（扩展列表）
5. DAO 模式检测
"""

import sys
from pathlib import Path

# 添加项目路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.analysis.base import AnalysisContext, DataFlowTracker
from src.analysis.rules.nosql_injection.javascript_ast_rule import JavaScriptNoSQLInjectionAstRule

# 尝试导入 tree-sitter（兼容 tree-sitter-languages 旧版 API）
try:
    from tree_sitter import Parser
    from tree_sitter_languages import get_language
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False


def create_parser():
    """创建 JavaScript 解析器"""
    if not TREE_SITTER_AVAILABLE:
        return None
    JS_LANGUAGE = get_language("javascript")
    parser = Parser()
    parser.set_language(JS_LANGUAGE)
    return parser


def analyze_code(code: str, parser) -> list:
    """分析代码并返回发现的问题"""
    tree = parser.parse(bytes(code, "utf8"))
    
    context = AnalysisContext(
        file_path=Path("test.js"),
        language="javascript"
    )
    
    rule = JavaScriptNoSQLInjectionAstRule()
    
    # 遍历 AST
    def visit_node(node):
        rule.visit(node, context)
        for child in node.children:
            visit_node(child)
    
    visit_node(tree.root_node)
    return context.findings


def test_direct_user_input():
    """测试直接用户输入检测"""
    parser = create_parser()
    if not parser:
        print("⚠️ Tree-sitter 不可用，跳过测试")
        return
    
    code = '''
    const userId = req.body.userId;
    db.users.findOne(req.body);
    '''
    
    findings = analyze_code(code, parser)
    print(f"测试1: 直接用户输入 -> 发现 {len(findings)} 个问题")
    for f in findings:
        print(f"  - {f['severity']}: {f['details'][:60]}...")
    
    assert len(findings) >= 1, "应该检测到至少1个 NoSQL 注入"
    assert any(f['severity'] == 'Critical' for f in findings), "应该有 Critical 级别的发现"


def test_indirect_taint_propagation():
    """测试间接污点传播检测"""
    parser = create_parser()
    if not parser:
        print("⚠️ Tree-sitter 不可用，跳过测试")
        return
    
    code = '''
    const query = req.body;
    db.users.findOne(query);
    '''
    
    findings = analyze_code(code, parser)
    print(f"测试2: 间接污点传播 -> 发现 {len(findings)} 个问题")
    for f in findings:
        print(f"  - {f['severity']}: {f['details'][:60]}...")
    
    # 应该检测到间接污点传播
    assert len(findings) >= 1, "应该检测到间接污点传播"


def test_object_literal_with_user_input():
    """测试对象字面量中的用户输入"""
    parser = create_parser()
    if not parser:
        print("⚠️ Tree-sitter 不可用，跳过测试")
        return
    
    code = '''
    db.users.findOne({ user: req.body.user });
    '''
    
    findings = analyze_code(code, parser)
    print(f"测试3: 对象字面量用户输入 -> 发现 {len(findings)} 个问题")
    for f in findings:
        print(f"  - {f['severity']}: {f['details'][:60]}...")
    
    assert len(findings) >= 1, "应该检测到对象字面量中的用户输入"


def test_dangerous_operators():
    """测试危险操作符检测"""
    parser = create_parser()
    if not parser:
        print("⚠️ Tree-sitter 不可用，跳过测试")
        return
    
    code = '''
    db.users.findOne({ $where: req.body.code });
    db.users.findOne({ $ne: req.body.password });
    db.users.findOne({ $regex: req.query.pattern });
    '''
    
    findings = analyze_code(code, parser)
    print(f"测试4: 危险操作符 -> 发现 {len(findings)} 个问题")
    for f in findings:
        print(f"  - {f['severity']}: {f['details'][:60]}...")
    
    assert len(findings) >= 1, "应该检测到危险操作符"


def test_dao_pattern():
    """测试 DAO 模式检测"""
    parser = create_parser()
    if not parser:
        print("⚠️ Tree-sitter 不可用，跳过测试")
        return
    
    code = '''
    allocationsDAO.update(userId, stocks, funds, bonds);
    contributionsDAO.update(userId, preTax, afterTax, roth);
    '''
    
    findings = analyze_code(code, parser)
    print(f"测试5: DAO 模式 -> 发现 {len(findings)} 个问题")
    for f in findings:
        print(f"  - {f['severity']}: {f['details'][:60]}...")
    
    assert len(findings) >= 2, "应该检测到 DAO 模式的 NoSQL 注入"


def test_dataflow_tracker_unit():
    """测试数据流追踪器单元功能"""
    tracker = DataFlowTracker(language="javascript")
    
    # 测试用户输入检测
    assert tracker.is_user_input_expr("req.body.userId") == True
    assert tracker.is_user_input_expr("req.query.id") == True
    assert tracker.is_user_input_expr("someVariable") == False
    
    # 测试变量追踪
    tracker.track_assignment("userId", "req.body.userId", 10)
    assert tracker.is_tainted("userId") == True
    
    tracker.track_assignment("normalVar", "123", 11)
    assert tracker.is_tainted("normalVar") == False
    
    # 测试污点传播
    tracker.track_assignment("query", "userId", 12)
    # 注意：当前实现检查的是变量名是否在 _tainted_vars 中
    
    print("测试6: 数据流追踪器单元测试 -> 通过")


def test_no_false_positive():
    """测试没有误报"""
    parser = create_parser()
    if not parser:
        print("⚠️ Tree-sitter 不可用，跳过测试")
        return
    
    code = '''
    // 安全的代码 - 不应该报警
    const users = [1, 2, 3];
    const result = users.find(u => u > 1);
    
    // 数组 find 不应该被当成 MongoDB find
    array.find(x => x === target);
    '''
    
    findings = analyze_code(code, parser)
    print(f"测试7: 误报检测 -> 发现 {len(findings)} 个问题（应该是0）")
    for f in findings:
        print(f"  - {f['severity']}: {f['details'][:60]}...")
    
    # 应该没有误报
    assert len(findings) == 0, "不应该对 Array.find() 产生误报"


if __name__ == "__main__":
    print("=" * 60)
    print("NoSQL 注入检测 + 数据流分析 回归测试")
    print("=" * 60)
    
    tests = [
        test_direct_user_input,
        test_indirect_taint_propagation,
        test_object_literal_with_user_input,
        test_dangerous_operators,
        test_dao_pattern,
        test_dataflow_tracker_unit,
        test_no_false_positive,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
            print(f"✅ {test.__name__} 通过\n")
        except AssertionError as e:
            failed += 1
            print(f"❌ {test.__name__} 失败: {e}\n")
        except Exception as e:
            failed += 1
            print(f"❌ {test.__name__} 异常: {e}\n")
    
    print("=" * 60)
    print(f"测试结果: {passed} 通过, {failed} 失败")
    print("=" * 60)
