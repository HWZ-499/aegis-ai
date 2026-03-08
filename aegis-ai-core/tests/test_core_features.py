# test_core_features.py - 核心功能综合测试
"""
测试 Aegis AI 的核心功能：
1. AST 静态分析
2. 正则规则扫描
3. 项目扫描器
4. 报告生成
"""
import os
import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
_current_dir = Path(__file__).parent
_project_root = _current_dir.parent  # aegis-ai-core
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from src.analysis.ast_analyzer import analyze_code_ast
from src.analysis.security_rules import scan_code_locally
from src.analysis.rule_based_audit import merge_findings, audit_code_with_rules_only
from src.scanner.project_scanner import ProjectScanner
from src.scanner.report_generator import ReportGenerator


def test_ast_analyzer():
    """测试 AST 分析器"""
    print("="*70)
    print("🧪 测试 1: AST 静态分析器")
    print("="*70)
    
    # 读取测试代码
    test_file = _current_dir / "test_vulnerable_code.py"
    if not test_file.exists():
        print("❌ 测试文件不存在: test_vulnerable_code.py")
        return False
    
    with open(test_file, 'r', encoding='utf-8') as f:
        test_code = f.read()
    
    # 执行 AST 分析
    findings = analyze_code_ast(test_code)
    
    print(f"\n✅ AST 分析完成")
    print(f"   检测到 {len(findings)} 个问题")
    
    # 显示前5个问题
    for i, finding in enumerate(findings[:5], 1):
        print(f"\n   {i}. 第 {finding.get('line', '?')} 行")
        print(f"      类型: {finding.get('type', 'Unknown')}")
        print(f"      严重程度: {finding.get('severity', 'Medium')}")
        print(f"      详情: {finding.get('details', 'No details')[:60]}...")
    
    return len(findings) > 0


def test_regex_scanner():
    """测试正则规则扫描"""
    print("\n" + "="*70)
    print("🧪 测试 2: 正则规则扫描")
    print("="*70)
    
    # 读取测试代码
    test_file = _current_dir / "test_vulnerable_code.py"
    with open(test_file, 'r', encoding='utf-8') as f:
        test_code = f.read()
    
    # 执行正则扫描
    findings = scan_code_locally(test_code)
    
    print(f"\n✅ 正则扫描完成")
    print(f"   检测到 {len(findings)} 个问题")
    
    # 显示前5个问题
    for i, finding in enumerate(findings[:5], 1):
        print(f"\n   {i}. 第 {finding.get('line', '?')} 行")
        print(f"      类型: {finding.get('type', 'Unknown')}")
        print(f"      内容: {finding.get('content', 'No content')[:60]}...")
    
    return len(findings) > 0


def test_merge_findings():
    """测试结果合并"""
    print("\n" + "="*70)
    print("🧪 测试 3: 结果合并（AST + 正则）")
    print("="*70)
    
    # 读取测试代码
    test_file = _current_dir / "test_vulnerable_code.py"
    with open(test_file, 'r', encoding='utf-8') as f:
        test_code = f.read()
    
    # 执行双重检测
    ast_findings = analyze_code_ast(test_code)
    regex_findings = scan_code_locally(test_code)
    merged = merge_findings(ast_findings, regex_findings)
    
    print(f"\n✅ 合并完成")
    print(f"   AST 检测: {len(ast_findings)} 个")
    print(f"   正则检测: {len(regex_findings)} 个")
    print(f"   合并后: {len(merged)} 个（去重后）")
    
    # 按严重程度统计
    severity_stats = {}
    for finding in merged:
        severity = finding.get('severity', 'Medium')
        severity_stats[severity] = severity_stats.get(severity, 0) + 1
    
    print(f"\n   严重程度统计:")
    for severity in ['Critical', 'High', 'Medium', 'Low']:
        count = severity_stats.get(severity, 0)
        if count > 0:
            emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(severity, '⚪')
            print(f"     {emoji} {severity}: {count}")
    
    return len(merged) > 0


def test_project_scanner():
    """测试项目扫描器"""
    print("\n" + "="*70)
    print("🧪 测试 4: 项目扫描器（批量扫描）")
    print("="*70)
    
    # 扫描当前项目的 src 目录
    src_dir = _project_root / "src"
    if not src_dir.exists():
        print("❌ src 目录不存在")
        return False
    
    scanner = ProjectScanner(str(src_dir))
    results = scanner.scan_project(verbose=True)
    stats = scanner.get_stats()
    
    print(f"\n✅ 项目扫描完成")
    print(f"   扫描文件数: {stats['scanned_files']}")
    print(f"   有问题文件数: {stats['files_with_issues']}")
    print(f"   总问题数: {stats['total_issues']}")
    print(f"   扫描耗时: {stats['scan_time']:.2f} 秒")
    
    return stats['scanned_files'] > 0


def test_project_scanner_support_level():
    """1.4 多语言诚实标注：get_support_level 返回 full/partial/None。"""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        scanner = ProjectScanner(d)
        assert scanner.get_support_level(".py") == "full"
        assert scanner.get_support_level(".js") == "full"
        assert scanner.get_support_level(".cjs") == "full"
        assert scanner.get_support_level(".java") == "full"
        assert scanner.get_support_level(".php") == "full"
        assert scanner.get_support_level(".go") == "full"
        assert scanner.get_support_level(".rs") is None
        assert scanner.get_support_level(".swift") is None


def test_report_generator():
    """测试报告生成器"""
    print("\n" + "="*70)
    print("🧪 测试 5: 报告生成器")
    print("="*70)
    
    # 读取测试代码
    test_file = _current_dir / "test_vulnerable_code.py"
    with open(test_file, 'r', encoding='utf-8') as f:
        test_code = f.read()
    
    # 执行检测
    ast_findings = analyze_code_ast(test_code)
    regex_findings = scan_code_locally(test_code)
    merged = merge_findings(ast_findings, regex_findings)
    
    # 准备结果
    results = {
        "test_vulnerable_code.py": merged
    }
    
    stats = {
        "total_files": 1,
        "scanned_files": 1,
        "files_with_issues": 1 if merged else 0,
        "total_issues": len(merged),
        "scan_time": 0.1,
        "severity_stats": {}
    }
    
    # 统计严重程度
    for finding in merged:
        severity = finding.get('severity', 'Medium')
        stats['severity_stats'][severity] = stats['severity_stats'].get(severity, 0) + 1
    
    # 生成报告
    generator = ReportGenerator("Test Project")
    
    # JSON 格式
    json_report = generator.generate_json(results, stats)
    print(f"\n✅ JSON 报告生成成功")
    print(f"   长度: {len(json_report)} 字符")
    
    # Markdown 格式
    md_report = generator.generate_markdown(results, stats)
    print(f"✅ Markdown 报告生成成功")
    print(f"   长度: {len(md_report)} 字符")
    
    # HTML 格式
    html_report = generator.generate_html(results, stats)
    print(f"✅ HTML 报告生成成功")
    print(f"   长度: {len(html_report)} 字符")
    
    # SARIF 格式
    sarif_report = generator.generate_sarif(results, stats)
    print(f"✅ SARIF 报告生成成功")
    print(f"   长度: {len(sarif_report)} 字符")
    
    return True


def main():
    """主测试函数"""
    print("="*70)
    print("🚀 Aegis AI 核心功能测试")
    print("="*70)
    print(f"📁 项目根目录: {_project_root}")
    print(f"📁 测试目录: {_current_dir}")
    print("="*70)
    
    test_results = []
    
    # 测试 1: AST 分析器
    try:
        result = test_ast_analyzer()
        test_results.append(("AST 分析器", result))
    except Exception as e:
        print(f"❌ AST 分析器测试失败: {e}")
        test_results.append(("AST 分析器", False))
    
    # 测试 2: 正则扫描
    try:
        result = test_regex_scanner()
        test_results.append(("正则规则扫描", result))
    except Exception as e:
        print(f"❌ 正则扫描测试失败: {e}")
        test_results.append(("正则规则扫描", False))
    
    # 测试 3: 结果合并
    try:
        result = test_merge_findings()
        test_results.append(("结果合并", result))
    except Exception as e:
        print(f"❌ 结果合并测试失败: {e}")
        test_results.append(("结果合并", False))
    
    # 测试 4: 项目扫描器
    try:
        result = test_project_scanner()
        test_results.append(("项目扫描器", result))
    except Exception as e:
        print(f"❌ 项目扫描器测试失败: {e}")
        import traceback
        traceback.print_exc()
        test_results.append(("项目扫描器", False))
    
    # 测试 5: 报告生成器
    try:
        result = test_report_generator()
        test_results.append(("报告生成器", result))
    except Exception as e:
        print(f"❌ 报告生成器测试失败: {e}")
        test_results.append(("报告生成器", False))
    
    # 显示测试总结
    print("\n" + "="*70)
    print("📊 测试总结")
    print("="*70)
    
    passed = sum(1 for _, result in test_results if result)
    total = len(test_results)
    
    for name, result in test_results:
        status = "✅ 通过" if result else "❌ 失败"
        print(f"   {status} - {name}")
    
    print(f"\n总计: {passed}/{total} 个测试通过")
    
    if passed == total:
        print("\n🎉 所有核心功能测试通过！")
        return 0
    else:
        print(f"\n⚠️ 有 {total - passed} 个测试失败")
        return 1


if __name__ == "__main__":
    sys.exit(main())
