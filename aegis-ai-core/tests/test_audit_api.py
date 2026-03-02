# test_audit_api.py - 直接测试审计函数
"""直接测试审计函数，不通过 HTTP，定位错误"""

import os
import sys

# 添加项目根目录到 Python 路径
_current_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_current_dir)  # aegis-ai-core
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from src.analysis.ast_analyzer import analyze_code_ast
from src.analysis.security_rules import scan_code_locally
from src.analysis.rule_based_audit import merge_findings, audit_code_with_rules_only

# 读取测试文件
_test_file_path = os.path.join(_current_dir, 'test_vulnerable_code.py')
with open(_test_file_path, 'r', encoding='utf-8') as f:
    test_code = f.read()

print("="*70)
print("🧪 直接测试审计函数")
print("="*70)

try:
    # 1. 双重检测
    print("\n[1] 双重检测...")
    ast_findings = analyze_code_ast(test_code)
    regex_findings = scan_code_locally(test_code)
    merged_findings = merge_findings(ast_findings, regex_findings)
    print(f"   ✅ AST: {len(ast_findings)}, Regex: {len(regex_findings)}, Merged: {len(merged_findings)}")
    
    # 2. 纯规则审计
    print("\n[2] 纯规则审计...")
    result = audit_code_with_rules_only(test_code, "test_vulnerable_code.py")
    print(f"   ✅ 报告长度: {len(result['report'])} 字符")
    print(f"   ✅ 检测到: {result['total_count']} 个问题")
    
    # 3. 统计严重程度
    print("\n[3] 统计严重程度...")
    severity_count = {
        "Critical": len([f for f in merged_findings if f.get('severity') == 'Critical']),
        "High": len([f for f in merged_findings if f.get('severity') == 'High']),
        "Medium": len([f for f in merged_findings if f.get('severity') == 'Medium']),
        "Low": len([f for f in merged_findings if f.get('severity') == 'Low'])
    }
    print(f"   ✅ {severity_count}")
    
    print("\n" + "="*70)
    print("✅ 所有测试通过！")
    print("="*70)
    
except Exception as e:
    print(f"\n❌ 错误: {e}")
    import traceback
    traceback.print_exc()
