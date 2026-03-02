# test_ast_rules.py - 测试 AST 规则引擎
"""测试新扩展的 AST 规则引擎是否能正确检测漏洞"""

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
print("🧪 AST 规则引擎测试")
print("="*70)

# 1. AST 分析
print("\n[1] AST 分析结果：")
ast_findings = analyze_code_ast(test_code)
print(f"   检测到 {len(ast_findings)} 个问题")
for i, f in enumerate(ast_findings, 1):
    severity = f.get('severity', 'Medium')
    print(f"   {i}. 第 {f['line']} 行 [{severity}] {f['type']}")
    print(f"      详情: {f['details']}")

# 2. 正则规则扫描
print("\n[2] 正则规则扫描结果：")
regex_findings = scan_code_locally(test_code)
print(f"   检测到 {len(regex_findings)} 个问题")
for i, f in enumerate(regex_findings, 1):
    print(f"   {i}. 第 {f['line']} 行 [{f['type']}]")
    print(f"      内容: {f['content']}")

# 3. 合并结果
print("\n[3] 合并结果（去重后）：")
merged = merge_findings(ast_findings, regex_findings)
print(f"   总计 {len(merged)} 个问题")

# 按严重程度分组
critical = [f for f in merged if f.get('severity') == 'Critical']
high = [f for f in merged if f.get('severity') == 'High']
medium = [f for f in merged if f.get('severity') == 'Medium']
low = [f for f in merged if f.get('severity') == 'Low']

print(f"\n   严重程度统计：")
print(f"   🔴 Critical: {len(critical)}")
print(f"   🟠 High: {len(high)}")
print(f"   🟡 Medium: {len(medium)}")
print(f"   🟢 Low: {len(low)}")

# 4. 纯规则审计报告
print("\n[4] 纯规则审计报告（前 500 字符）：")
result = audit_code_with_rules_only(test_code, "test_vulnerable_code.py")
report = result["report"]
print(report[:500])
print("...")
print(f"\n   报告总长度: {len(report)} 字符")
print(f"   检测到的问题数: {result['total_count']}")
print(f"   AST 检测: {result['ast_count']} 个")
print(f"   正则检测: {result['regex_count']} 个")

print("\n" + "="*70)
print("✅ 测试完成！")
print("="*70)
