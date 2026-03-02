# test_api_direct.py - 直接测试 API 函数（绕过 HTTP）
"""
直接测试审计函数，不经过 HTTP，可以查看完整的错误堆栈
"""
import sys
sys.path.insert(0, '.')

import asyncio
import io
from fastapi import UploadFile
from aegis_server import audit_code

async def test_audit():
    """测试审计函数"""
    print("="*70)
    print("🧪 直接测试审计函数（绕过 HTTP）")
    print("="*70)
    
    # 读取测试文件
    try:
        with open('test_vulnerable_code.py', 'rb') as f:
            content = f.read()
    except FileNotFoundError:
        print("❌ 错误：找不到 test_vulnerable_code.py")
        print("   请先创建测试文件")
        return
    
    # 创建 UploadFile 对象
    file = UploadFile(
        filename="test_vulnerable_code.py",
        file=io.BytesIO(content)
    )
    
    print("\n[1] 调用审计函数...")
    try:
        result = await audit_code(file=file, request=None)
        
        print("✅ 成功！")
        print(f"\n[2] 结果：")
        print(f"   检测到的问题数: {result.get('findings_count', 0)}")
        print(f"   AST 检测: {result.get('ast_findings_count', 0)}")
        print(f"   正则检测: {result.get('regex_findings_count', 0)}")
        print(f"   严重程度: {result.get('severity_count', {})}")
        print(f"   使用 AI: {result.get('used_ai', False)}")
        print(f"   报告长度: {len(result.get('reply', ''))} 字符")
        
        print(f"\n[3] 报告前 500 字符：")
        print(result.get('reply', '')[:500])
        print("...")
        
        print("\n" + "="*70)
        print("✅ 测试完成！")
        print("="*70)
        
    except Exception as e:
        print(f"\n❌ 错误: {e}")
        print("\n[详细错误堆栈]：")
        import traceback
        traceback.print_exc()
        
        print("\n" + "="*70)
        print("💡 提示：")
        print("   1. 检查错误堆栈，找到具体的问题行")
        print("   2. 检查是否所有变量都已定义")
        print("   3. 检查导入是否正确")
        print("="*70)

if __name__ == "__main__":
    asyncio.run(test_audit())
