# 🔧 API 接口本地测试方案

## 📋 问题分析

**API 返回 500 错误的原因分析**：
- ❌ **不是代理问题**：服务运行在 `127.0.0.1:8000`（本地），不经过代理
- ✅ **可能是代码逻辑问题**：某些变量在特定执行路径下未定义
- ✅ **可能是异常处理问题**：异常被捕获但没有正确返回错误信息

---

## 🧪 测试方案

### 方案 1：查看详细错误日志

**步骤**：
1. 打开终端，进入 `aegis-ai-core` 目录
2. 启动服务（会显示详细错误）：
   ```bash
   python aegis_server.py
   ```
   或者：
   ```bash
   uvicorn aegis_server:app --port 8000 --log-level debug
   ```
3. 在另一个终端测试：
   ```bash
   python -c "import requests; files = {'file': ('test.py', open('test_vulnerable_code.py', 'rb'), 'text/plain')}; r = requests.post('http://127.0.0.1:8000/api/audit', files=files); print('状态码:', r.status_code); print('响应:', r.text)"
   ```
4. **查看第一个终端的错误信息**，找到具体的错误行号和原因

---

### 方案 2：使用 Python 直接测试（绕过 HTTP）

**步骤**：
1. 创建测试脚本 `test_api_direct.py`：
   ```python
   # test_api_direct.py
   import sys
   sys.path.insert(0, '.')
   
   from aegis_server import audit_code
   from fastapi import UploadFile
   import io
   
   # 读取测试文件
   with open('test_vulnerable_code.py', 'rb') as f:
       content = f.read()
   
   # 创建 UploadFile 对象
   file = UploadFile(
       filename="test_vulnerable_code.py",
       file=io.BytesIO(content)
   )
   
   # 直接调用函数（需要异步）
   import asyncio
   
   async def test():
       try:
           result = await audit_code(file=file, request=None)
           print("✅ 成功！")
           print(f"检测到 {result['findings_count']} 个问题")
           print(f"AST: {result['ast_findings_count']}, Regex: {result['regex_findings_count']}")
           print(f"严重程度: {result['severity_count']}")
       except Exception as e:
           print(f"❌ 错误: {e}")
           import traceback
           traceback.print_exc()
   
   asyncio.run(test())
   ```
2. 运行：
   ```bash
   python test_api_direct.py
   ```
3. 查看完整的错误堆栈

---

### 方案 3：检查服务日志文件

**步骤**：
1. 如果配置了日志文件，查看日志：
   ```bash
   # Windows PowerShell
   Get-Content .\logs\*.log -Tail 50
   ```
2. 或者查看终端输出文件（如果有）

---

### 方案 4：使用 curl 测试（排除 Python requests 库问题）

**步骤**：
1. 安装 curl（Windows 10+ 自带）
2. 测试：
   ```bash
   curl -X POST http://127.0.0.1:8000/api/audit -F "file=@test_vulnerable_code.py"
   ```
3. 查看返回的错误信息

---

## 🔍 常见问题排查

### 1. 检查导入是否正确
```python
# 在 aegis_server.py 开头检查
from rule_based_audit import merge_findings, audit_code_with_rules_only
from security_rules import scan_code_locally
from ast_analyzer import analyze_code_ast
```

### 2. 检查变量是否在所有路径下都定义
```python
# 确保 merged_findings, regex_findings 在所有执行路径下都定义
# 在函数开始就定义：
ast_findings = []
regex_findings = []
merged_findings = []
```

### 3. 检查异常处理
```python
# 确保所有异常都被正确捕获和记录
except Exception as e:
    logger.error("详细错误", extra={"error": str(e), "traceback": traceback.format_exc()})
    raise HTTPException(status_code=500, detail=f"内部错误: {str(e)}")
```

---

## 📝 测试检查清单

- [ ] 服务能正常启动
- [ ] `/api/health` 接口返回 200
- [ ] `/api/audit` 接口能接收文件
- [ ] 文件能正确读取
- [ ] AST 分析能正常执行
- [ ] 正则扫描能正常执行
- [ ] 合并函数能正常执行
- [ ] 返回的 JSON 格式正确
- [ ] 所有变量都已定义
- [ ] 异常被正确捕获

---

## 💡 快速修复建议

如果发现是变量未定义问题，可以这样修复：

```python
# 在 audit_code 函数开始处，确保所有变量都初始化
ast_findings = []
regex_findings = []
merged_findings = []
reply = ""
use_ai = False

# 然后再执行检测逻辑
```

---

## 🎯 预期结果

**正常情况应该返回**：
```json
{
  "reply": "报告内容...",
  "mode": "audit",
  "filename": "test_vulnerable_code.py",
  "findings_count": 22,
  "ast_findings_count": 16,
  "regex_findings_count": 6,
  "severity_count": {
    "Critical": 5,
    "High": 5,
    "Medium": 10,
    "Low": 2
  },
  "used_ai": false
}
```

---

## 📞 如果还是不行

1. **查看完整错误堆栈**：使用方案 1 或 2
2. **检查 Python 版本**：确保是 Python 3.8+
3. **检查依赖**：确保所有包都已安装
4. **简化测试**：先用最简单的代码文件测试
