
# 🎯 面试准备文档：AST 规则引擎扩展与测试

## 📚 项目背景

**项目名称**：Aegis AI - 代码安全审计系统  
**核心功能**：使用 AST（抽象语法树）和正则规则进行代码安全漏洞检测  
**技术栈**：Python, FastAPI, AST, ChromaDB, DeepSeek API

---

## 🎯 本次任务：扩展 AST 规则引擎

### 1. 任务目标

**问题**：项目原本依赖外部 AI API，技术深度不够，像"套壳工具"  
**目标**：扩展本地 AST 规则引擎，增加技术深度，实现不依赖 AI 的纯规则审计

---

## 🔧 技术实现

### 2.1 AST 规则引擎扩展

**原有功能**：
- 检测 `eval()`, `exec()` 等代码注入
- 检测 `os.system()` 等命令注入

**新增功能**（8 种新规则）：

#### 1. SQL 注入检测
```python
def _is_sql_string(node):
    """检测是否是 SQL 字符串"""
    if isinstance(node, ast.Str):
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP']
        return any(kw in node.s.upper() for kw in sql_keywords)
    return False

def _is_user_input(node):
    """检测是否是用户输入（input, request 等）"""
    # 检查是否是 input() 调用
    # 检查是否是 request 参数
    # ...
```

**技术要点**：
- 使用 AST 遍历语法树
- 检测字符串拼接模式（`+` 操作符）
- 识别用户输入来源（`input()`, `request` 等）

#### 2. XSS 风险检测
```python
# 检测未转义的用户输入直接输出
if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
    if node.func.id == 'print' and _is_user_input(node.args[0]):
        # 发现 XSS 风险
```

#### 3. 硬编码凭证检测
```python
# 检测变量名包含 password, api_key, secret 等
if isinstance(node, ast.Assign):
    for target in node.targets:
        if isinstance(target, ast.Name):
            var_name = target.id.lower()
            if any(keyword in var_name for keyword in ['password', 'api_key', 'secret']):
                # 检查值是否是字符串字面量
                if isinstance(node.value, ast.Str):
                    # 发现硬编码凭证
```

#### 4. 路径遍历风险检测
```python
# 检测文件操作中使用用户输入
if isinstance(node, ast.Call):
    func_name = _get_function_name(node.func)
    if func_name in ['open', 'file']:
        if len(node.args) > 0 and _is_user_input(node.args[0]):
            # 发现路径遍历风险
```

#### 5. 反序列化风险检测
```python
# 检测 pickle.loads, json.loads 等
if isinstance(node, ast.Call):
    func_name = _get_function_name(node.func)
    if func_name in ['pickle.loads', 'json.loads']:
        if _is_user_input(node.args[0]):
            # 发现反序列化风险
```

#### 6. 不安全库检测
```python
# 检测导入不安全的库
if isinstance(node, ast.Import):
    for alias in node.names:
        if alias.name in ['telnetlib', 'md5']:
            # 发现不安全库
```

#### 7. 弱加密算法检测
```python
# 检测使用 md5, sha1 等弱算法
if isinstance(node, ast.Call):
    func_name = _get_function_name(node.func)
    if 'md5' in func_name or 'sha1' in func_name:
        # 发现弱加密算法
```

#### 8. 调试代码检测
```python
# 检测 __debug__ 或 DEBUG 变量
if isinstance(node, ast.If):
    if isinstance(node.test, ast.Name) and node.test.id == '__debug__':
        # 发现调试代码
```

---

### 2.2 双重检测机制

**实现**：
```python
# 1. AST 分析（语法树结构分析）
ast_findings = analyze_code_ast(code_text)

# 2. 正则规则扫描（模式匹配）
regex_findings = scan_code_locally(code_text)

# 3. 合并结果（去重）
merged_findings = merge_findings(ast_findings, regex_findings)
```

**优势**：
- AST：能理解代码结构，检测逻辑漏洞
- 正则：快速检测明显的危险模式
- 合并：避免重复，提高准确性

---

### 2.3 纯规则审计引擎

**实现**：`rule_based_audit.py`

**核心函数**：
```python
def audit_code_with_rules_only(code: str, filename: str) -> dict:
    """
    纯规则审计（不依赖 AI）
    返回：{
        "report": "Markdown 格式报告",
        "findings": [...],
        "total_count": 22,
        "ast_count": 16,
        "regex_count": 6
    }
    """
    # 1. AST 分析
    ast_findings = analyze_code_ast(code)
    
    # 2. 正则扫描
    regex_findings = scan_code_locally(code)
    
    # 3. 合并去重
    merged = merge_findings(ast_findings, regex_findings)
    
    # 4. 生成报告
    report = generate_rule_based_report(merged, filename)
    
    return {
        "report": report,
        "findings": merged,
        "total_count": len(merged),
        "ast_count": len(ast_findings),
        "regex_count": len(regex_findings)
    }
```

**降级策略**：
```python
# 如果 AI 不可用，自动使用纯规则审计
if not use_ai or not reply:
    rule_result = audit_code_with_rules_only(code_text, file.filename)
    reply = rule_result["report"]
    merged_findings = rule_result["findings"]
```

---

## 🧪 测试过程

### 3.1 测试文件创建

**创建**：`test_vulnerable_code.py`（包含 10+ 种漏洞）

**包含的漏洞**：
1. Code Injection (`eval`, `exec`)
2. Command Injection (`os.system`, `subprocess`)
3. SQL Injection（字符串拼接）
4. XSS Risk（未转义输出）
5. Hardcoded Credentials（密码、密钥）
6. Path Traversal（文件操作）
7. Deserialization Risk（`pickle.loads`）
8. Insecure Library（`telnetlib`, `md5`）
9. Weak Cryptography（`md5`, `sha1`）
10. Debug Code（`if __debug__`）

---

### 3.2 测试结果

**AST 分析**：检测到 **16 个问题**  
**正则扫描**：检测到 **6 个问题**  
**合并结果**：**22 个问题**（去重后）

**严重程度统计**：
- 🔴 Critical: 5 个
- 🟠 High: 5 个
- 🟡 Medium: 10 个
- 🟢 Low: 2 个

**纯规则审计报告**：5073 字符，包含完整的 Markdown 格式报告

---

### 3.3 遇到的问题

#### 问题 1：日志字段冲突错误

**现象**：API 返回 `KeyError: "Attempt to overwrite 'filename' in LogRecord"`

**原因**：
```python
# 错误代码：filename 是 Python logging 模块的保留字段
logger.info("收到审计请求", extra={
    "filename": file.filename,  # ❌ filename 是 LogRecord 的保留属性
    ...
})
```

**解决方案**：
```python
# 改为其他字段名，比如 file_name
logger.info("收到审计请求", extra={
    "file_name": file.filename,  # ✅ 使用自定义字段名
    ...
})
```

**技术要点**：
- Python logging 模块的 LogRecord 有保留字段：`filename`, `lineno`, `funcName`, `levelname` 等
- 不能通过 `extra` 参数覆盖这些保留字段
- 需要使用其他字段名，如 `file_name`, `audit_filename` 等

**面试回答要点**：
> "测试时发现日志记录报错，因为 `filename` 是 Python logging 模块的保留字段。我将所有日志记录中的 `filename` 改为 `file_name`，解决了这个问题。这让我意识到要了解第三方库的保留字段和命名约定。"

---

#### 问题 2：变量未定义错误

**现象**：API 返回 500 错误

**原因**：
```python
# 错误代码：merged_findings 只在降级策略中定义
if not use_ai:
    merged_findings = rule_result["findings"]  # 只在这里定义

# 后面使用 merged_findings（如果 use_ai=True，这里会报错）
severity_count = {
    "Critical": len([f for f in merged_findings if ...])  # ❌ 可能未定义
}
```

**解决方案**：
```python
# 在函数开始就做双重检测，确保所有变量都定义
ast_findings = analyze_code_ast(code_text)
regex_findings = scan_code_locally(code_text)
merged_findings = merge_findings(ast_findings, regex_findings)  # ✅ 始终定义
```

**技术要点**：
- 确保所有变量在所有执行路径下都定义
- 使用防御性编程，提前初始化变量

---

#### 问题 2：变量名不一致

**现象**：`ast_time` 未定义

**原因**：
```python
ast_time = (time.time() - ast_start) * 1000  # 旧代码
# 后来改成了：
analysis_time = (time.time() - ast_start) * 1000  # 新代码
# 但日志中还在用 ast_time
logger.info("...", extra={"ast_time_ms": ast_time})  # ❌ 未定义
```

**解决方案**：
```python
# 统一使用 analysis_time
logger.info("...", extra={"analysis_time_ms": analysis_time})  # ✅
```

**技术要点**：
- 重构时注意变量名的一致性
- 使用 IDE 的全局搜索替换功能

---

#### 问题 3：代码重复

**现象**：代码截断逻辑重复了两次

**原因**：
```python
# 第一次定义（在构建 Prompt 之前）
MAX_CODE_LENGTH = 10000
code_preview = code_text[:MAX_CODE_LENGTH]

# 第二次定义（在 AI 调用时）
if use_ai:
    MAX_CODE_LENGTH = 10000  # 重复
    code_preview = code_text[:MAX_CODE_LENGTH]  # 重复
```

**解决方案**：
```python
# 只定义一次，在需要的地方使用
MAX_CODE_LENGTH = 10000
code_preview = code_text[:MAX_CODE_LENGTH]
if len(code_text) > MAX_CODE_LENGTH:
    logger.warning("代码过长，已截断", ...)
```

**技术要点**：
- DRY 原则（Don't Repeat Yourself）
- 提取公共逻辑到函数或变量

---

## 💡 面试可能问的问题

### Q1: 为什么要扩展 AST 规则引擎？

**回答要点**：
1. **技术深度**：不依赖外部 API，有自己的核心技术
2. **可靠性**：即使 AI API 不可用，也能提供基础审计
3. **性能**：本地检测速度快，不依赖网络
4. **成本**：减少 API 调用成本

**示例回答**：
> "项目原本依赖外部 AI API，技术深度不够。我扩展了 AST 规则引擎，新增了 8 种漏洞检测规则，实现了双重检测机制（AST + 正则），并实现了降级策略。这样即使 AI API 不可用，系统也能提供完整的审计报告。"

---

### Q2: AST 和正则规则有什么区别？为什么两者都用？

**回答要点**：
1. **AST**：理解代码结构，检测逻辑漏洞，准确度高
2. **正则**：快速检测明显模式，性能好
3. **互补**：AST 能发现正则发现不了的逻辑问题，正则能快速发现明显的危险模式

**示例回答**：
> "AST 通过解析语法树理解代码结构，能检测逻辑漏洞，比如检测 SQL 字符串拼接是否使用了用户输入。正则规则通过模式匹配快速检测明显的危险模式，比如 `eval(user_input)`。两者结合，既能保证准确性，又能提高性能。"

---

### Q3: 如何避免重复检测？

**回答要点**：
1. **合并函数**：`merge_findings()` 实现去重
2. **去重策略**：同一行、同一类型只保留一个
3. **优先级**：AST 结果优先（更准确）

**示例回答**：
> "我实现了 `merge_findings()` 函数，通过比较行号和漏洞类型来去重。如果同一行检测到相同类型的漏洞，优先保留 AST 的结果（因为 AST 分析更准确）。这样避免了重复，提高了报告的可读性。"

---

### Q4: 如何实现降级策略？

**回答要点**：
1. **检测 AI 可用性**：检查 API Key 和响应
2. **自动降级**：AI 失败时使用纯规则审计
3. **用户体验**：用户无感知，始终有结果返回

**示例回答**：
> "我实现了降级策略：首先尝试使用 AI 增强审计，如果 AI API 不可用或返回错误，自动切换到纯规则审计引擎。这样确保用户始终能获得审计报告，提高了系统的可靠性。"

---

### Q5: 测试过程中遇到了什么问题？如何解决的？

**回答要点**：
1. **问题**：变量未定义、变量名不一致、代码重复
2. **解决**：防御性编程、统一变量名、提取公共逻辑
3. **经验**：测试的重要性、代码审查的重要性

**示例回答**：
> "测试时发现 API 返回 500 错误。通过查看错误日志，发现是变量 `merged_findings` 在某些执行路径下未定义。我通过在函数开始就做双重检测，确保所有变量都定义，解决了这个问题。这让我意识到防御性编程和全面测试的重要性。"

---

### Q6: 如何评估检测结果的准确性？

**回答要点**：
1. **测试用例**：创建包含已知漏洞的测试文件
2. **覆盖率**：测试各种类型的漏洞
3. **误报率**：检查是否有误报
4. **严重程度**：正确分类漏洞严重程度

**示例回答**：
> "我创建了包含 10+ 种漏洞的测试文件，验证了检测引擎能正确识别各种类型的漏洞。测试结果显示检测到 22 个问题，严重程度分类正确（5 个 Critical，5 个 High 等）。这证明了检测引擎的准确性。"

---

### Q7: 如何优化检测性能？

**回答要点**：
1. **并行检测**：AST 和正则可以并行执行
2. **缓存**：缓存 AST 解析结果
3. **早期退出**：发现严重漏洞时提前返回
4. **代码截断**：大文件只分析前 N 行

**示例回答**：
> "我实现了代码长度限制（前 10000 字符），避免分析超大文件。未来可以优化为并行执行 AST 和正则检测，或者实现缓存机制来避免重复解析相同的代码片段。"

---

## 📊 技术亮点总结

1. **AST 静态分析**：深入理解代码结构，检测逻辑漏洞
2. **双重检测机制**：AST + 正则，提高准确性和性能
3. **降级策略**：确保系统可靠性
4. **去重算法**：避免重复检测
5. **报告生成**：自动生成 Markdown 格式报告
6. **严重程度分类**：Critical, High, Medium, Low
7. **测试驱动**：创建测试用例验证功能

---

## 🎓 学习要点

1. **AST 模块**：Python 的 `ast` 模块用于解析和分析代码
2. **防御性编程**：确保所有变量在所有路径下都定义
3. **代码重构**：注意变量名一致性和代码重复
4. **测试方法**：直接测试函数、API 测试、日志分析
5. **问题排查**：查看错误日志、使用调试工具、简化测试

---

## 📝 项目改进建议（未来）

1. **性能优化**：并行检测、缓存机制
2. **规则扩展**：更多漏洞类型检测
3. **误报优化**：减少误报率
4. **UI 优化**：前端展示检测结果
5. **CI/CD**：自动化测试和部署

---

## 🔗 相关文件

- `ast_analyzer.py`：AST 规则引擎
- `security_rules.py`：正则规则扫描
- `rule_based_audit.py`：纯规则审计引擎
- `aegis_server.py`：API 接口
- `test_vulnerable_code.py`：测试文件
- `TEST_RESULTS.md`：测试结果

---

**最后更新**：2026-02-03  
**作者**：Aegis AI 开发团队
