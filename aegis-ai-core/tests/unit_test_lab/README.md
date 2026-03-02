# 🧪 单元测试实验室

## 📋 目的

建立单元测试实验室，包含10个简单的JS/TS测试文件，用于验证扫描器的准确性。

**测试原则**：
- 包含常见的RCE、SQLi、XSS漏洞
- 既有真漏洞，也有假漏洞（Hardcoded safe values）
- 确保扫描器能100%正确区分它们

---

## 📁 测试文件结构

```
tests/unit_test_lab/
├── README.md
├── rce/
│   ├── rce_true_vulnerable.ts      # 真漏洞：eval(userInput)
│   ├── rce_false_safe.ts           # 假漏洞：eval("hardcoded string")
│   └── rce_false_regexp.ts         # 假漏洞：RegExp.exec()
├── sqli/
│   ├── sqli_true_vulnerable.ts     # 真漏洞：query("SELECT * FROM users WHERE id = " + userInput)
│   ├── sqli_false_prepared.ts      # 假漏洞：prepare()参数化查询
│   └── sqli_false_hardcoded.ts     # 假漏洞：硬编码SQL
└── xss/
    ├── xss_true_vulnerable.ts      # 真漏洞：innerHTML = userInput
    ├── xss_false_sanitized.ts      # 假漏洞：htmlspecialchars(userInput)
    └── xss_false_hardcoded.ts      # 假漏洞：innerHTML = "hardcoded string"
```

---

## ✅ 测试用例要求

### RCE测试用例

1. **真漏洞**：
   - `eval(userInput)` - 用户输入直接执行
   - `child_process.exec(userInput)` - 用户输入直接执行命令

2. **假漏洞（应该不报告）**：
   - `eval("hardcoded string")` - 硬编码字符串，安全
   - `RegExp.exec()` - 正则表达式方法，不是命令执行
   - `new Function("hardcoded")` - 硬编码字符串

### SQL注入测试用例

1. **真漏洞**：
   - `query("SELECT * FROM users WHERE id = " + userInput)` - 字符串拼接
   - `User.find({ where: { email: userInput + "..." } })` - ORM字符串拼接

2. **假漏洞（应该不报告）**：
   - `prepare("SELECT * FROM users WHERE id = ?")` - 参数化查询，安全
   - `query("SELECT * FROM users WHERE id = 1")` - 硬编码SQL，安全

### XSS测试用例

1. **真漏洞**：
   - `innerHTML = userInput` - 用户输入直接输出
   - `bypassSecurityTrustHtml(userInput)` - Angular绕过安全策略

2. **假漏洞（应该不报告）**：
   - `innerHTML = "hardcoded string"` - 硬编码字符串，安全
   - `htmlspecialchars(userInput)` - 已转义，安全
   - `textContent = userInput` - textContent会转义，安全

---

## 🎯 验证标准

扫描器应该：
- ✅ 检测到所有真漏洞
- ✅ 不报告所有假漏洞
- ✅ 准确分类漏洞类型（RCE、SQLi、XSS）
- ✅ 准确分类严重程度（Critical、High、Medium）

---

## 📊 预期结果

| 文件 | 漏洞类型 | 是否应该报告 | 严重程度 |
|------|---------|------------|---------|
| rce_true_vulnerable.ts | RCE | ✅ 是 | Critical |
| rce_false_safe.ts | RCE | ❌ 否 | - |
| rce_false_regexp.ts | RCE | ❌ 否 | - |
| sqli_true_vulnerable.ts | SQLi | ✅ 是 | High |
| sqli_false_prepared.ts | SQLi | ❌ 否 | - |
| sqli_false_hardcoded.ts | SQLi | ❌ 否 | - |
| xss_true_vulnerable.ts | XSS | ✅ 是 | High |
| xss_false_sanitized.ts | XSS | ❌ 否 | - |
| xss_false_hardcoded.ts | XSS | ❌ 否 | - |

---

## 🧪 运行测试

```bash
# 扫描单元测试实验室
cd aegis-ai-core
python -m src.scanner.cli scan tests/unit_test_lab --output unit_test_lab_report.html

# 验证结果
# 应该只报告真漏洞，不报告假漏洞
```

---

## 📝 注意事项

1. **测试文件应该简单**：每个文件只包含一个测试场景
2. **命名清晰**：文件名应该明确表示是真漏洞还是假漏洞
3. **注释说明**：每个文件应该包含注释说明为什么是真漏洞或假漏洞
4. **定期更新**：随着规则改进，应该更新测试用例
