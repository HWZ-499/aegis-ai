# ⚡ 5 分钟快速入门指南

## 🎯 目标
让你的 Aegis RAG 系统在 5 分钟内运行起来

---

## 第 1 步：获取 API Key（2 分钟）

### 选项 A：如果你已经有 DeepSeek API Key
跳过此步骤，直接到第 2 步

### 选项 B：如果你还没有 API Key
1. 打开 https://platform.deepseek.com/
2. 点击 "Sign Up"（没有账户）或 "Sign In"（有账户）
3. 登录后，点击左侧 "API Keys"
4. 点击 "Create New Secret Key"
5. 复制显示的 Key（格式：sk-xxxxxxxx）

⏱️ 预计时间：2 分钟

---

## 第 2 步：设置 API Key（2 分钟）

### 最简单的方式：使用自动化脚本

在 PowerShell 中运行：
```powershell
cd C:\Users\HT341\aegis-ai\aegis-ai-core
python setup_deepseek.py
```

然后按照提示操作：
- 选择 `1` 创建 .env 文件（推荐）
- 输入你的 API Key
- 完成！

⏱️ 预计时间：2 分钟

---

或者，如果你想手动设置：

### 手动方式 A：创建 .env 文件

1. 在 `C:\Users\HT341\aegis-ai\aegis-ai-core` 目录下创建一个文件，名字为 `.env`

2. 用记事本打开，写入：
```
DEEPSEEK_API_KEY=sk-your-key-here
```

3. 保存文件

4. （可选）安装 python-dotenv：
```powershell
pip install python-dotenv
```

### 手动方式 B：设置系统环境变量

在 PowerShell 中运行：
```powershell
[System.Environment]::SetEnvironmentVariable('DEEPSEEK_API_KEY', 'sk-your-key-here', 'User')
```

然后关闭 PowerShell 并重新打开一个新窗口

⏱️ 预计时间：2 分钟

---

## 第 3 步：运行系统（1 分钟）

在 PowerShell 中运行：
```powershell
cd C:\Users\HT341\aegis-ai\aegis-ai-core
python aegis_shell_enterprise.py
```

你应该看到：
```
🔌 [System] 正在挂载本地向量数据库...
✅ 已加载 .env 文件
✅ 数据库连接成功，包含 7 条记录

============================================================
🛡️  Aegis-AI RAG Terminal (Enterprise Edition)
============================================================
📂 数据库: ./aegis_db
🌐 API: https://api.deepseek.com/chat/completions
📏 阈值: 1.5
============================================================

🕵️  You >
```

⏱️ 预计时间：1 分钟

---

## 第 4 步：测试系统（几秒钟）

在 `You >` 提示符后输入：
```
fastjson 漏洞有什么危害
```

你应该看到系统检索数据并生成答案。

---

## ✅ 成功标志

如果你看到：
```
✅ 配置验证通过
✅ 数据库连接成功
🕵️  You > 
```

恭喜！系统已经成功运行了！🎉

---

## ❌ 常见错误及解决方案

### 错误 1：❌ DEEPSEEK_API_KEY 未设置

**原因**：环境变量没有设置  
**解决**：
```powershell
# 方式 1: 使用自动脚本
python setup_deepseek.py

# 方式 2: 手动创建 .env 文件
# 在项目目录下创建 .env，内容：DEEPSEEK_API_KEY=sk-your-key
```

### 错误 2：ModuleNotFoundError: No module named 'chromadb'

**原因**：缺少依赖  
**解决**：
```powershell
pip install chromadb requests certifi
```

### 错误 3：❌ API 报错 401 Unauthorized

**原因**：API Key 无效或过期  
**解决**：
1. 登录 https://platform.deepseek.com/api-keys
2. 查看你的 Key 是否有效
3. 如果无效，生成新的 Key
4. 更新你的环境变量或 .env 文件

### 错误 4：Connection refused / timeout

**原因**：网络连接问题或 API 服务暂时不可用  
**解决**：
1. 检查网络连接
2. 稍后重试
3. 尝试用浏览器访问 https://api.deepseek.com（测试连接）

---

## 🎯 下一步

系统运行成功后，你可以：

1. **尝试不同的查询**：
   ```
   log4j RCE 如何防护
   什么是 SQL 注入
   最新的漏洞是什么
   ```

2. **查看日志**：
   日志会显示 API 调用、检索距离等信息

3. **阅读文档**：
   - `README_ENTERPRISE.md` - 企业级说明
   - `ENTERPRISE_AUDIT.md` - 完整审计报告
   - `QUICK_FIX_GUIDE.md` - 快速修复指南

4. **进行改进**（18 小时）：
   按照审计报告的建议进行 P0、P1、P2 阶段的改进

---

## 📋 快速参考

| 命令 | 用途 |
|------|------|
| `python setup_deepseek.py` | 自动设置 API Key |
| `python aegis_shell_enterprise.py` | 运行 RAG 系统 |
| `echo $env:DEEPSEEK_API_KEY` | 检查 API Key 是否设置 |

---

## 💡 技巧

### 如何快速输入 API Key 而不暴露？

在 PowerShell 中使用 `-AsSecureString`：
```powershell
$apiKey = Read-Host "输入 API Key" -AsSecureString
[System.Environment]::SetEnvironmentVariable('DEEPSEEK_API_KEY', $apiKey, 'User')
```

### 如何验证 API Key 有效性？

```powershell
python setup_deepseek.py
# 然后选择选项 3 验证
```

---

## 🚀 成功案例

```
User > fastjson 漏洞有什么危害

🤖 Aegis:
【Aegis 终端 - 威胁情报分析】

**目标：** CVE-2023-50505 - Fastjson 远程代码执行

Fastjson 的反序列化漏洞允许攻击者...
[AI 生成的完整答案]
```

---

**现在开始吧！只需 5 分钟，你就能拥有一个完整的企业级 RAG 系统！** 🎉
