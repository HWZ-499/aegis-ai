# 环境变量设置指南

## 方法 1: Windows PowerShell（推荐）

### 临时设置（仅当前 PowerShell 窗口有效）
```powershell
$env:DEEPSEEK_API_KEY = "sk-your-actual-key-here"
```

然后运行程序：
```powershell
python aegis_shell_enterprise.py
```

---

## 方法 2: Windows 永久设置（推荐）

### 步骤 1: 打开环境变量设置
在 PowerShell 中运行：
```powershell
[System.Environment]::SetEnvironmentVariable('DEEPSEEK_API_KEY', 'sk-your-actual-key-here', 'User')
```

### 步骤 2: 重启 PowerShell 使变量生效
关闭当前 PowerShell 窗口，重新打开一个新的

### 步骤 3: 验证设置成功
```powershell
$env:DEEPSEEK_API_KEY
```
应该显示你的 API Key

---

## 方法 3: .env 文件（开发环境）

### 步骤 1: 创建 .env 文件
在项目根目录创建 `.env` 文件（与 aegis_shell_enterprise.py 同级）

### 步骤 2: 写入内容
```
DEEPSEEK_API_KEY=sk-your-actual-key-here
DEEPSEEK_API_URL=https://api.deepseek.com/chat/completions
RAG_DISTANCE_THRESHOLD=1.5
RAG_API_TIMEOUT=30
RAG_RETRY_MAX_ATTEMPTS=3
CHROMADB_PATH=./aegis_db
```

### 步骤 3: 安装 python-dotenv
```powershell
pip install python-dotenv
```

### 步骤 4: 修改代码加载 .env 文件
在 aegis_shell_enterprise.py 顶部加入：
```python
from dotenv import load_dotenv
load_dotenv()
```

### 步骤 5: 重要：.env 文件不要上传到 Git
在 .gitignore 中添加：
```
.env
```

---

## 如何获取 DeepSeek API Key？

### 步骤 1: 访问官网
https://platform.deepseek.com/

### 步骤 2: 注册和登录
- 点击 "Sign Up"
- 使用邮箱或 GitHub 账号注册
- 登录账户

### 步骤 3: 创建 API Key
- 点击 "API Keys" 或 "Account Settings"
- 选择 "Create New API Key"
- 复制显示的 Key（格式：sk-xxxxxx）

### 步骤 4: 保管好你的 Key
⚠️ **重要**：
- 不要在代码中硬编码 Key
- 不要分享给他人
- 如果泄露，立即撤销并生成新的

---

## 快速测试

### 检查环境变量是否设置成功
```powershell
# 查看 API Key 是否设置了
echo $env:DEEPSEEK_API_KEY

# 如果显示你的 Key，说明设置成功 ✅
# 如果为空，说明设置失败 ❌
```

### 运行程序测试
```powershell
cd C:\Users\HT341\aegis-ai\aegis-ai-core
python aegis_shell_enterprise.py
```

---

## 常见问题

### Q: 我在哪里能看到我的 API Key？
A: 登录 https://platform.deepseek.com/api-keys

### Q: 设置了环境变量但还是报错？
A: 
1. 确保没有多余的空格
2. 重启 PowerShell
3. 用 `echo $env:DEEPSEEK_API_KEY` 验证

### Q: API Key 泄露了怎么办？
A:
1. 立即登录官网撤销 Key
2. 生成新的 Key
3. 更新环境变量

### Q: 我没有 API Key 怎么办？
A: 去 https://platform.deepseek.com 注册并创建 API Key

### Q: 有免费额度吗？
A: 有，新用户通常有免费试用额度。具体见官网说明。

---

## 最简单的设置方法（5 分钟）

### 1️⃣ 获取 API Key
去 https://platform.deepseek.com/api-keys 复制你的 Key

### 2️⃣ 打开 PowerShell
`Win + R` → 输入 `powershell` → 回车

### 3️⃣ 设置环境变量
```powershell
[System.Environment]::SetEnvironmentVariable('DEEPSEEK_API_KEY', 'sk-你的KEY', 'User')
```

### 4️⃣ 关闭重开 PowerShell
让设置生效

### 5️⃣ 测试运行
```powershell
cd C:\Users\HT341\aegis-ai\aegis-ai-core
python aegis_shell_enterprise.py
```

完成！✅

---

## 验证清单

- [ ] 我有 DeepSeek API Key（从 platform.deepseek.com 获取）
- [ ] 我用 PowerShell 或 .env 文件设置了环境变量
- [ ] 我验证了 `$env:DEEPSEEK_API_KEY` 有值
- [ ] 我用 `python aegis_shell_enterprise.py` 成功运行了程序

如果都打钩了，你就可以开始使用 RAG 系统了！🚀
