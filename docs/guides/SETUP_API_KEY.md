# 🔑 API Key 设置指南

## ⚠️ 重要提醒

**旧 Key 已泄露**（之前写死在代码里），请立即：
1. 登录 [DeepSeek 控制台](https://platform.deepseek.com/) 撤销旧 Key
2. 生成新 Key 并按照下面方式设置

---

## 方法 1：环境变量（推荐，当前代码已支持）

### Windows PowerShell（当前会话有效）

```powershell
# 设置 Key
$env:DEEPSEEK_API_KEY = "sk-你的新Key"

# 验证是否设置成功
echo $env:DEEPSEEK_API_KEY

# 然后启动服务
cd aegis-ai-core
uvicorn aegis_server:app --reload --port 8000
```

### Windows PowerShell（永久设置，推荐）

```powershell
# 永久设置到用户环境变量
[System.Environment]::SetEnvironmentVariable('DEEPSEEK_API_KEY', 'sk-你的新Key', 'User')

# 重新打开 PowerShell 窗口后生效，或刷新当前窗口：
$env:DEEPSEEK_API_KEY = [System.Environment]::GetEnvironmentVariable('DEEPSEEK_API_KEY', 'User')
```

### Windows CMD

```cmd
set DEEPSEEK_API_KEY=sk-你的新Key
echo %DEEPSEEK_API_KEY%
```

### Linux / macOS

```bash
export DEEPSEEK_API_KEY="sk-你的新Key"
echo $DEEPSEEK_API_KEY
```

---

## 方法 2：使用 .env 文件（更友好，需要安装 python-dotenv）

### 步骤 1：安装 python-dotenv

```bash
cd aegis-ai-core
pip install python-dotenv
```

### 步骤 2：创建 .env 文件

在 `aegis-ai-core` 目录下创建 `.env` 文件：

```bash
# 复制模板
copy .env.example .env
```

然后编辑 `.env`，填入你的 Key：

```
DEEPSEEK_API_KEY=sk-你的新Key
```

### 步骤 3：代码会自动加载（如果已添加 dotenv 支持）

如果代码已支持 `.env`，启动时会自动读取。否则需要手动添加：

```python
from dotenv import load_dotenv
load_dotenv()  # 在读取环境变量之前调用
```

---

## 验证设置

启动服务后，如果看到以下提示说明配置成功：

```
🔌 [System] 正在挂载本地向量数据库...
🚀 Aegis Server 准备就绪！
```

如果看到 `❌ 未配置 DEEPSEEK_API_KEY`，说明环境变量未设置成功。

---

## 常见问题

### Q: 设置了环境变量但服务还是报错？

A: 确保：
- 在**同一个 PowerShell/CMD 窗口**中设置环境变量并启动服务
- 或者使用永久设置方式，然后**重新打开**终端窗口

### Q: 如何查看当前设置的环境变量？

**PowerShell:**
```powershell
echo $env:DEEPSEEK_API_KEY
```

**CMD:**
```cmd
echo %DEEPSEEK_API_KEY%
```

**Linux/macOS:**
```bash
echo $DEEPSEEK_API_KEY
```

### Q: 想临时测试不同的 Key？

在启动服务的终端窗口直接设置：
```powershell
$env:DEEPSEEK_API_KEY = "sk-临时测试Key"
# 然后重启服务
```

---

## 安全建议

✅ **推荐做法：**
- 使用环境变量或 `.env` 文件（已加入 `.gitignore`）
- 不要将 Key 提交到 Git
- 定期轮换 Key

❌ **禁止做法：**
- 在代码中硬编码 Key
- 将 `.env` 文件提交到 Git
- 在公开场合分享 Key
