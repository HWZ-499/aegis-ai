# VSCode Marketplace 发布指南

> 将 Aegis AI Security Scanner 发布到 [Visual Studio Code Marketplace](https://marketplace.visualstudio.com/)。

---

## 1. 前置条件

| 项目 | 说明 |
|------|------|
| Node.js | ≥ 18 |
| vsce | `npm install -g @vscode/vsce` |
| Azure DevOps 账号 | 与 Microsoft 账号相同 |
| Publisher | 在 Marketplace 创建 Publisher（见下） |

---

## 2. 创建 Publisher

1. 打开 [Marketplace 发布管理页](https://marketplace.visualstudio.com/manage)
2. 使用 Microsoft 账号登录
3. 点击 **Create publisher**
4. 填写：
   - **ID**：`aegis-ai`（与 `package.json` 中 `publisher` 一致，创建后不可改）
   - **Name**：`Aegis AI`（展示名称）

---

## 3. 创建 Personal Access Token (PAT)

1. 打开 [Azure DevOps PAT 页面](https://dev.azure.com/)
2. 选择组织 → **User settings** → **Personal access tokens**
3. **New Token**：
   - Name：`vsce-publish`
   - Scopes：**Custom defined** → **Marketplace** → **Manage**
4. 创建后**立即复制** Token（只显示一次）

---

## 4. 登录 vsce

```bash
cd aegis-vscode
vsce login aegis-ai
# 粘贴 PAT 后回车
```

---

## 5. 发布前检查

```bash
cd aegis-vscode

# 安装依赖并编译
npm ci
npm run compile

# 打包（不发布，仅生成 .vsix）
vsce package

# 检查生成的 .vsix 文件
ls -la *.vsix
```

**package.json 必填字段**：`name`, `displayName`, `version`, `publisher`, `description`, `engines.vscode`, `license`

**安全约束**（vsce 会校验）：
- README/CHANGELOG 中的图片不能为用户提供的 SVG
- 图片 URL 必须为 `https://`
- 无硬编码 API Key 或敏感信息

---

## 6. 发布

```bash
# 发布当前版本
vsce publish

# 或自动递增版本后发布
vsce publish patch   # 0.2.0 → 0.2.1
vsce publish minor   # 0.2.0 → 0.3.0
vsce publish major   # 0.2.0 → 1.0.0
```

首次发布会提示确认扩展信息；后续发布会直接上传。

---

## 7. 发布后

- 扩展页：`https://marketplace.visualstudio.com/items?itemName=aegis-ai.aegis-ai-security`
- 安装命令：`code --install-extension aegis-ai.aegis-ai-security`
- 数据查看：在 [Manage](https://marketplace.visualstudio.com/manage) 中查看安装量、评分、评论

---

## 8. 版本更新流程

1. 更新 `aegis-vscode/package.json` 中的 `version`
2. 更新 `aegis-vscode/CHANGELOG.md` 记录变更
3. 运行 `vsce package` 验证
4. 运行 `vsce publish` 或 `vsce publish patch/minor/major`

---

## 9. 常见问题

| 问题 | 处理 |
|------|------|
| `vsce publish` 提示未登录 | 执行 `vsce login aegis-ai` |
| 图片校验失败 | 确保 README/CHANGELOG 中无用户 SVG，图片 URL 为 https |
| 扩展 ID 冲突 | 检查 `package.json` 中 `name` 是否与已有扩展冲突 |
| 发布后未立即显示 | Marketplace 有数分钟延迟，稍后刷新 |
