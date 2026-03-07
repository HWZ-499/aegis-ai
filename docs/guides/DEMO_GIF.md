# 演示 GIF 制作指南

> 目标：展示「编写漏洞代码 → 保存触发扫描 → 实时诊断 → 点击灯泡 → AI 精准修复」的完整闭环。

---

## 1. 推荐工具

| 工具 | 平台 | 说明 |
|------|------|------|
| **ScreenToGif** | Windows | 开源，支持录制 → 编辑 → 导出 GIF，帧率可调 |
| **LICEcap** | Win/Mac | 轻量，直接录制为 GIF |
| **Kap** | macOS | 开源，支持 GIF/MP4/WebM |
| **Peek** | Linux | GTK 录屏，导出 GIF |

---

## 2. 录制场景脚本（约 30–45 秒）

### 场景 A：NoSQL 注入 + AI 修复（推荐）

1. **准备**：打开 VSCode/Cursor，工作区为 `aegis-ai-core` 或包含 NodeGoat 的目录
2. **新建文件**：`demo.js`，输入以下漏洞代码：

```javascript
const express = require('express');
const mongoose = require('mongoose');

async function getUser(req, res) {
  const id = req.params.id;  // 用户输入，未验证
  const user = await User.findOne({ _id: id });  // NoSQL 注入
  res.json(user);
}
```

3. **保存**（Ctrl+S）→ 等待 1–2 秒，观察波浪线诊断出现
4. **悬停**：鼠标悬停在 `id` 或 `findOne` 上，展示诊断详情
5. **点击灯泡**：点击行内灯泡图标 → 选择「Apply AI Fix」
6. **确认修复**：展示 AI 生成的参数化查询修复代码

### 场景 B：硬编码凭证（备选）

1. 新建 `config.js`，输入：

```javascript
const apiKey = "sk-1234567890abcdef";  // 硬编码
module.exports = { apiKey };
```

2. 保存 → 诊断出现 → 灯泡 → AI 修复（建议改为 `process.env.API_KEY`）

---

## 3. 录制参数建议

| 参数 | 建议值 |
|------|--------|
| 分辨率 | 1280×720 或 1920×1080 |
| 帧率 | 10–15 fps（GIF 体积与流畅度平衡） |
| 时长 | 30–45 秒 |
| 光标 | 保持可见，便于展示操作 |

---

## 4. 后期处理

- **裁剪**：去掉首尾空白，只保留核心操作
- **加速**：等待扫描的 1–2 秒可适当加速（1.5x）
- **标注**：可选在关键步骤加文字（如「保存」「AI 修复」）
- **输出**：GIF 建议 < 5MB，可考虑 WebP 或 MP4 作为备选

---

## 5. 放置位置

- 主 README：`![Demo](docs/assets/demo.gif)`
- 扩展 README（aegis-vscode/README.md）：Marketplace 展示页
- 建议路径：`docs/assets/demo.gif`（需创建 `docs/assets/` 目录）

---

## 6. 检查清单

- [ ] 演示代码能稳定触发漏洞诊断
- [ ] AI 修复流程完整（灯泡 → Apply AI Fix → 代码替换）
- [ ] 已配置 `DEEPSEEK_API_KEY`，AI 修复可用
- [ ] Status Bar 可见（`Aegis: N issues` 或 `Aegis: Secure`）
- [ ] GIF 体积适中，加载不卡顿
