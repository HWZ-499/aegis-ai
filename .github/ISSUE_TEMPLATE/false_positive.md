---
name: 误报报告
about: 报告 Aegis AI 对安全代码发出了错误的漏洞警告
title: '[FP] '
labels: false-positive
assignees: ''
---

## 误报描述

<!-- 描述 Aegis AI 对哪段代码发出了错误的警告 -->

**报告的漏洞类型**：SQL 注入 / NoSQL 注入 / XSS / RCE / 路径穿越 / 其他

## 误报代码

<!-- 粘贴触发误报的完整代码片段 -->

```javascript
// 在此粘贴代码
```

**文件名**：`example.js`
**报告行号**：第 X 行

## 为什么这不是漏洞

<!-- 解释为什么这段代码实际上是安全的 -->

例如：
- 该变量已通过 `parseInt()` / `validator.isNumeric()` 等函数验证
- 使用了参数化查询（Prepared Statement）
- 输入来自硬编码常量，不受用户控制
- 其他原因：

## 使用的防御机制

- [ ] 参数化查询 / Prepared Statement
- [ ] 白名单验证
- [ ] 类型强转（parseInt、Number 等）
- [ ] Guard Clause 早返回（`if (!valid) return;`）
- [ ] ORM 框架（Sequelize / Mongoose / SQLAlchemy 等）
- [ ] 其他：

## 环境信息

| 项目 | 内容 |
|------|------|
| Aegis AI 版本 | Core 1.5.x / VS Code 0.6.x |
| 扫描语言 | JavaScript / TypeScript / Python / PHP / Java / Go / C/C++ |
| 框架 | Express / Django / Flask / 无 |

## 期望行为

Aegis AI 应该识别该防御机制，不报告此漏洞。

## 补充信息

<!-- 其他有助于定位问题的信息，例如完整函数上下文 -->
