# Aegis AI 推广策略与增长规划

> **创建日期**: 2026-03-17 | **文档版本**: 1.0 | **状态**: 活跃执行中
>
> 本文档是 Aegis AI Security Scanner 从 Marketplace 发布到用户增长的完整推广规划，
> 覆盖品牌定位、渠道策略、内容矩阵、社区建设与阶段性里程碑。

---

## 目录

- [一、当前态势分析](#一当前态势分析)
- [二、目标用户画像](#二目标用户画像)
- [三、核心卖点提炼（USP）](#三核心卖点提炼usp)
- [四、Phase 1 — 冷启动（第 1-4 周）](#四phase-1--冷启动第-14-周)
- [五、Phase 2 — 内容驱动增长（第 5-12 周）](#五phase-2--内容驱动增长第-512-周)
- [六、Phase 3 — 社区与生态（第 3-6 月）](#六phase-3--社区与生态第-36-月)
- [七、Phase 4 — 长期品牌建设（6 月+）](#七phase-4--长期品牌建设6-月)
- [八、Marketplace 优化清单](#八marketplace-优化清单)
- [九、关键指标追踪](#九关键指标追踪)
- [十、竞品分析与差异化定位](#十竞品分析与差异化定位)
- [十一、风险与应对](#十一风险与应对)
- [十二、执行检查清单](#十二执行检查清单)
- [十三、变更记录](#十三变更记录)

---

## 一、当前态势分析

### 1.1 产品现状

| 维度 | 状态 |
|------|------|
| VS Code Marketplace | ✅ 已发布 v0.3.0 |
| PyPI | ✅ 已发布 aegis-ai-core |
| GitHub 仓库 | 公开，MIT 协议 |
| 支持语言 | JS/TS/Python/PHP/Java/Go（6 种） |
| 漏洞类型 | 10+ 类（SQLi, NoSQLi, XSS, RCE, SSRF 等） |
| AI 修复 | DeepSeek / OpenAI / Ollama |
| 基准测试 | NodeGoat F1=1.00, Django F1=0.92 |
| CI/CD | GitHub Actions, SARIF 输出 |

### 1.2 优势

- **开源 + 免费**：MIT 协议，零门槛
- **实时扫描**：保存即扫描，1 秒内反馈
- **AI 修复**：不只报问题，还帮你修
- **多语言深度分析**：不是 regex 匹配，是 AST + 污点追踪
- **基准成绩优秀**：有量化数据支撑

### 1.3 挑战

- 品牌认知度为零，需从零冷启动
- 安全工具赛道有 Semgrep、Snyk、SonarQube 等成熟竞品
- 个人开发者/小团队项目，缺乏企业背书
- 文档和演示素材尚不完善

---

## 二、目标用户画像

### 2.1 主要目标（Primary）

| 画像 | 特征 | 痛点 | 我们的价值 |
|------|------|------|-----------|
| **独立开发者** | 个人项目/自由职业，JS/Python 为主 | 知道安全重要但不懂安全，没时间学 | 零配置，保存即扫描，AI 帮修 |
| **初中级后端开发者** | 1-3 年经验，写 Node.js/Django/PHP | 代码审查没人看安全，CI 太重 | IDE 内实时反馈，学习安全知识 |
| **安全学习者/学生** | CTF 爱好者，安全入门 | 想理解漏洞原理和修复方法 | 真实漏洞检测 + AI 修复解释 |

### 2.2 次要目标（Secondary）

| 画像 | 特征 | 痛点 | 我们的价值 |
|------|------|------|-----------|
| **小型团队 Tech Lead** | 5-20 人团队 | 想加安全门禁但 Snyk/SonarQube 太贵太重 | 免费开源，CLI + CI 集成 |
| **DevSecOps 工程师** | 负责安全流水线 | 需要补充 SAST 覆盖 | SARIF 输出，GitHub Security 集成 |
| **开源项目维护者** | 维护公共仓库 | 想确保贡献代码安全 | GitHub Actions 集成，PR 扫描 |

---

## 三、核心卖点提炼（USP）

### 一句话定位

> **"写代码的时候就能发现和修复安全漏洞 — 免费、开源、AI 驱动"**

### 差异化三角

```
         ┌─────────────┐
         │  免费 + 开源  │  ← Snyk/Checkmarx 收费
         └──────┬──────┘
                │
    ┌───────────┼───────────┐
    │                       │
┌───┴───┐             ┌────┴────┐
│ IDE 实时 │             │ AI 自动修 │  ← Semgrep 只报不修
│ 1s 反馈  │             │ 一键替换  │
└─────────┘             └─────────┘
     ↑                       ↑
  CodeQL 需要                ESLint 安全插件
  编译 + CI 才能跑           只有 regex 匹配
```

### 关键 Messages（不同场景使用）

| 场景 | 信息 |
|------|------|
| **Marketplace 副标题** | Real-time SAST scanner with AI auto-fix — SQL/NoSQL injection, XSS, RCE across 6 languages |
| **Twitter/X 一句话** | Stop shipping vulnerabilities. Aegis AI scans your code in real-time and fixes security issues with one click. Free & open source. |
| **技术社区标题** | 我写了一个开源 VSCode 安全扫描插件：AST 污点分析 + AI 自动修复，NodeGoat F1 满分 |
| **Reddit/HN 标题** | Show HN: Aegis AI — Free open-source SAST scanner for VS Code with AI auto-fix (6 languages, 10+ vuln types) |
| **给学生** | 不用学安全也能写安全的代码 — Aegis AI 在你写代码时实时检测漏洞并教你怎么修 |

---

## 四、Phase 1 — 冷启动（第 1-4 周）

**目标**：100+ 安装量，建立初始用户群，收集第一批反馈

### 4.1 Marketplace 页面优化（第 1 周）

这是最高 ROI 的工作，因为所有流量都会落到这个页面。

- [ ] **演示 GIF/视频**（最关键）
  - 录制 30 秒 GIF：打开有漏洞的文件 → 保存 → 波浪线出现 → 点灯泡 → AI 修复 → 漏洞消失
  - 工具推荐：ScreenToGif (Windows) / LICEcap
  - 放入 `docs/assets/` 并在 README 和 Marketplace 页面顶部展示
  - **这是转化率最大的单一因素**

- [ ] **README 结构优化**
  - 开头：一句话 + GIF + Install 按钮
  - "Why Aegis AI?" 部分用对比表格（vs Semgrep, vs ESLint-security）
  - 添加 "Getting Started in 60 seconds" 极简步骤
  - 底部加 Star 按钮和社区链接

- [ ] **Marketplace 元数据完善**
  - Categories: 确保在 `Linters` 和 `Programming Languages` 下可被搜索到
  - Keywords: 补充 `sast`, `vulnerability scanner`, `code security`, `devsecops`
  - Gallery Banner: 使用专业深色主题

### 4.2 GitHub 仓库优化（第 1 周）

- [ ] **README 添加**：
  - 安装量 badge（Marketplace installs shield）
  - 演示 GIF
  - "Star this repo" CTA
  - `## Contributing` 部分突出"欢迎贡献"

- [ ] **创建 GitHub Topics**：`security`, `sast`, `vscode-extension`, `static-analysis`, `ai`, `devsecops`

- [ ] **创建 Discussions 板块**：开启 GitHub Discussions，分为 Q&A / Feature Requests / Show & Tell

- [ ] **Issue Templates**：Bug Report / Feature Request / False Positive Report 模板

- [ ] **第一个 Release**：创建 GitHub Release（tag v0.3.0），写清晰的 Release Notes

### 4.3 首发帖子（第 1-2 周）

在以下平台发布介绍帖，**每个平台的标题和内容需针对性调整**：

#### 中文社区

| 平台 | 策略 | 预期效果 |
|------|------|---------|
| **掘金** | 长文：《我开发了一个开源 VSCode 安全扫描插件：3 层分析 + AI 自动修复》，技术深度文 | 重点讲架构设计、AST 污点分析原理、NodeGoat 基准测试过程 |
| **V2EX** | `/t/create` 简短介绍 + 项目链接，标题突出"开源""免费" | V2EX 用户对开源项目友好，可能获得早期 Star |
| **知乎** | 回答安全相关问题（如"如何在开发阶段发现安全漏洞"）时自然提及 | 长尾流量 |
| **CSDN/博客园** | 技术教程：《VSCode 实时安全扫描：从 0 到 1 构建 SAST 工具》 | SEO 长尾 |
| **微信公众号/技术群** | 分享链接 + 简短介绍 | 种子用户 |

#### 英文社区

| 平台 | 策略 | 注意事项 |
|------|------|---------|
| **Hacker News** | "Show HN: Aegis AI — Open-source SAST for VS Code with AI auto-fix" | 周二-周四上午发，标题不要太营销 |
| **Reddit r/vscode** | "I built a free security scanner extension with AI fix suggestions" | 先贡献再推广，别纯广告 |
| **Reddit r/netsec** | 技术角度分享，强调 AST+Taint 分析 | 这个社区最看重技术深度 |
| **Reddit r/webdev** | 面向 Web 开发者，强调 JS/TS/Python | 用例驱动 |
| **Dev.to** | 详细教程文章 | 代码示例丰富 |
| **Twitter/X** | 发布线程：问题 → 解决方案 → Demo GIF → 链接 | @vikimaster @syntax 等技术博主 |
| **Product Hunt** | 考虑做一次正式 Launch | 需要准备好所有素材后再上 |

### 4.4 种子用户激活（第 2-4 周）

- [ ] 在 GitHub Issues 中创建 "Good First Issue" 标签的简单任务
- [ ] 对每一个 Star / Issue / PR 及时回复和感谢
- [ ] 找 3-5 位开发者朋友试用，收集真实反馈
- [ ] 在 Marketplace 页面回复所有评论和评分

---

## 五、Phase 2 — 内容驱动增长（第 5-12 周）

**目标**：500+ 安装量，建立内容矩阵，形成搜索引擎长尾流量

### 5.1 系列技术博客

以教育价值为核心，自然引出工具。每篇都是独立有价值的技术内容。

| # | 标题（中英双语） | 核心内容 | 自然引入点 |
|---|--------------|---------|-----------|
| 1 | **SQL 注入检测：从 Regex 到 AST 污点追踪的进化之路** | 对比 regex / AST / taint 三种方式的检测能力 | "我在 Aegis AI 中实现了三层分析管道" |
| 2 | **如何用 Tree-sitter 构建多语言安全分析器** | Tree-sitter 入门 + 多语言 AST 遍历 | "Aegis AI 用 Tree-sitter 支持 6 种语言" |
| 3 | **LLM 驱动的代码修复：Prompt 工程实战** | 框架感知 Prompt 设计、置信度阈值 | "Aegis AI 的 AI 修复管道如何工作" |
| 4 | **LSP 协议实战：构建实时代码分析器** | pygls + VSCode Extension 开发 | "如何让安全扫描器变成 IDE 原生体验" |
| 5 | **OWASP NodeGoat 安全审计实战** | 用 Aegis 扫描 NodeGoat 的完整过程 | 直接演示产品能力 |
| 6 | **NoSQL 注入：被忽视的 MongoDB 安全威胁** | MongoDB 注入原理 + 检测方法 | "Aegis AI 如何检测 DAO 层 NoSQL 注入" |
| 7 | **CI/CD 安全门禁：GitHub Actions + SARIF 实战** | 安全流水线搭建教程 | 使用 Aegis CLI + SARIF |
| 8 | **对比评测：5 款免费 SAST 工具横向对比** | 公正评测（包含自己和竞品） | 展示 Aegis 在特定场景的优势 |

### 5.2 视频内容

| 类型 | 内容 | 平台 |
|------|------|------|
| **60s 快速演示** | 安装 → 扫描 → 修复完整流程 | YouTube Shorts / B 站 / Twitter |
| **5min 教程** | "How to find SQL injection in your Node.js app" | YouTube / B 站 |
| **15min 深度** | 架构解析：AST + Taint + AI 三层管道 | YouTube / B 站 |
| **直播/录播** | 用 Aegis 审计一个真实开源项目 | B 站 / Twitch |

### 5.3 SEO 与长尾

- [ ] 确保 GitHub README 包含关键搜索词：`vscode security scanner`, `sast tool`, `sql injection detector`
- [ ] 技术博客标题覆盖长尾搜索意图
- [ ] Marketplace 关键词持续优化
- [ ] 在 StackOverflow 相关问题下提供有价值的回答（不要硬广）

---

## 六、Phase 3 — 社区与生态（第 3-6 月）

**目标**：1000+ 安装量，20+ GitHub Stars，活跃社区

### 6.1 社区建设

- [ ] **Discord / Telegram 群**：创建社区交流群，分为 #general / #bug-reports / #feature-requests / #rules-development
- [ ] **定期更新**：每月发布 "Monthly Update" 帖子，展示新功能和统计数据
- [ ] **贡献者激励**：
  - 贡献者墙（README 中展示）
  - "Contributors" badge
  - 优秀贡献者可以加入 Maintainer
  - Issue 标签：`good-first-issue`, `help-wanted`, `bounty`

### 6.2 合作与集成

| 方向 | 策略 |
|------|------|
| **教育机构** | 联系大学安全课程老师，Aegis 可作为教学工具（免费扫描 + AI 解释） |
| **安全培训平台** | 与 CTF 平台或安全训练营合作，提供集成 |
| **开源项目** | 为知名开源项目（如 Express, Django 插件）提交安全扫描结果 PR |
| **技术博主** | 联系安全/DevOps 领域博主，提供试用和合作机会 |
| **Awesome Lists** | 提交到 `awesome-vscode`, `awesome-security`, `awesome-static-analysis` 等列表 |

### 6.3 自定义规则生态

- [ ] 完善 DSL YAML 规则编写文档
- [ ] 提供 3-5 个示例规则包（OWASP Top 10, API Security, Cloud Security）
- [ ] 鼓励社区贡献规则，建立 `community-rules` 仓库

### 6.4 多 IDE 扩展

| IDE | 优先级 | 策略 |
|-----|--------|------|
| **Cursor** | 高 | 已兼容 VS Code 扩展，验证并在 README 标明 |
| **Windsurf** | 中 | 同 VS Code 生态，验证兼容性 |
| **JetBrains** | 中 | 基于 LSP4IJ 开发 IntelliJ Plugin |
| **Neovim** | 低 | 提供 LSP client 配置文档 |

---

## 七、Phase 4 — 长期品牌建设（6 月+）

**目标**：5000+ 安装量，成为 "免费开源 SAST" 品类的首选

### 7.1 技术会议与演讲

| 会议 | 场景 |
|------|------|
| **OWASP 本地分会** | 演讲：开源 SAST 工具的架构设计 |
| **GDG/Google DevFest** | Workshop：用 AI 修复代码安全漏洞 |
| **PyCon / JSConf** | Lightning Talk：Tree-sitter 多语言安全分析 |
| **安全会议** | Poster/Demo：Aegis AI 现场演示 |

### 7.2 企业功能与商业化探索

当社区足够大（5000+ 安装）时可考虑：

| 功能 | 模式 |
|------|------|
| **团队 Dashboard** | SaaS 付费 |
| **组织级规则管理** | 企业订阅 |
| **合规报告导出** | 企业订阅 |
| **优先支持 SLA** | 企业订阅 |
| **私有部署** | 企业订阅 |

核心引擎和 IDE 扩展**永远免费开源**，商业化只做增值层。

### 7.3 对标与定位演进

| 阶段 | 定位 |
|------|------|
| 现在 | "免费的 IDE 安全扫描器" |
| 6 个月后 | "开发者首选的开源 SAST 工具" |
| 1 年后 | "最快的 AI 驱动安全扫描平台" |

---

## 八、Marketplace 优化清单

Marketplace 页面是最重要的转化入口，需持续优化。

### 8.1 必做项

- [ ] **Hero GIF**：30s 演示动图放在 README 最顶部
- [ ] **Before/After 对比图**：左边红色波浪线 → 右边绿色 ✅
- [ ] **Install 体验优化**：确保 `pip install aegis-ai-core` 后即可使用，减少配置步骤
- [ ] **评分引导**：在扩展中适时提示"如果觉得有用，请给我们评分"（不要骚扰）
- [ ] **更新频率**：保持至少每月一次版本更新，Marketplace 算法偏好活跃扩展

### 8.2 A/B 测试方向

| 元素 | 测试方向 |
|------|---------|
| 标题 | "Aegis AI Security Scanner" vs "Aegis AI — Real-time Security Scanner" |
| 描述第一句 | 功能导向 vs 痛点导向 |
| 截图顺序 | GIF 优先 vs 功能列表优先 |

---

## 九、关键指标追踪

### 9.1 核心指标

| 指标 | 第 1 月目标 | 第 3 月目标 | 第 6 月目标 | 追踪方式 |
|------|-----------|-----------|-----------|---------|
| **Marketplace 安装量** | 100 | 500 | 2000 | Marketplace 后台 |
| **GitHub Stars** | 20 | 50 | 200 | GitHub Insights |
| **周活跃用户（WAU）** | 30 | 100 | 500 | 扩展 telemetry（可选） |
| **GitHub Issues** | 5 | 15 | 30 | GitHub |
| **社区贡献者** | 1 | 3 | 10 | GitHub |

### 9.2 内容指标

| 指标 | 第 1 月 | 第 3 月 | 第 6 月 |
|------|--------|--------|--------|
| 技术博客篇数 | 2 | 6 | 12 |
| 视频数量 | 1 | 3 | 6 |
| 外部引用/转载 | 0 | 5 | 15 |

### 9.3 质量指标

| 指标 | 目标 | 说明 |
|------|------|------|
| Marketplace 评分 | ≥ 4.0 | 低于 3.5 需紧急处理 |
| Issue 响应时间 | < 48h | 社区信任的关键 |
| 卸载率 | < 30% | 高卸载率说明产品有问题 |

---

## 十、竞品分析与差异化定位

### 10.1 竞品矩阵

| 特性 | **Aegis AI** | **Semgrep** | **SonarQube** | **Snyk Code** | **CodeQL** |
|------|-------------|-------------|---------------|---------------|------------|
| 价格 | **免费开源** | 社区版免费 | 社区版免费 | 免费额度有限 | 开源项目免费 |
| IDE 实时扫描 | **✅ 1s** | ✅ | 需要 SonarLint | ✅ | ❌ 需要 CI |
| AI 自动修复 | **✅ 一键替换** | ❌ | ❌ | ✅（付费） | ❌ |
| 多语言 | 6 种 | 30+ 种 | 20+ 种 | 10+ 种 | 10+ 种 |
| 安装复杂度 | 中 | 低 | 高 | 低 | 高 |
| 自定义规则 | YAML DSL | YAML | Java/Python | 有限 | QL |
| 污点分析 | **✅ 跨文件** | 有限 | ✅ | ✅ | **✅ 深度** |
| 离线可用 | **✅ Ollama** | ✅ | ✅ | ❌ | ✅ |

### 10.2 差异化打法

**不要试图在"规则数量"或"语言覆盖"上与 Semgrep/SonarQube 竞争。**

我们的差异化打法：

1. **"AI 修复" 是核心差异化** — 竞品只报问题，我们帮修。这是最直观的用户价值
2. **"开发者友好" 是体验差异化** — 零配置、1 秒反馈、IDE 原生体验
3. **"开源 + 本地 AI" 是信任差异化** — 代码不出本机（Ollama），企业安全团队最在意
4. **"真实基准成绩" 是可信度差异化** — NodeGoat F1=1.00 是硬数据

---

## 十一、风险与应对

| 风险 | 概率 | 影响 | 应对策略 |
|------|------|------|---------|
| 安装后配置复杂导致卸载 | 高 | 高 | 优化 onboarding：首次激活引导、自动检测 Python 环境、内置 fallback |
| 误报多导致差评 | 中 | 高 | 持续降低 FPR；提供便捷的 false positive 报告和 suppress 机制 |
| 竞品发布类似 AI 修复功能 | 中 | 中 | 保持迭代速度；深耕 dataflow 可视化等更深层差异化功能 |
| 社区发帖被当广告删除 | 中 | 低 | 先贡献价值再推广；帖子以教育内容为主 |
| DeepSeek API 不稳定影响体验 | 低 | 中 | 默认推荐 Ollama 本地模型；多 provider 兜底 |

---

## 十二、执行检查清单

### 第 1 周（立即行动）

- [ ] 录制演示 GIF（保存 → 扫描 → 灯泡 → AI 修复）
- [ ] 将 GIF 放入 Marketplace README 和 GitHub README 顶部
- [ ] 创建 GitHub Release v0.3.0
- [ ] 开启 GitHub Discussions
- [ ] 创建 Issue Templates（Bug / Feature / False Positive）
- [ ] 添加 GitHub Topics
- [ ] 提交到 `awesome-vscode` / `awesome-static-analysis` 列表

### 第 2 周

- [ ] 掘金发布技术深度文（架构设计 + 基准测试）
- [ ] V2EX 发布简短介绍帖
- [ ] Reddit r/vscode 发布介绍帖
- [ ] Dev.to 发布英文教程
- [ ] Twitter/X 发布 demo 线程

### 第 3-4 周

- [ ] Hacker News "Show HN" 投稿
- [ ] 第二篇技术博客（SQL 注入检测进化）
- [ ] 收集前 50 位用户反馈，整理 Top 3 痛点
- [ ] 基于反馈发布 v0.3.1 快速修复版

### 月度循环

- [ ] 发布版本更新
- [ ] 发布 1-2 篇技术博客
- [ ] 回顾安装/Star/Issue 指标
- [ ] 回复所有 GitHub Issues 和 Marketplace 评论

---

## 十三、变更记录

| 日期 | 变更内容 |
|------|----------|
| 2026-03-17 | 初版：完整推广策略规划 |
