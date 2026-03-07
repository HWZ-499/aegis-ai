# 贡献指南

感谢你有兴趣为 Aegis AI 做贡献！本文档说明如何搭建开发环境、如何添加新的漏洞检测规则，以及提交代码的规范要求。

---

## 目录

- [环境搭建](#环境搭建)
- [项目结构说明](#项目结构说明)
- [添加新漏洞检测规则](#添加新漏洞检测规则)
- [提交规范](#提交规范)
- [代码风格](#代码风格)
- [运行测试](#运行测试)
- [提交 PR 流程](#提交-pr-流程)

---

## 环境搭建

### 前置条件

- Python >= 3.10
- Node.js >= 18
- VSCode 或 Cursor

### 1. 克隆仓库

```bash
git clone https://github.com/HWZ-499/aegis-ai.git
cd aegis-ai
```

### 2. 安装 Python 依赖

```bash
cd aegis-ai-core
pip install -r requirements.txt
```

### 3. 配置 API Key（AI 修复功能需要）

```bash
# 复制示例配置
cp .env.example .env

# 编辑 .env，填入你的 DeepSeek API Key
# DEEPSEEK_API_KEY=your_key_here
```

### 4. 编译 VSCode 扩展（修改扩展代码时需要）

```bash
cd aegis-vscode
npm install
npm run compile
```

### 5. 验证安装

```bash
cd aegis-ai-core
# 运行核心测试套件
python -m pytest tests/ -v --tb=short

# 扫描一个测试文件
python -m src.scanner.cli scripts/test_cases/js_express.js --format json
```

---

## 项目结构说明

```
aegis-ai/
├── aegis-ai-core/
│   ├── src/
│   │   ├── analysis/
│   │   │   ├── rules/          ← 漏洞检测规则（主要贡献点）
│   │   │   │   ├── sql_injection/
│   │   │   │   │   ├── ast_rule.py         # Python AST 规则
│   │   │   │   │   └── javascript_ast_rule.py  # JS/TS AST 规则
│   │   │   │   ├── nosql_injection/
│   │   │   │   ├── xss/
│   │   │   │   ├── rce/
│   │   │   │   ├── path_traversal/
│   │   │   │   └── php/
│   │   │   ├── taint/          ← 污点分析引擎
│   │   │   └── analyzers/      ← 语言分析器
│   │   ├── lsp/                ← LSP Server
│   │   └── scanner/            ← AI 分析器、RAG 增强
│   ├── scripts/test_cases/     ← 规则测试用例
│   └── tests/                  ← pytest 测试套件
└── aegis-vscode/
    └── src/extension.ts        ← VSCode 扩展
```

---

## 添加新漏洞检测规则

以添加一个新的 JavaScript SSTI（服务端模板注入）规则为例：

### Step 1：创建规则目录

```bash
mkdir -p aegis-ai-core/src/analysis/rules/ssti
touch aegis-ai-core/src/analysis/rules/ssti/__init__.py
touch aegis-ai-core/src/analysis/rules/ssti/javascript_ast_rule.py
```

### Step 2：实现规则类

规则必须继承 `SecurityRule` 并实现 `visit()` 和/或 `after_file()` 方法：

```python
# aegis-ai-core/src/analysis/rules/ssti/javascript_ast_rule.py
from src.analysis.base.security_rule import SecurityRule
from src.analysis.base.analysis_context import AnalysisContext
from typing import Any

class SSTIJavaScriptRule(SecurityRule):
    """检测 JavaScript 服务端模板注入漏洞。"""

    @property
    def rule_id(self) -> str:
        return "SSTI-JS-001"

    @property
    def description(self) -> str:
        return "服务端模板注入：用户输入直接传入模板引擎"

    def visit(self, node: Any, context: AnalysisContext) -> None:
        # 在此实现 AST 节点访问逻辑
        pass
```

### Step 3：注册规则

在 `src/analysis/rule_engine.py` 的对应语言分析函数中导入并注册你的规则。

### Step 4：编写测试用例（必须）

在 `scripts/test_cases/` 下创建测试文件：

```
scripts/test_cases/
├── ssti_true_vulnerable.js   ← 正样本（应该被检出）
└── ssti_false_safe.js        ← 负样本（不应该被检出）
```

正样本示例（`ssti_true_vulnerable.js`）：
```javascript
// 应报告：用户输入直接传入模板引擎
const template = req.body.template;
const result = ejs.render(template, data);  // SSTI
```

负样本示例（`ssti_false_safe.js`）：
```javascript
// 不应报告：使用硬编码模板
const template = fs.readFileSync('./views/index.ejs', 'utf8');
const result = ejs.render(template, { user: req.body.user });
```

### Step 5：运行验证

```bash
cd aegis-ai-core

# 验证正样本被检出
python -m src.scanner.cli scripts/test_cases/ssti_true_vulnerable.js --format json

# 验证负样本没有误报
python -m src.scanner.cli scripts/test_cases/ssti_false_safe.js --format json

# 运行完整测试套件确保没有回归
python -m pytest tests/ -v
```

---

## 提交规范

使用 [Conventional Commits](https://www.conventionalcommits.org/) 格式：

```
<type>(<scope>): <简短描述>

[可选 body]

[可选 footer]
```

### 类型（type）

| 类型 | 说明 |
|------|------|
| `feat` | 新功能（新规则、新语言支持等） |
| `fix` | Bug 修复（误报、漏报修复等） |
| `perf` | 性能优化 |
| `refactor` | 重构（不影响功能） |
| `test` | 添加或修改测试 |
| `docs` | 文档更新 |
| `chore` | 构建脚本、依赖更新等 |

### 范围（scope）示例

- `sql`, `xss`, `rce`, `nosql`, `php` — 漏洞类型
- `taint` — 污点分析引擎
- `lsp` — LSP Server
- `vscode` — VSCode 扩展
- `ai` — AI 分析器

### 提交示例

```bash
feat(sql): 新增 MySQL stored procedure 中的注入检测

添加对 CALL proc(user_input) 模式的检测，覆盖存储过程调用场景。

Closes #42
```

```bash
fix(taint): 修复 Guard Clause 误报——isValid 布尔变量不应传播 taint

Fixes #38
```

---

## 代码风格

### Python

- 遵循 **PEP 8** 严格模式
- 所有函数必须有 **Google Style Docstring**（Args、Returns、Raises）
- 使用 **Type Hints** 标注所有参数和返回值，禁止裸 `Any`
- 使用 `logger` 而不是 `print()`

```python
def analyze_node(self, node: Any, context: AnalysisContext) -> list[Finding]:
    """分析 AST 节点是否存在漏洞。

    Args:
        node: Tree-sitter AST 节点。
        context: 当前文件的分析上下文。

    Returns:
        发现的漏洞列表，无漏洞时返回空列表。

    Raises:
        ValueError: 当 node 类型不受支持时。
    """
```

### TypeScript（VSCode 扩展）

- 启用 `strict` 模式（已在 `tsconfig.json` 配置）
- 禁止使用 `any`，使用具体接口类型
- 使用 **JSDoc** 注释公共函数
- 清理 RxJS 订阅（避免内存泄漏）

---

## 运行测试

```bash
cd aegis-ai-core

# 运行全部测试
python -m pytest tests/ -v

# 只运行特定模块测试
python -m pytest tests/test_taint_analysis.py -v

# 运行测试并输出覆盖率
python -m pytest tests/ --cov=src --cov-report=term-missing

# 运行守卫子句专项测试
python -m pytest scripts/test_cases/guard_clause_test.py -v
```

---

## 提交 PR 流程

1. Fork 本仓库
2. 创建功能分支：`git checkout -b feat/ssti-rule`
3. 实现代码 + 测试用例
4. 确认测试通过：`python -m pytest tests/ -v`
5. 提交代码（遵循提交规范）
6. 提交 Pull Request，填写 PR 模板中的检查清单

如果你不确定某个实现方向，建议先开一个 Issue 讨论，避免无效工作。

---

## Good First Issue

适合新贡献者的任务会标注 `good-first-issue` 标签，通常具有以下特点：

- 范围明确，可在 1–2 天内完成
- 不依赖复杂污点分析或跨文件逻辑
- 有现成参考（如类似规则的实现）

**浏览 Good First Issues**：  
[Issues with good-first-issue label](https://github.com/aegis-ai/aegis-ai/issues?q=label%3A%22good+first+issue%22)

若你发现适合新贡献者的任务，可使用 [建议 Good First Issue](.github/ISSUE_TEMPLATE/good_first_issue.md) 模板提交，维护者审核后会添加标签。

---

## 社区与安全

- **[行为准则（Code of Conduct）](CODE_OF_CONDUCT.md)**：参与本社区即表示同意遵守 [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/)。
- **[安全策略（SECURITY）](SECURITY.md)**：漏洞披露与安全相关问题请参见 SECURITY.md。

感谢你的贡献！
