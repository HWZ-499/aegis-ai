# Aegis-AI v1.2.0 代码质量优化计划

> 文档版本: 1.0
> 日期: 2026-03-12
> 状态: 待执行

---

## 一、背景

Aegis-AI 经过多个版本迭代，核心功能（多语言 SAST、污点分析、AI 增强、VSCode 集成）已基本成型。但在快速开发过程中积累了以下技术债务：

| # | 问题 | 严重度 | 影响范围 |
|---|------|--------|----------|
| 1 | 120+ 处 `except Exception` 宽泛异常捕获 | 高 | 37 个源文件 |
| 2 | `false_positive_manager.py` 时间戳 bug | 高 | 审计记录不可信 |
| 3 | 废弃模块 `ast_analyzer.py` / `security_rules.py` 仍被广泛导入 | 中 | 17+ 文件 |
| 4 | CORS 默认 `*` 全开放 | 中 | 安全配置 |
| 5 | VSCode Webview 潜在 XSS | 中 | 扩展安全 |
| 6 | `rag_system.py` 脚本混入包 | 低 | 模块导入 |
| 7 | `aegis_server.py` 模块级副作用 + 重复代码 | 中 | 服务端启动 |
| 8 | `openai` 隐藏依赖未声明 | 低 | 依赖管理 |
| 9 | 测试风格不统一（脚本式 vs pytest） | 低 | ~10 测试文件 |
| 10 | README 版本过旧，信息失真 | 中 | 项目文档 |

本文档制定分 6 个阶段的优化计划，遵循以下原则：

- **安全第一**：每个阶段完成后 CI 必须保持绿色
- **低风险优先**：先修定点 bug，再做大范围重构
- **按爆炸半径分组**：同文件修改尽量放在同阶段，避免冲突
- **依赖有序**：废弃模块迁移必须先于异常处理收紧

---

## 二、分阶段执行计划

### Phase 1: 定点 Bug 修复与配置加固

**对应问题**: #2, #4, #5, #8
**影响文件**: 4-5 个
**风险等级**: 极低

#### 1a. 修复 `false_positive_manager.py` 时间戳 bug

**文件**: `src/scanner/false_positive_manager.py`
**问题**: `created_at` 字段存储的是 `str(Path.cwd())`（当前工作目录路径），不是时间戳。

```python
# 修复前
"created_at": str(Path.cwd())

# 修复后
"created_at": datetime.now().isoformat()
```

需要在文件头部添加 `from datetime import datetime`。

#### 1b. 收紧 CORS 默认值

**文件**: `src/core/config.py`
**问题**: CORS 默认允许所有来源 `"*"`，安全工具自身配置不应如此。

```python
# 修复前
os.getenv("CORS_ALLOW_ORIGINS", "*")

# 修复后
os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:3000,http://localhost:8080")
# 生产环境请通过 CORS_ALLOW_ORIGINS 环境变量配置具体域名
```

#### 1c. 声明 `openai` 可选依赖

**文件**: `requirements.txt`
**问题**: `ai_analyzer.py` 运行时 import openai，但 requirements.txt 未声明。

```
# 可选：AI 修复建议（需要 OpenAI 兼容 API）
# openai>=1.0.0
```

注：`pyproject.toml` 的 `[project.optional-dependencies]` 中已有 `ai` 组声明，此处同步补充说明。

#### 1d. 修复 VSCode Webview XSS 风险

**文件**: `aegis-vscode/src/reportWebview.ts`
**问题**: `enableScripts: true` 加载未消毒 HTML，存在 XSS 风险。

修复方案：注入 CSP（Content Security Policy）meta 标签：

```typescript
// 在 HTML <head> 中注入 CSP
const csp = `<meta http-equiv="Content-Security-Policy"
  content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline';
  img-src ${webview.cspSource} data:; script-src 'none';">`;
```

#### Phase 1 验证

```bash
cd aegis-ai-core && python -m pytest tests/ -v
cd aegis-ai-core && ruff check src/ && ruff format --check src/
cd aegis-vscode && npm run compile
```

---

### Phase 2: 模块卫生清理

**对应问题**: #6, #7
**影响文件**: 2 个
**风险等级**: 低

#### 2a. 隔离 `rag_system.py` 脚本代码

**文件**: `src/rag/rag_system.py`
**问题**: 文件包含 `print()`、硬编码路径、emoji 输出，import 即执行。

修复方案：将所有执行逻辑包裹在 `if __name__ == "__main__":` 保护中。

```python
# 修复前：模块级代码直接执行
print("🔍 RAG System Demo")
collection = client.get_collection(...)

# 修复后：加入 main guard
def main():
    print("RAG System Demo")
    collection = client.get_collection(...)

if __name__ == "__main__":
    main()
```

#### 2b. 清理 `aegis_server.py` 模块级副作用

**文件**: `src/server/aegis_server.py`
**问题**:
1. 模块级别直接连接 ChromaDB，import 即触发网络 I/O
2. `MAX_CODE_LENGTH = 10000` 在同函数内重复定义两次
3. 启动 banner 日志在模块级执行

修复方案：

```python
# 1. ChromaDB 延迟初始化
_collection = None

def _get_collection():
    global _collection
    if _collection is None:
        client = chromadb.PersistentClient(path=str(CHROMA_PATH))
        _collection = client.get_or_create_collection("cve_collection")
    return _collection

# 2. 删除 audit_code() 中第二处重复的 MAX_CODE_LENGTH 定义

# 3. 启动日志移入 FastAPI startup 事件
@app.on_event("startup")
async def startup_banner():
    logger.info("Aegis AI Server starting...")
```

#### Phase 2 验证

```bash
cd aegis-ai-core && python -c "from src.rag import rag_system"  # 不应执行脚本
cd aegis-ai-core && python -c "import src.server.aegis_server"  # 不应连接 ChromaDB
cd aegis-ai-core && python -m pytest tests/ -v
```

---

### Phase 3: 废弃模块导入迁移

**对应问题**: #3
**影响文件**: ~20 个
**风险等级**: 中

> 必须在 Phase 4（异常处理收紧）之前完成，因为两者涉及相同文件。

#### 3a. 在 `rule_engine.py` 中添加 re-export

**文件**: `src/analysis/rule_engine.py`

```python
# 向后兼容的 re-export
from .ast_analyzer import analyze_code_ast  # noqa: F401
from .security_rules import (  # noqa: F401
    VULN_SIGNATURES,
    VULN_SEVERITY,
    scan_code_locally,
)
```

#### 3b. 迁移源文件导入路径（7 个文件）

| 文件 | 修改内容 |
|------|----------|
| `src/analysis/multi_language_ast.py` | `ast_analyzer` → `rule_engine`，`security_rules` → `rule_engine` |
| `src/analysis/rule_based_audit.py` | 两个废弃导入均改为从 `rule_engine` 导入 |
| `src/scanner/project_scanner.py` | 同上 |
| `src/scanner/performance_optimizer.py` | 同上（lazy import 保持 lazy） |
| `src/scanner/rule_config.py` | `VULN_SIGNATURES` 改从 `rule_engine` 导入 |

#### 3c. 迁移测试文件导入路径（6 个文件）

| 文件 | 修改内容 |
|------|----------|
| `tests/test_core_features.py` | 废弃导入 → `rule_engine` |
| `tests/test_audit_api.py` | 同上 |
| `tests/test_ast_rules.py` | 同上 |
| `tests/test_multi_language.py` | 同上 |
| `tests/test_php_sqli_benchmark.py` | 同上 |

#### 3d. 为废弃模块添加运行时警告

**文件**: `src/analysis/ast_analyzer.py`, `src/analysis/security_rules.py`

```python
import warnings
warnings.warn(
    "此模块已废弃，请从 src.analysis.rule_engine 导入",
    DeprecationWarning,
    stacklevel=2,
)
```

> 注意：不删除这两个模块，`rule_engine.py` 的 re-export 依赖它们。

#### Phase 3 验证

```bash
cd aegis-ai-core && python -m pytest tests/ -v
cd aegis-ai-core && ruff check src/ tests/
# 确认已无直接导入（仅 rule_engine.py 和废弃模块自身除外）
grep -r "from src.analysis.ast_analyzer\|from src.analysis.security_rules" src/ tests/
```

---

### Phase 4: 异常处理收紧

**对应问题**: #1
**影响文件**: 36 个源文件 + 9 个测试文件
**风险等级**: 中

这是改动量最大的阶段，按模块分 6 个子批次执行。

#### 异常替换策略

| 场景分类 | 当前写法 | 替换为 |
|----------|---------|--------|
| Tree-sitter 初始化 | `except Exception` | `except (ImportError, RuntimeError, OSError)` |
| 文件 I/O | `except Exception` | `except (OSError, json.JSONDecodeError, UnicodeDecodeError)` |
| 网络/API 调用 | `except Exception` | `except (ConnectionError, TimeoutError, httpx.HTTPError)` |
| ChromaDB 操作 | `except Exception` | `except (chromadb.errors.ChromaError, ValueError)` |
| AST 遍历/分析 | `except Exception` | `except (RuntimeError, AttributeError, ValueError, KeyError)` |
| Pydantic 校验 | `except Exception` | `except pydantic.ValidationError` |
| LSP 协议操作 | `except Exception` | `except (RuntimeError, KeyError)` |
| ML 模型加载 | `except Exception` | `except (ImportError, OSError, RuntimeError)` |

> 对于线程安全/顶层防护的 catch-all 场景，保留 `except Exception` 但添加注释 `# Intentional: top-level defensive catch`

#### 4a. LSP Server — 23 处

**文件**: `src/lsp/server.py`（单文件修改量最大）

关键修改示例：

```python
# L49: AI 模块导入
except (ImportError, ModuleNotFoundError):

# L452: 读取文件头部检测框架
except OSError:

# L585: 扫描文档主入口 — 保留 Exception（重新抛出为 ScanError）
except Exception as e:  # Intentional: re-raises as ScanError

# L969/977/1068/1087: LSP 通知发送
except RuntimeError:
```

#### 4b. 语言分析器 — 12 处

**文件**: `src/analysis/analyzers/` 下 5 个分析器

统一模式：
- 解析器初始化: `except (ImportError, RuntimeError, OSError)`
- AST 遍历: `except (RuntimeError, AttributeError, ValueError, KeyError)`

#### 4c. Scanner 模块 — 22 处

**文件**: `src/scanner/` 下 9 个文件

| 文件 | 修改数 | 主要异常类型 |
|------|--------|-------------|
| `taint_enhancer.py` | 5 | `RuntimeError, AttributeError, ValueError, KeyError` |
| `performance_optimizer.py` | 5 | `OSError, json.JSONDecodeError` + `RuntimeError` |
| `rag_enhancer.py` | 4 | `ImportError, RuntimeError, KeyError` |
| `ai_analyzer.py` | 2 | `openai.APIError, KeyError, ValueError` |
| `project_scanner.py` | 2 | `OSError, UnicodeDecodeError, RuntimeError` |
| `cli.py` | 2 | `OSError, ValueError` |
| 其他 3 个文件 | 各 1 | 按场景分类 |

#### 4d. 分析核心模块 — 18 处

**文件**: `src/analysis/` 下 10 个文件

重点文件：
- `multi_language_ast.py`: 7 处
- `taint/taint_analyzer.py`: 5 处
- `taint/cross_file_analyzer.py`: 3 处

#### 4e. Server/Worker/Crawler/RAG — 15 处

**文件**: 11 个文件

重点：
- `server/aegis_server.py`: 5 处 → `httpx.HTTPError` / `chromadb.errors.ChromaError`
- `rag/local_embedding.py`: 5 处 → `ImportError, OSError, RuntimeError`
- Crawler 文件: 8 处 → `requests.RequestException, KeyError, ValueError`

#### 4f. 测试文件 — 14 处

**文件**: 9 个测试文件

大多为导入测试保护，收紧为 `ImportError` 或 `(ImportError, RuntimeError)`。

#### Phase 4 后续

修改 `pyproject.toml` 的 ruff 配置，防止回退：

```toml
[tool.ruff.lint]
select = [..., "BLE001"]  # 新增：禁止宽泛异常捕获
# 从 ignore 中移除 "E722"
```

#### Phase 4 验证（每个子批次后执行）

```bash
cd aegis-ai-core && python -m pytest tests/ -v
cd aegis-ai-core && ruff check src/ tests/
cd aegis-ai-core && mypy src/lsp/ src/analysis/rule_engine.py src/analysis/base/ \
  src/scanner/project_scanner.py --config-file pyproject.toml --follow-imports=skip
```

---

### Phase 5: 测试风格统一

**对应问题**: #9
**影响文件**: ~10 个测试文件
**风险等级**: 低

#### 5a. 纯脚本式测试 → pytest（3 个文件）

| 文件 | 改动 |
|------|------|
| `tests/test_nosql_rule.py` | 提取逻辑为 `def test_*()` + `assert` |
| `tests/test_nosql_nodegoat.py` | 同上 |
| `tests/test_vuln_express_rule.py` | 同上 |

修改模式：

```python
# 修改前
def main():
    result = scan_code_locally(code, "javascript")
    if result:
        print("PASS")
    else:
        print("FAIL")
        sys.exit(1)

if __name__ == "__main__":
    main()

# 修改后
def test_nosql_injection_detection():
    result = scan_code_locally(code, "javascript")
    assert len(result) > 0, "应检测到 NoSQL 注入漏洞"
```

#### 5b. 混合风格测试清理（7 个文件）

| 文件 | 改动 |
|------|------|
| `tests/test_core_features.py` | 移除 `sys.path.insert()` 和 `main()` |
| `tests/test_cross_file_analysis.py` | 同上 |
| `tests/test_multi_language.py` | 同上 |
| `tests/test_nosql_dataflow.py` | 同上 |
| `tests/test_taint_analysis.py` | 同上 |
| `tests/test_api_direct.py` | 同上 |
| `tests/new_engine/test_python_analyzer_demo.py` | 同上 |

统一移除模式：
- 删除 `sys.path.insert(0, ...)`
- 删除 `def main():` 和 `if __name__ == "__main__":`
- 所有判断改为 `assert` 语句

#### Phase 5 验证

```bash
cd aegis-ai-core && python -m pytest tests/ --collect-only  # 确认新测试被收集
cd aegis-ai-core && python -m pytest tests/ -v
```

---

### Phase 6: README 与文档更新

**对应问题**: #10
**影响文件**: 2-3 个
**风险等级**: 极低

#### 6a. 更新 `README.md`

| 修改项 | 内容 |
|--------|------|
| 版本号 | `v0.2.0` → `v1.2.0` |
| 语言支持 | 新增 Java、Go 到"核心特性"和技术栈表 |
| 功能列表 | 补充 v1.1.0/v1.2.0 新增功能：基线管理、增量扫描、自定义规则、NoSQL 注入增强 |
| 项目结构 | 新增 `src/analysis/cfg/`、`src/analysis/dsl/`、`src/analysis/analyzers/`、`src/rag/`、`scripts/` |
| demo.gif | 移除不存在的 `docs/assets/demo.gif` 引用 |
| 最后更新日期 | 更新为当前日期 |
| 代码质量说明 | 新增"代码质量"章节，说明本轮优化工作 |

#### 6b. 更新 CHANGELOG.md

在 `[1.2.0]` 下添加：

```markdown
### Changed
- 收紧 120+ 处宽泛异常捕获为具体异常类型
- 修复 false_positive_manager 时间戳 bug
- 迁移废弃模块导入路径至 rule_engine
- 清理模块级副作用（aegis_server.py, rag_system.py）
- 统一测试风格为标准 pytest
- 加固 CORS 默认配置和 VSCode Webview CSP
```

#### Phase 6 验证

```bash
# 最终全链路 CI 模拟
cd aegis-ai-core && ruff check src/ tests/
cd aegis-ai-core && ruff format --check src/ tests/
cd aegis-ai-core && mypy src/lsp/ src/analysis/rule_engine.py src/analysis/base/ \
  src/scanner/project_scanner.py --config-file pyproject.toml --follow-imports=skip
cd aegis-ai-core && python -m pytest tests/ -v
```

---

## 三、总览

| 阶段 | 对应问题 | 文件数 | 风险 | 提交策略 |
|------|---------|--------|------|---------|
| Phase 1 | #2, #4, #5, #8 | 4-5 | 极低 | 每个子项 1 commit（4 commits） |
| Phase 2 | #6, #7 | 2 | 低 | 2 commits |
| Phase 3 | #3 | ~20 | 中 | 3 commits（re-export / src迁移 / test迁移） |
| Phase 4 | #1 | 45 | 中 | 每子批次 1 commit（6 commits） |
| Phase 5 | #9 | ~10 | 低 | 2 commits |
| Phase 6 | #10 | 2-3 | 极低 | 1 commit |

**预计总提交数**: ~18 commits
**总涉及文件**: ~70 个（部分文件跨阶段修改）

---

## 四、风险控制

1. **Phase 3 必须先于 Phase 4**：导入迁移完成后再收紧异常，避免同文件多次冲突
2. **Phase 4 分批提交**：每个子批次独立 CI 验证，不一次性修改 36 个文件
3. **ruff 配置变更**：Phase 4 全部完成后才启用 `BLE001` lint 规则，防止过程中 CI 红
4. **VSCode 扩展**：Phase 1d 修改后需 `npm run compile` 验证编译，建议手动打开报告 Webview 测试

---

## 五、关键文件清单

以下文件在多个阶段被修改，需特别关注：

| 文件 | 涉及阶段 | 说明 |
|------|---------|------|
| `src/lsp/server.py` | Phase 4a | 23 处异常修改，改动量最大 |
| `src/analysis/rule_engine.py` | Phase 3, 4d | re-export 入口 + 异常修改 |
| `src/server/aegis_server.py` | Phase 2, 4e | 副作用清理 + 异常修改 |
| `src/analysis/multi_language_ast.py` | Phase 3, 4d | 导入迁移 + 7 处异常 |
| `src/scanner/project_scanner.py` | Phase 3, 4c | 导入迁移 + 异常修改 |
| `pyproject.toml` | Phase 4 后 | ruff 规则更新 |
| `README.md` | Phase 6 | 最终文档更新 |
