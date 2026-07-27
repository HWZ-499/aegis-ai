# Aegis AI SAST 评估报告

**目标**: flask-2.3.2  
**日期**: 2026-07-12  

---

## 检测率 (Recall)

| 漏洞类型 | 应检出 | 已检出 | Recall |
|----------|--------|--------|--------|
| DESERIALIZATION | 0 | 0 | N/A |
| HARDCODED_CREDENTIALS | 0 | 0 | N/A |
| RCE_COMMAND_EXEC | 0 | 0 | N/A |
| **总计** | **0** | **0** | **0.0%** |

---

## 按语言质量矩阵

| 语言 | TP | TN | FP | FN | Recall | Precision | FPR | F1 |
|------|---:|---:|---:|---:|-------:|----------:|----:|---:|

### 语言 × 漏洞类型

| 语言 | 漏洞类型 | TP | TN | FP | FN | Recall | Precision |
|------|----------|---:|---:|---:|---:|-------:|----------:|

---

## 误报率 (FPR)

- 总发现数: 10
- 真阳性 (TP): 0
- 误报 (FP): 10
- 应阴性总数 (TN+FP): 11
- **误报率 (FPR)**: 90.9%

---

## 综合指标

- **Recall (检测率)**: 0.0%
- **Precision (精确率)**: 0.0%
- **F1 Score**: 0.00

---

## 明细 (TP/TN/FP/FN)

| # | 判定 | 漏洞类型 | 位置 | 规则 | 说明 |
|---:|------|----------|------|------|------|
| 1 | FP | RCE_COMMAND_EXEC | src\flask\cli.py:963 | RCE_COMMAND_EXEC_PY_AST | [工具脚本] 发现 compile()，参数含变量，处于框架工具脚本上下文，已降级。 |
| 2 | TN | RCE_COMMAND_EXEC | config.py:187 |  | 误报：框架设计上的合法 exec 用法，需要上下文感知（source tracking）才能区分。这正是污点分析 Source→Sink 追踪能力的改进方向。 |
| 3 | FP | HARDCODED_CREDENTIALS | examples\tutorial\flaskr\__init__.py:11 | dsl.python.hardcoded-password | 检测到疑似硬编码密码，请改为从安全配置或环境变量加载。 |
| 4 | FP | DESERIALIZATION | src\flask\cli.py:963 | DESERIALIZATION_PY_AST | eval() 执行用户输入内容，等同于任意代码执行。 |
| 5 | FP | RCE_COMMAND_EXEC | tests\conftest.py:183 | RCE_COMMAND_EXEC_PY_AST | 发现 subprocess.check_call() 调用，参数含变量，建议确认是否可控。 |
| 6 | FP | HARDCODED_CREDENTIALS | tests\conftest.py:51 | dsl.python.hardcoded-password | 检测到疑似硬编码密码，请改为从安全配置或环境变量加载。 |
| 7 | FP | HARDCODED_CREDENTIALS | tests\test_config.py:11 | dsl.python.hardcoded-password | 检测到疑似硬编码密码，请改为从安全配置或环境变量加载。 |
| 8 | FP | HARDCODED_CREDENTIALS | tests\test_config.py:121 | dsl.python.hardcoded-password | 检测到疑似硬编码密码，请改为从安全配置或环境变量加载。 |
| 9 | FP | HARDCODED_CREDENTIALS | tests\test_config.py:125 | dsl.python.hardcoded-password | 检测到疑似硬编码密码，请改为从安全配置或环境变量加载。 |
| 10 | FP | HARDCODED_CREDENTIALS | tests\test_config.py:138 | dsl.python.hardcoded-password | 检测到疑似硬编码密码，请改为从安全配置或环境变量加载。 |
| 11 | FP | HARDCODED_CREDENTIALS | tests\test_reqctx.py:243 | dsl.python.hardcoded-password | 检测到疑似硬编码密码，请改为从安全配置或环境变量加载。 |

---

## Evaluation scope

- Ground-truth entries supplied: 3
- Entries evaluated: 2
- Explicitly out of scope: 1
- Invalid at this target revision: 0

### Excluded entries
- `SESSION_COOKIE_DISCLOSURE` in `sessions.py`: CVE-2023-30861 concerns a missing Vary: Cookie header in versions before 2.3.1; Flask 2.3.2 is patched and Aegis does not advertise cache/session-disclosure coverage.

---

## Performance

- Scan duration: `1.194 s`
- RSS before scan: `44.879 MiB`
- RSS after scan: `59.227 MiB`
- RSS delta: `14.348 MiB`
- Process peak RSS: `69.578 MiB`

Peak RSS is the lifetime peak of this standalone evaluator process.

---

## Reproducibility

- Clean release baseline: `yes`
- Engine: `new`
- Scanner revision: `d51bd8b946492fe1799f431b45c1da070a35cbc1`
- Scanner dirty: `no`
- Scanner diff SHA-256: `unavailable`
- Target revision: `f3b8f570545200c87465d18386f3fc9f2258307a`
- Target subdirectory: `.`
- Target dirty: `no`
- Target diff SHA-256: `unavailable`
- Ground truth: `scripts/data/ground_truth_flask_2.3.2.json`
- Ground truth SHA-256: `81777835f755789f376afd2ff76d96ce38cbd4a8b28fb00acaab9502b2906e58`
- Python: `3.11.0`
- Platform: `Windows-10-10.0.26200-SP0`
- Processor: `Intel64 Family 6 Model 183 Stepping 1, GenuineIntel`
