"""
test_ai_fix_quality.py - AI 精准修复质量端到端验证

在真实漏洞文件（NodeGoat user-dao.js 中的 NoSQL 注入）上测试：
1. _extract_rich_context() 能否正确提取 import、函数签名、框架推断、近域变量
2. _build_analysis_prompt() 生成的 prompt 是否包含框架感知信息
3. AI 返回的 fixed_code 是否复用原变量名、使用正确框架 API
"""
from __future__ import annotations

import os
import sys
import json
from pathlib import Path

# 设置 PYTHONPATH，使 src 包可导入
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.scanner.ai_analyzer import _extract_rich_context, AIAnalyzer

# ── 配置 ────────────────────────────────────────────────────────────────────
VULN_FILE = r"C:\AegisTestTargets\NodeGoat\app\data\user-dao.js"
VULN_LINE = 91  # usersCol.findOne({ userName: userName }, validateUserDoc)

# ── Step 1: 验证 rich context 提取 ──────────────────────────────────────────
print("=" * 60)
print("Step 1: _extract_rich_context() 验证")
print("=" * 60)

ctx = _extract_rich_context(
    file_path=VULN_FILE,
    vuln_line=VULN_LINE,
    padding=10,
)

print(f"\n[框架推断] framework_hints: {ctx['framework_hints']}")
print(f"[函数签名] function_signature: {ctx['function_signature']!r}")
print(f"[Import 数量] {len(ctx['imports'])} 条")
for imp in ctx["imports"]:
    print(f"  - {imp}")
print(f"\n[近域变量] local_vars: {ctx['local_vars']}")
print(f"\n[漏洞片段] actual_start_line={ctx['actual_start_line']}")
print(ctx["vuln_snippet"])

# ── 验证断言 ─────────────────────────────────────────────────────────────────
print("\n--- 验证结果 ---")
checks = {
    "framework_hints 不为空": bool(ctx["framework_hints"]),
    "function_signature 包含有效函数名（不是控制流关键字）": bool(ctx.get("function_signature"))
        and not ctx["function_signature"].startswith(("if ", "else", "for ", "while ")),
    "imports 包含 bcrypt": any("bcrypt" in imp for imp in ctx["imports"]),
    "local_vars 包含 userName 或 usersCol": any(
        v in ctx["local_vars"] for v in ["userName", "usersCol", "password"]
    ),
    "vuln_snippet 包含 findOne": "findOne" in ctx["vuln_snippet"],
}

all_pass = True
for check, result in checks.items():
    status = "✓ PASS" if result else "✗ FAIL"
    if not result:
        all_pass = False
    print(f"  {status}: {check}")

if not all_pass:
    print("\n[警告] 部分断言失败，rich context 提取有缺失")

# ── Step 2: 验证 prompt 生成 ──────────────────────────────────────────────────
print("\n" + "=" * 60)
print("Step 2: _build_analysis_prompt() 内容验证")
print("=" * 60)

analyzer = AIAnalyzer()
finding = {
    "type": "NOSQL_INJECTION",
    "severity": "High",
    "file": VULN_FILE,
    "line": VULN_LINE,
    "start_line": VULN_LINE,
    "end_line": VULN_LINE,
    "details": "检测到 MongoDB findOne 查询直接使用外部参数 userName，存在 NoSQL 注入风险",
    "language": "javascript",
}

prompt = analyzer._build_analysis_prompt(
    finding,
    rich_ctx=ctx,
    language="javascript",
)

print("\n[生成的 prompt（前 1500 字符）]")
print(prompt[:1500])

# 验证 prompt 质量
print("\n--- Prompt 质量验证 ---")
prompt_checks = {
    "包含框架信息 (mongoose/mongodb/bcrypt)": any(
        kw in prompt.lower() for kw in ["mongoose", "mongodb", "bcrypt", "框架"]
    ),
    "包含函数签名": "validateLogin" in prompt or "function" in prompt.lower(),
    "包含 import 列表": "bcrypt" in prompt or "require" in prompt,
    "包含 local_vars 提示": "变量" in prompt or "local" in prompt.lower(),
    "包含 fixed_code 要求": "fixed_code" in prompt,
    "包含框架感知修复指引": "findOne" in prompt or "类型" in prompt or "mongoose" in prompt.lower(),
}

all_pass2 = True
for check, result in prompt_checks.items():
    status = "✓ PASS" if result else "✗ FAIL"
    if not result:
        all_pass2 = False
    print(f"  {status}: {check}")

# ── Step 3: 调用 AI 获取精准修复 ──────────────────────────────────────────────
print("\n" + "=" * 60)
print("Step 3: AI 精准修复调用（真实 API）")
print("=" * 60)

if not analyzer.enabled:
    print("[跳过] AI 未启用（缺少 API key）")
else:
    print("[调用中] 请稍候…")
    source_code = Path(VULN_FILE).read_text(encoding="utf-8")
    result = analyzer.analyze_finding(
        finding,
        language="javascript",
        source_code=source_code,
    )

    print(f"\n[AI 结果]")
    print(f"  is_true_positive : {result.is_true_positive}")
    print(f"  confidence       : {result.confidence:.2f}")
    print(f"  risk_level       : {result.risk_level}")
    print(f"  requires_review  : {result.requires_review}")
    print(f"  fix_suggestion   : {result.fix_suggestion}")
    print(f"\n[fixed_code]")
    if result.fixed_code:
        print(result.fixed_code)
    else:
        print("  (无修复代码)")

    # 验证修复代码质量
    print("\n--- 修复代码质量验证 ---")
    fc = result.fixed_code or ""
    fix_checks = {
        "fixed_code 非空": bool(fc.strip()),
        "复用原变量名 userName": "userName" in fc,
        "包含 NoSQL 注入防御（类型检查 或 $eq 操作符 或 sanitize）": any(
            kw in fc for kw in ["typeof", "String(", "instanceof", "trim()", "$eq", "sanitize", "validate"]
        ),
        "保留 findOne 调用结构": "findOne" in fc,
        "置信度 >= 0.75（满足 replaceRange 条件）": result.confidence >= 0.75,
    }

    all_pass3 = True
    for check, r in fix_checks.items():
        status = "✓ PASS" if r else "✗ FAIL"
        if not r:
            all_pass3 = False
        print(f"  {status}: {check}")

    # 最终总结
    print("\n" + "=" * 60)
    print("端到端验证总结")
    print("=" * 60)
    results = [
        ("rich context 提取", all_pass),
        ("prompt 质量", all_pass2),
        ("AI 修复代码质量", all_pass3),
    ]
    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {status}: {name}")
