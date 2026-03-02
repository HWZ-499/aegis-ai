"""
debug_runner.py - 端到端调试触发脚本

直接调用 scan_document + _extract_rich_context + _build_analysis_prompt 的完整链路，
收集调试日志用于假设验证。不需要启动 LSP Server 进程。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

print("[debug_runner] 开始端到端调试...")

# ── 1. 测试 scan_document（H-C 假设）
print("\n[Step 1] 测试 scan_document (JS/Python/PHP)...")
from src.lsp.server import scan_document

TEST_FILES = [
    # (source, file_path) — 涵盖三种语言
    (
        "const mysql = require('mysql2');\nconst id = req.body.id;\ndb.query('SELECT * FROM users WHERE id = ' + id);",
        "test_sql_inject.js"
    ),
    (
        "import os\ndef handler(request):\n    cmd = request.GET['cmd']\n    os.system(cmd)",
        "test_rce.py"
    ),
    (
        "<?php\n$id = $_GET['id'];\n$db->query('SELECT * FROM users WHERE id = ' . $id);",
        "test_sqli.php"
    ),
]

for source, fpath in TEST_FILES:
    print(f"  扫描 {fpath}...")
    try:
        findings = scan_document(source, fpath)
        print(f"    -> {len(findings)} 个发现")
        for f in findings[:2]:
            print(f"       type={f.get('type')} line={f.get('line')} severity={f.get('severity')}")
    except Exception as e:
        print(f"    -> 异常: {type(e).__name__}: {e}")

# ── 2. 测试 _extract_rich_context（H-A/H-B 假设）
print("\n[Step 2] 测试 _extract_rich_context...")
from src.scanner.ai_analyzer import _extract_rich_context

NODEGOAT_DAO = r"C:\AegisTestTargets\NodeGoat\app\data\user-dao.js"
if Path(NODEGOAT_DAO).exists():
    ctx = _extract_rich_context(NODEGOAT_DAO, vuln_line=91)
    print(f"  NodeGoat user-dao.js L91:")
    print(f"    framework_hints={ctx['framework_hints']}")
    print(f"    function_signature={ctx['function_signature']!r}")
    print(f"    imports_count={len(ctx['imports'])}")
    print(f"    local_vars_count={len(ctx['local_vars'])}")
else:
    print(f"  NodeGoat 文件不存在，使用内联 source_code 测试...")
    src_inline = """const bcrypt = require("bcrypt-nodejs");
function UserDAO(db) {
    const usersCol = db.collection("users");
    this.validateLogin = (userName, password, callback) => {
        const comparePassword = (fromDB, fromUser) => fromDB === fromUser;
        const validateUserDoc = (err, user) => {
            if (err) return callback(err, null);
            if (user) {
                if (comparePassword(password, user.password)) callback(null, user);
                else { const e = new Error("Invalid password"); callback(e, null); }
            }
        };
        usersCol.findOne({ userName: userName }, validateUserDoc);
    };
}"""
    ctx = _extract_rich_context("test_user_dao.js", vuln_line=12, source_code=src_inline)
    print(f"  inline source test:")
    print(f"    framework_hints={ctx['framework_hints']}")
    print(f"    function_signature={ctx['function_signature']!r}")
    print(f"    imports={ctx['imports']}")

# ── 3. 测试 AIAnalyzer._build_analysis_prompt（H-D/H-E 假设）
print("\n[Step 3] 测试 _build_analysis_prompt (rich_ctx=None 降级)...")
from src.scanner.ai_analyzer import AIAnalyzer

analyzer = AIAnalyzer(enabled=False)  # 不真实调用 AI，只测试 prompt 构建

test_finding = {
    "type": "NOSQL_INJECTION",
    "severity": "High",
    "file": "test.js",
    "line": 10,
    "start_line": 10,
    "end_line": 10,
    "details": "NoSQL injection detected",
    "language": "javascript",
}

# 测试 rich_ctx=None 的降级路径
try:
    prompt_none = analyzer._build_analysis_prompt(test_finding, rich_ctx=None, language="javascript")
    print(f"  rich_ctx=None -> prompt length={len(prompt_none)}, OK")
except Exception as e:
    print(f"  rich_ctx=None -> 异常: {type(e).__name__}: {e}")

# 测试正常路径
test_ctx = {
    "vuln_snippet": "usersCol.findOne({ userName: userName }, cb);",
    "function_signature": "this.validateLogin = (userName, password, callback) => {",
    "imports": ['const bcrypt = require("bcrypt-nodejs");'],
    "local_vars": ["userName", "password", "callback"],
    "framework_hints": ["mongodb"],
    "actual_start_line": 10,
}
try:
    prompt_ok = analyzer._build_analysis_prompt(test_finding, rich_ctx=test_ctx, language="javascript")
    print(f"  rich_ctx=OK -> prompt length={len(prompt_ok)}, contains 'mongodb'={'mongodb' in prompt_ok.lower()}")
except Exception as e:
    print(f"  rich_ctx=OK -> 异常: {type(e).__name__}: {e}")


# ── 4. 测试 AIAnalyzer 环境变量读取（H-F 假设）
print("\n[Step 4] 测试 AIAnalyzer 环境变量读取 (H-F)...")
import os, json as _j, time as _t
api_key_env = os.getenv("DEEPSEEK_API_KEY") or os.getenv("OPENAI_API_KEY")
print(f"  os.getenv('DEEPSEEK_API_KEY') = {'SET (***' + api_key_env[-6:] + ')' if api_key_env else 'NOT SET'}")

# 实例化不带参数（模拟 LSP server 中的 AIAnalyzer()）
analyzer_real = AIAnalyzer()
print(f"  AIAnalyzer() enabled={analyzer_real.enabled}")
print(f"  AIAnalyzer() api_key={'SET' if analyzer_real.api_key else 'NONE'}")

# 记录到 debug log
_hf = {"sessionId":"02e970","hypothesisId":"H-F","location":"debug_runner.py:step4","message":"AIAnalyzer env check","data":{"env_key_set":bool(api_key_env),"analyzer_enabled":analyzer_real.enabled,"analyzer_has_key":bool(analyzer_real.api_key)},"timestamp":int(_t.time()*1000)}
try:
    with open("debug-02e970.log","a",encoding="utf-8") as _f: _f.write(_j.dumps(_hf)+"\n")
except Exception: pass

# ── 5. 测试 analyze_finding 完整路径 incl. AI 调用（H-D + H-G）
if analyzer_real.enabled:
    print("\n[Step 5] 测试 analyze_finding 完整路径 (H-D/H-G)...")
    test_f = {
        "type": "NOSQL_INJECTION", "severity": "High",
        "file": r"C:\AegisTestTargets\NodeGoat\app\data\user-dao.js",
        "line": 91, "start_line": 91, "end_line": 91,
        "details": "NoSQL injection via userName", "language": "javascript",
    }
    src_code = Path(r"C:\AegisTestTargets\NodeGoat\app\data\user-dao.js").read_text(encoding="utf-8") if Path(r"C:\AegisTestTargets\NodeGoat\app\data\user-dao.js").exists() else None
    try:
        result = analyzer_real.analyze_finding(test_f, language="javascript", source_code=src_code)
        print(f"  result.confidence={result.confidence}, enabled={result.is_true_positive}")
        print(f"  fixed_code={'YES (' + str(len(result.fixed_code)) + ' chars)' if result.fixed_code else 'NONE'}")
        _hg = {"sessionId":"02e970","hypothesisId":"H-G","location":"debug_runner.py:step5","message":"analyze_finding result","data":{"confidence":result.confidence,"has_fixed_code":bool(result.fixed_code),"requires_review":result.requires_review},"timestamp":int(_t.time()*1000)}
        try:
            with open("debug-02e970.log","a",encoding="utf-8") as _f: _f.write(_j.dumps(_hg)+"\n")
        except Exception: pass
    except Exception as e:
        print(f"  analyze_finding 异常: {type(e).__name__}: {e}")
        _hg_err = {"sessionId":"02e970","hypothesisId":"H-G","location":"debug_runner.py:step5_error","message":"analyze_finding exception","data":{"error":str(e),"type":type(e).__name__},"timestamp":int(_t.time()*1000)}
        try:
            with open("debug-02e970.log","a",encoding="utf-8") as _f: _f.write(_j.dumps(_hg_err)+"\n")
        except Exception: pass
else:
    print("\n[Step 5] 跳过（AI 未启用）")

print("\n[debug_runner] 完成，检查 debug-02e970.log 查看详细日志。")
