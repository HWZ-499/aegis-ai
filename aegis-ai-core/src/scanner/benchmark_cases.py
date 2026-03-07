"""
benchmark_cases.py - 阶段四：标准基准测试用例定义

与 test_acceptance_benchmark 中的 TP_CASES / TN_CASES 对齐，
供 benchmark.run_benchmark 与 pytest 共用。
"""

from dataclasses import dataclass


@dataclass
class BenchCase:
    """单个基准测试用例。"""

    id: str
    category: str
    pattern: str
    description: str
    code: str
    expect_finding: bool  # True = 应报 (TP)，False = 不应报 (TN)


# ── True Positive：应检出 ──

BENCH_CASES_TP: list[BenchCase] = [
    # NoSQL Injection
    BenchCase(
        "TP-NOSQL-01",
        "NOSQL_INJECTION",
        "direct_source",
        "直接 req.body 传入 findOne",
        "db.users.findOne(req.body);",
        True,
    ),
    BenchCase(
        "TP-NOSQL-02",
        "NOSQL_INJECTION",
        "variable_propagation",
        "变量间接传播",
        "const data = req.body;\ndb.users.findOne(data);",
        True,
    ),
    BenchCase(
        "TP-NOSQL-03",
        "NOSQL_INJECTION",
        "destructuring",
        "解构赋值传播",
        "const { userId } = req.body;\ndb.users.findOne(userId);",
        True,
    ),
    BenchCase(
        "TP-NOSQL-04",
        "NOSQL_INJECTION",
        "object_literal",
        "对象字面量含 req.body",
        "db.users.findOne({ user: req.body.user });",
        True,
    ),
    BenchCase(
        "TP-NOSQL-05",
        "NOSQL_INJECTION",
        "dangerous_operator",
        "$where + 用户输入",
        "db.users.findOne({ $where: req.body.code });",
        True,
    ),
    BenchCase(
        "TP-NOSQL-06",
        "NOSQL_INJECTION",
        "dao_pattern",
        "DAO 模式更新",
        "allocationsDAO.update(userId, stocks, funds, bonds);",
        True,
    ),
    # SQL Injection
    BenchCase(
        "TP-SQL-01",
        "SQL_INJECTION",
        "string_concat",
        "字符串拼接 SQL",
        'const q = "SELECT * FROM users WHERE name = " + req.body.name;',
        True,
    ),
    BenchCase(
        "TP-SQL-02",
        "SQL_INJECTION",
        "template_literal",
        "模板字符串 SQL",
        "const q = `SELECT * FROM users WHERE id = ${userId}`;",
        True,
    ),
    # XSS
    BenchCase("TP-XSS-01", "XSS_RISK", "innerHTML", "innerHTML 赋值", "element.innerHTML = userInput;", True),
    BenchCase(
        "TP-XSS-02",
        "XSS_RISK",
        "dangerouslySetInnerHTML",
        "React dangerouslySetInnerHTML",
        "const comp = { dangerouslySetInnerHTML: { __html: data } };",
        True,
    ),
    # RCE
    BenchCase("TP-RCE-01", "RCE_COMMAND_EXEC", "eval", "eval 调用", "eval(userInput);", True),
    BenchCase("TP-RCE-02", "RCE_COMMAND_EXEC", "child_process", "child_process.exec", "child_process.exec(cmd);", True),
    # Hardcoded Credentials
    BenchCase(
        "TP-CRED-01", "HARDCODED_CREDENTIALS", "literal", "硬编码密码", 'const password = "SuperSecret123!";', True
    ),
    # Path Traversal
    BenchCase(
        "TP-PATH-01",
        "PATH_TRAVERSAL",
        "fs_read",
        "fs.readFile 用户输入路径",
        "fs.readFile(req.query.path, callback);",
        True,
    ),
]

# ── True Negative：不应检出 ──

BENCH_CASES_TN: list[BenchCase] = [
    BenchCase(
        "TN-NOSQL-01",
        "NOSQL_INJECTION",
        "array_find",
        "Array.find 非 MongoDB",
        "const item = [1, 2, 3].find(x => x > 1);",
        False,
    ),
    BenchCase(
        "TN-NOSQL-02",
        "NOSQL_INJECTION",
        "variable_name",
        "变量名含 body 非用户输入",
        'const bodyParser = require("body-parser");',
        False,
    ),
    BenchCase("TN-XSS-01", "XSS_RISK", "textContent", "textContent 安全", "element.textContent = userInput;", False),
    BenchCase(
        "TN-RCE-01",
        "RCE_COMMAND_EXEC",
        "regex_exec",
        "正则 exec 非 child_process",
        "const match = /pattern/.exec(str);",
        False,
    ),
    BenchCase(
        "TN-CRED-01",
        "HARDCODED_CREDENTIALS",
        "env_var",
        "process.env 安全",
        "const password = process.env.DB_PASSWORD;",
        False,
    ),
    BenchCase(
        "TN-CRED-02",
        "HARDCODED_CREDENTIALS",
        "error_var",
        "passwordError 变量名",
        'const passwordError = "Password must be 8 characters";',
        False,
    ),
    BenchCase(
        "TN-NOSQL-03",
        "NOSQL_INJECTION",
        "sanitized",
        "parseInt 净化后不报",
        "const rawId = req.body.id;\nconst id = parseInt(rawId);\ndb.users.findOne(id);",
        False,
    ),
    BenchCase(
        "TN-SQL-01", "SQL_INJECTION", "no_sql_keyword", "无 SQL 关键字拼接", 'const msg = "Hello " + name;', False
    ),
    BenchCase(
        "TN-SQL-02",
        "SQL_INJECTION",
        "parameterized",
        "参数化查询",
        'db.query("SELECT * FROM users WHERE id = ?", [userId]);',
        False,
    ),
    BenchCase(
        "TN-PATH-01",
        "PATH_TRAVERSAL",
        "static_path",
        "静态路径 fs.readFile",
        'fs.readFile("./config.json", callback);',
        False,
    ),
]
