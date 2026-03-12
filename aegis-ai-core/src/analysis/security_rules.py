# security_rules.py
"""
.. deprecated:: 1.2.0
    此模块为旧版正则规则引擎，已被 ``rule_engine.py`` + ``rules/`` 目录取代。
    新代码请使用 ``from src.analysis.rule_engine import get_default_rules_for_language``。
    计划在 v1.5 中移除。
"""

import logging
import re

logger = logging.getLogger(__name__)

# tree-sitter 懒加载（PHP AST 分析用）
try:
    from tree_sitter import Parser as _TsParser
    from tree_sitter_languages import get_language as _ts_get_language

    _TS_AVAILABLE = True
except ImportError:
    _TsParser = None
    _ts_get_language = None
    _TS_AVAILABLE = False

# 漏洞特征库 - 通用正则规则
# 格式：漏洞名: [正则表达式列表]
# 说明：正则规则为通用匹配，适用于所有语言但精度有限。
#       完整的 AST 级安全检测仅覆盖 JavaScript/TypeScript 和 Python。

# 漏洞严重程度定义
# 参考专业建议：eval/system/shell_exec 应为 Critical（致命）
VULN_SEVERITY = {
    "SQL_INJECTION": "High",
    "RCE_COMMAND_EXEC": "Critical",  # 提升为 Critical：eval/system/shell_exec 直接执行代码/命令，风险极高
    "XSS_RISK": "High",  # 注意：Reflected XSS 可考虑降为 Medium，但需要区分类型
    "PATH_TRAVERSAL": "High",
    "DESERIALIZATION": "High",
    "HARDCODED_CREDENTIALS": "High",
    "BUFFER_OVERFLOW": "Critical",
    "FORMAT_STRING": "High",
    "NOSQL_INJECTION": "High",
    "OPEN_REDIRECT": "Medium",  # CWE-601：任意 URL 跳转，与 XSS 危害模型不同
}

VULN_SIGNATURES = {
    # ===== SQL 注入 =====
    "SQL_INJECTION": [
        # Python - 排除参数化查询
        r"execute\s*\(\s*['\"].*%s.*['\"]\s*%\s*",  # execute("...%s..." % var) - 危险
        r"\.execute\s*\(\s*['\"].*\+.*['\"]\s*\)",  # cursor.execute("..." + var) - 危险
        # JavaScript/Node.js
        r"\.query\s*\(\s*['\"].*\+.*['\"]\s*\)",  # .query("..." + var) - 危险
        r"db\.query\s*\(\s*['\"].*\+.*['\"]\s*\)",  # db.query("..." + var) - 危险
        r"connection\.query\s*\(\s*['\"].*\+.*['\"]\s*\)",  # MySQL - 危险
        r"`SELECT.*\$\{.*\}.*`",  # 模板字符串注入 - 危险
        # 【P0优化2】Sequelize (ORM) - SQL注入
        r"\.find\s*\(\s*\{[^}]*where\s*:\s*\{[^}]*\w+\s*:\s*[^}]+\+",  # .find({ where: { email: var + ... } })
        r"\.findOne\s*\(\s*\{[^}]*where\s*:\s*\{[^}]*\w+\s*:\s*[^}]+\+",  # .findOne({ where: { email: var + ... } })
        r"\.findAll\s*\(\s*\{[^}]*where\s*:\s*\{[^}]*\w+\s*:\s*[^}]+\+",  # .findAll({ where: { email: var + ... } })
        r"Sequelize\.literal\s*\(\s*['\"].*\+",  # Sequelize.literal("..." + var)
        r"\.query\s*\(\s*['\"].*\+.*['\"]\s*\)",  # .query("..." + var)
        # 【P0优化2】Mongoose (ODM) - SQL注入（实际上是NoSQL注入，但归类为SQL_INJECTION）
        r"\.find\s*\(\s*\{[^}]*\w+\s*:\s*[^}]+\+",  # .find({ email: var + ... })
        r"\.findOne\s*\(\s*\{[^}]*\w+\s*:\s*[^}]+\+",  # .findOne({ email: var + ... })
        r"\.findById\s*\(\s*[^)]+\+",  # .findById(var + ...)
        r"\.where\s*\(\s*['\"].*\+",  # .where("..." + var)
        # Java - 排除 PreparedStatement 的参数化查询
        r"Statement\.execute\s*\(\s*['\"].*\+.*['\"]\s*\)",  # Statement.execute("..." + var) - 危险
        # 注意：不检测 prepare()，因为它是安全的参数化查询
        # Go
        r"\.Query\s*\(\s*['\"].*\+.*['\"]\s*\)",  # db.Query("..." + var) - 危险
        r"\.Exec\s*\(\s*['\"].*\+.*['\"]\s*\)",  # db.Exec("..." + var) - 危险
        # PHP - 排除 prepare() 和参数化查询
        r"mysql_query\s*\(\s*['\"].*\.\s*\$.*['\"]\s*\)",  # mysql_query("..." . $var) - 危险
        r"mysqli_query\s*\(\s*['\"].*\.\s*\$.*['\"]\s*\)",  # mysqli_query - 危险
        r"\$.*->query\s*\(\s*['\"].*\.\s*\$.*['\"]\s*\)",  # $db->query("..." . $var) - 危险
        # 兼容 DVWA 等常见 PHP SQLi 写法：直接在 WHERE 中插入 '$id'
        r"SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=\s*'\$[A-Za-z_]\w*'\s*;",  # ... WHERE user_id = '$id';
        r"SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=\s*\"\$[A-Za-z_]\w*\"\s*;",  # ... WHERE user_id = \"$id\";
        # 注意：不检测 prepare()，因为它是安全的参数化查询
        # 通用 SQL 拼接模式（排除参数化查询）
        r"SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=\s*['\"].*\+",  # WHERE ... = "..." + - 危险
        r"INSERT\s+INTO.*VALUES\s*\(.*\+",  # INSERT ... VALUES (...) + - 危险
        r"UPDATE\s+.*SET\s+.*=\s*['\"].*\+",  # UPDATE ... SET ... = "..." + - 危险
    ],
    # ===== 代码/命令执行 =====
    "RCE_COMMAND_EXEC": [
        # Python
        r"os\.system\s*\(",  # os.system()
        r"subprocess\.call\s*\(",  # subprocess.call()
        r"subprocess\.run\s*\(",  # subprocess.run()
        r"subprocess\.Popen\s*\(",  # subprocess.Popen()
        r"\beval\s*\(",  # eval() - 使用单词边界避免误匹配
        r"\bexec\s*\(",  # exec() - 使用单词边界避免误匹配
        r"\bcompile\s*\(",  # compile() - 使用单词边界
        # JavaScript/Node.js
        r"\beval\s*\(",  # eval() - 使用单词边界
        r"\bFunction\s*\(\s*['\"]",  # new Function()
        r"setTimeout\s*\(\s*['\"].*\+",  # setTimeout("..." + code)
        r"setInterval\s*\(\s*['\"].*\+",  # setInterval("..." + code)
        r"child_process\.exec\s*\(",  # Node.js exec（命令执行）
        r"child_process\.spawn\s*\(",  # Node.js spawn
        # 注意：不检测 RegExp.exec() - 这是正则表达式方法，不是命令执行
        # 不添加 r"\bexec\s*\(" 规则，因为会误匹配 RegExp.exec()
        # RegExp.exec() 会在检测时排除
        # Java
        r"Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(",  # Runtime.exec()
        r"ProcessBuilder\s*\(",  # ProcessBuilder
        r"ProcessBuilder\([^)]+\)\.start\s*\(",
        # C/C++
        r"system\s*\(",  # system()
        r"execve\s*\(",  # execve()
        r"execvp\s*\(",  # execvp()
        # Go
        r"exec\.Command\s*\(",  # exec.Command()
        r"os\.Exec\s*\(",  # os.Exec()
        # PHP
        r"\bexec\s*\(",  # exec() - 使用单词边界（注意：不匹配 RegExp.exec()）
        r"\bsystem\s*\(",  # system() - 使用单词边界
        r"shell_exec\s*\(",  # shell_exec()
        r"passthru\s*\(",  # passthru()
        r"\beval\s*\(",  # eval() - 使用单词边界
        # 注意：这些函数在字符串字面量或 HTML 文本中不应该被检测
        # 注意：JavaScript中的 RegExp.exec() 会在检测时排除
    ],
    # ===== 硬编码凭证 =====
    "HARDCODED_CREDENTIALS": [
        # Python
        r"password\s*=\s*['\"][a-zA-Z0-9@#$%]{3,}['\"]",  # password = "..."
        r"api_key\s*=\s*['\"][a-zA-Z0-9]{10,}['\"]",  # api_key = "..."
        r"secret\s*=\s*['\"][a-zA-Z0-9]{10,}['\"]",  # secret = "..."
        r"token\s*=\s*['\"][a-zA-Z0-9]{10,}['\"]",  # token = "..."
        # JavaScript
        r"password\s*[:=]\s*['\"][a-zA-Z0-9@#$%]{3,}['\"]",  # password: "..." 或 password = "..."
        r"apiKey\s*[:=]\s*['\"][a-zA-Z0-9]{10,}['\"]",
        r"secret\s*[:=]\s*['\"][a-zA-Z0-9]{10,}['\"]",
        # Java
        r"String\s+password\s*=\s*['\"][a-zA-Z0-9@#$%]{3,}['\"]",  # String password = "..."
        r"private\s+String\s+apiKey\s*=\s*['\"][a-zA-Z0-9]{10,}['\"]",
        # Go
        r"password\s*:=\s*['\"][a-zA-Z0-9@#$%]{3,}['\"]",  # password := "..."
        r"apiKey\s*:=\s*['\"][a-zA-Z0-9]{10,}['\"]",
        # PHP
        r"\$password\s*=\s*['\"][a-zA-Z0-9@#$%]{3,}['\"]",  # $password = "..."
        r"\$api_key\s*=\s*['\"][a-zA-Z0-9]{10,}['\"]",
    ],
    # ===== XSS 风险 =====
    # 注意：Reflected XSS 通常为 Medium，Stored XSS 为 High
    "XSS_RISK": [
        # JavaScript
        r"innerHTML\s*=\s*.*\+",  # element.innerHTML = ... + var
        r"\.innerHTML\s*=\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*;",  # element.innerHTML = userInput; (直接赋值变量)
        r"getElementById\([^)]+\)\.innerHTML\s*=\s*[a-zA-Z_$]",  # document.getElementById(...).innerHTML = var
        r"document\.write\s*\(\s*.*\+",  # document.write(... + ...)
        r"document\.write\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)",  # document.write(userInput)
        r"\.html\s*\(\s*.*\+",  # jQuery .html(... + ...)
        r"\.html\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)",  # jQuery .html(userInput)
        r"\.text\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)",  # jQuery .text(userInput) - 虽然 text() 会转义，但也要检查
        r"outerHTML\s*=\s*[a-zA-Z_$]",  # element.outerHTML = var
        # 【P0优化4】Angular XSS绕过
        r"bypassSecurityTrustHtml\s*\(",  # DomSanitizer.bypassSecurityTrustHtml()
        r"bypassSecurityTrustScript\s*\(",  # DomSanitizer.bypassSecurityTrustScript()
        r"bypassSecurityTrustStyle\s*\(",  # DomSanitizer.bypassSecurityTrustStyle()
        r"bypassSecurityTrustUrl\s*\(",  # DomSanitizer.bypassSecurityTrustUrl()
        r"bypassSecurityTrustResourceUrl\s*\(",  # DomSanitizer.bypassSecurityTrustResourceUrl()
        r"sanitizer\.bypassSecurity",  # sanitizer.bypassSecurity*
        r"DomSanitizer\.bypassSecurity",  # DomSanitizer.bypassSecurity*
        # 【P0优化4】React XSS绕过
        r"dangerouslySetInnerHTML\s*=\s*\{",  # dangerouslySetInnerHTML={{ __html: ... }}
        r"__html\s*:\s*[^,}]+",  # __html: userInput
        # 【P0优化4】Vue XSS绕过
        r"v-html\s*=\s*['\"]",  # v-html="userInput"
        r"v-html\s*=\s*\{",  # v-html={userInput}
        # Python (Web 框架)
        r"render_template_string\s*\(\s*.*\+",  # Flask render_template_string
        r"Template\s*\(\s*.*\+",  # Jinja2 Template
        # PHP
        # 注意：echo/print 需要上下文分析（是否经过 json_encode、header() 设置等）
        # 当前规则保留，但会在检测时进行上下文过滤
        r"echo\s+\$.*;",  # echo $var; (需要检查上下文)
        r"print\s+\$.*;",  # print $var; (需要检查上下文)
        # PHP 字符串拼接式 XSS：直接把 $_GET/$_POST/$_REQUEST/$_COOKIE 拼入 HTML 字符串
        # header("location: " . $_GET[...]) 由 OPEN_REDIRECT 规则单独覆盖
        r"\.\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[",
    ],
    # ===== 任意 URL 跳转（Open Redirect，CWE-601）=====
    "OPEN_REDIRECT": [
        # PHP：header("location: " . $userInput) 或 header("Location: " . $_GET[...])
        r"header\s*\(\s*['\"]location\s*:\s*['\"]?\s*\.\s*\$",  # header("location: " . $var)
        r"header\s*\(\s*['\"]location\s*:.*\$_(GET|POST|REQUEST|COOKIE)\s*\[",  # header("location:...$_GET[...]")
        r'header\s*\(\s*"location\s*:.*\$',  # header("location: $var")
        # Python/Flask
        r"redirect\s*\(\s*request\.(args|form|values|json)",  # redirect(request.args['url'])
        # Node.js/Express
        r"res\.redirect\s*\(\s*req\.(query|body|params)",  # res.redirect(req.query.url)
    ],
    # ===== 反序列化风险 =====
    "DESERIALIZATION": [
        # Python
        r"pickle\.loads\s*\(",  # pickle.loads()
        r"pickle\.load\s*\(",  # pickle.load()
        r"yaml\.load\s*\(",  # yaml.load()
        r"json\.loads\s*\(\s*[^,)]+\)",  # json.loads() 需要检查参数
        # Java
        r"ObjectInputStream.*readObject\s*\(",  # ObjectInputStream.readObject()
        r"\.readObject\s*\(",  # .readObject()
        r"Serializable",
        # PHP
        r"unserialize\s*\(",  # unserialize()
        # JavaScript
        r"JSON\.parse\s*\(\s*[^,)]+\)",  # JSON.parse() 需要检查
    ],
    # ===== 路径遍历 =====
    "PATH_TRAVERSAL": [
        # Python
        r"open\s*\(\s*.*\+.*['\"]",  # open(... + "...")
        r"file\s*\(\s*.*\+.*['\"]",  # file(... + "...")
        # Java
        r"File\s*\(\s*.*\+.*['\"]",  # new File(... + "...")
        r"new File\s*\(\s*.*\+",
        # Go
        r"os\.Open\s*\(\s*.*\+",  # os.Open(... + ...)
        r"ioutil\.ReadFile\s*\(\s*.*\+",
        # PHP
        r"fopen\s*\(\s*.*\.\s*\$",  # fopen("..." . $var)
        r"include\s*\(\s*.*\.\s*\$",  # include("..." . $var)
        r"require\s*\(\s*.*\.\s*\$",  # require("..." . $var)
        # C/C++
        r"fopen\s*\(\s*.*\+",  # fopen(... + ...)
        # JavaScript/Node.js - 只检测文件操作，不检测UI操作
        # 注意：UI操作（snackBar.open(), window.open()等）会在检测时排除
        r"fs\.open\s*\(\s*.*\+",  # fs.open(... + ...)
        r"fs\.readFile\s*\(\s*.*\+",  # fs.readFile(... + ...)
        r"fs\.writeFile\s*\(\s*.*\+",  # fs.writeFile(... + ...)
        r"fs\.createReadStream\s*\(\s*.*\+",  # fs.createReadStream(... + ...)
        r"fs\.createWriteStream\s*\(\s*.*\+",  # fs.createWriteStream(... + ...)
        r"path\.join\s*\(\s*.*\+",  # path.join(... + ...)
    ],
    # ===== NoSQL注入 =====
    # 【P0优化3】新增NoSQL注入检测
    "NOSQL_INJECTION": [
        # Mongoose NoSQL注入
        r"\.find\s*\(\s*\{[^}]*\$where\s*:\s*['\"].*\+",  # .find({ $where: "..." + var })
        r"\.find\s*\(\s*\{[^}]*\$where\s*:\s*`.*\$\{",  # .find({ $where: `...${var}` })
        r"\.findOne\s*\(\s*\{[^}]*\$where\s*:\s*['\"].*\+",  # .findOne({ $where: "..." + var })
        r"\.find\s*\(\s*\{[^}]*\$ne\s*:\s*[^}]+\+",  # .find({ email: { $ne: var + ... } })
        r"\.find\s*\(\s*\{[^}]*\$regex\s*:\s*[^}]+\+",  # .find({ email: { $regex: var + ... } })
        r"\.find\s*\(\s*\{[^}]*\$gt\s*:\s*[^}]+\+",  # .find({ age: { $gt: var + ... } })
        r"\.find\s*\(\s*\{[^}]*\$lt\s*:\s*[^}]+\+",  # .find({ age: { $lt: var + ... } })
        r"\.find\s*\(\s*\{[^}]*\$in\s*:\s*[^}]+\+",  # .find({ id: { $in: var + ... } })
        r"\.find\s*\(\s*\{[^}]*\$nin\s*:\s*[^}]+\+",  # .find({ id: { $nin: var + ... } })
        r"\.find\s*\(\s*\{[^}]*\$or\s*:\s*\[.*\+",  # .find({ $or: [...] + var })
        r"\.find\s*\(\s*\{[^}]*\$and\s*:\s*\[.*\+",  # .find({ $and: [...] + var })
        # MongoDB原生查询
        r"db\.\w+\.find\s*\(\s*\{[^}]*\$where\s*:\s*['\"].*\+",  # db.users.find({ $where: "..." + var })
        r"collection\.find\s*\(\s*\{[^}]*\$where\s*:\s*['\"].*\+",  # collection.find({ $where: "..." + var })
        r"db\.\w+\.aggregate\s*\(\s*\[.*\$match.*\+",  # db.users.aggregate([{ $match: ... + var }])
    ],
    # ===== 缓冲区溢出 (C/C++) =====
    "BUFFER_OVERFLOW": [
        r"strcpy\s*\(",  # strcpy() - 危险
        r"strcat\s*\(",  # strcat() - 危险
        r"gets\s*\(",  # gets() - 危险
        # 注意：不检测 sprintf()，因为 PHP 的 sprintf() 是安全的
        r"strncpy\s*\(\s*[^,]+,\s*[^,]+,\s*strlen",  # strncpy(..., ..., strlen(...)) 危险用法
    ],
    # ===== 格式化字符串漏洞 (C/C++) =====
    # 注意：只检测真正危险的格式化字符串，排除安全的 sprintf() 使用
    "FORMAT_STRING": [
        # C/C++: printf/sprintf 使用变量作为格式字符串（危险）
        r"printf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)",  # printf(user_input) - 危险
        r"sprintf\s*\(\s*[^,]+,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)",  # sprintf(buffer, user_input) - 危险
        # 注意：不检测 printf("format", ...) 这种安全用法
    ],
}

# 预编译正则，减少 scan_code_locally 热路径中的重复编译
VULN_SIGNATURES_COMPILED = {k: [re.compile(r, re.IGNORECASE) for r in v] for k, v in VULN_SIGNATURES.items()}

# ── 后处理常用正则预编译（RCE / XSS 上下文判断）──
_RE_PHP_USER_INPUT = re.compile(r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[", re.IGNORECASE)
_RE_PHP_JSON_ENCODE = re.compile(r"json_encode\s*\(", re.IGNORECASE)
_RE_PHP_HTMLSPECIAL = re.compile(r"htmlspecialchars\s*\(|htmlentities\s*\(", re.IGNORECASE)
_RE_PHP_FILTER_SANIT = re.compile(r"filter_var\s*\(.*FILTER_SANITIZE", re.IGNORECASE)
_RE_PHP_CONTENT_JSON = re.compile(r'header\s*\(\s*["\']Content-Type:\s*application/json', re.IGNORECASE)
_RE_PHP_RESP_JSONENC = re.compile(r"\$response\s*\[.*\]\s*=\s*json_encode\s*\(", re.IGNORECASE)
_RE_PHP_RESP_METHOD = re.compile(r"\$response\s*=\s*\$this\s*->\s*\w+\s*\(", re.IGNORECASE)
_RE_PHP_DB_QUERY = re.compile(r"(SELECT|mysqli_query|mysql_query|->query)\s*\(", re.IGNORECASE)
_RE_PHP_FPASSTHRU = re.compile(r"\bfpassthru\s*\(", re.IGNORECASE)
_RE_PHP_SHELL_EXEC = re.compile(r"\b(shell_exec|exec|system|passthru|popen)\s*\(", re.IGNORECASE)
_RE_OPEN_REDIRECT_HDR = re.compile(r'header\s*\(\s*["\']location\s*:', re.IGNORECASE)
_RE_JS_REGEX_EXEC = re.compile(r"/.*/\.exec\s*\(", re.IGNORECASE)
_RE_ARRAY_DEF = re.compile(r"var\s+\w+\s*=\s*\[", re.IGNORECASE)
_RE_HTML_TAG_RCE = re.compile(r"<[^>]*>.*(shutdown|system|exec|shell_exec)", re.IGNORECASE)
_RE_ECHO_PRINT_RCE = re.compile(r'(echo|print)\s*["\'].*(shutdown|system|exec|shell_exec)', re.IGNORECASE)
# PHP RCE：调用前存在通用输入校验函数（is_numeric / intval / preg_match 等），用于降级 Medium
_RE_PHP_VALIDATION = re.compile(
    r"\b(is_numeric|intval|ctype_digit|preg_match|filter_var|in_array|array_search|strip_tags)\s*\(", re.IGNORECASE
)


def _strip_comments_and_strings(line: str, language: str = "python") -> str:
    """
    移除行中的注释和字符串字面量，只保留实际代码部分

    Args:
        line: 代码行
        language: 编程语言类型

    Returns:
        移除注释和字符串后的代码行
    """
    # Python: 移除 # 注释和字符串
    if language == "python":
        import re

        # 先处理三引号字符串（多行字符串，通常用于文档字符串）
        # 移除三引号字符串内容
        line = re.sub(r'"""[^"]*"""', '""""""', line, flags=re.DOTALL)
        line = re.sub(r"'''[^']*'''", "''''''", line, flags=re.DOTALL)

        # 移除单行注释（检查 # 是否在字符串中）
        if "#" in line:
            in_single_quote = False
            in_double_quote = False
            comment_pos = -1
            for i, char in enumerate(line):
                if char == "'" and (i == 0 or line[i - 1] != "\\"):
                    in_single_quote = not in_single_quote
                elif char == '"' and (i == 0 or line[i - 1] != "\\"):
                    in_double_quote = not in_double_quote
                elif char == "#" and not in_single_quote and not in_double_quote:
                    comment_pos = i
                    break
            if comment_pos >= 0:
                line = line[:comment_pos]

        # 移除字符串字面量内容（保留引号结构）
        # 单引号字符串
        line = re.sub(r"'[^']*'", "''", line)
        # 双引号字符串
        line = re.sub(r'"[^"]*"', '""', line)

    # JavaScript/TypeScript: 移除 // 注释和字符串
    elif language in ["javascript", "typescript"]:
        import re

        # 移除单行注释
        if "//" in line:
            in_single_quote = False
            in_double_quote = False
            comment_pos = -1
            for i in range(len(line) - 1):
                if line[i] == "'" and (i == 0 or line[i - 1] != "\\"):
                    in_single_quote = not in_single_quote
                elif line[i] == '"' and (i == 0 or line[i - 1] != "\\"):
                    in_double_quote = not in_double_quote
                elif line[i : i + 2] == "//" and not in_single_quote and not in_double_quote:
                    comment_pos = i
                    break
            if comment_pos >= 0:
                line = line[:comment_pos]

        # 移除字符串内容
        line = re.sub(r"'[^']*'", "''", line)
        line = re.sub(r'"[^"]*"', '""', line)
        line = re.sub(r"`[^`]*`", "``", line)  # 模板字符串

    # Java: 移除 // 注释和字符串
    elif language == "java":
        import re

        if "//" in line:
            in_double_quote = False
            comment_pos = -1
            for i in range(len(line) - 1):
                if line[i] == '"' and (i == 0 or line[i - 1] != "\\"):
                    in_double_quote = not in_double_quote
                elif line[i : i + 2] == "//" and not in_double_quote:
                    comment_pos = i
                    break
            if comment_pos >= 0:
                line = line[:comment_pos]

        line = re.sub(r'"[^"]*"', '""', line)

    # PHP: 移除 //、# 和 /* */ 注释
    elif language == "php":
        import re

        # 先处理多行注释 /* */
        line = re.sub(r"/\*.*?\*/", "", line, flags=re.DOTALL)

        # 移除单行注释 // 和 #
        if "//" in line or "#" in line:
            in_single_quote = False
            in_double_quote = False
            comment_pos = -1
            for i, char in enumerate(line):
                if char == "'" and (i == 0 or line[i - 1] != "\\"):
                    in_single_quote = not in_single_quote
                elif char == '"' and (i == 0 or line[i - 1] != "\\"):
                    in_double_quote = not in_double_quote
                elif (
                    (char == "#" or (i < len(line) - 1 and line[i : i + 2] == "//"))
                    and not in_single_quote
                    and not in_double_quote
                ):
                    comment_pos = i
                    break
            if comment_pos >= 0:
                line = line[:comment_pos]

        # 移除字符串内容
        line = re.sub(r"'[^']*'", "''", line)
        line = re.sub(r'"[^"]*"', '""', line)

    # C/C++: 移除 // 和 /* */ 注释
    elif language in ["c", "cpp"]:
        import re

        # 先处理多行注释 /* */
        line = re.sub(r"/\*.*?\*/", "", line, flags=re.DOTALL)

        # 移除单行注释
        if "//" in line:
            in_double_quote = False
            comment_pos = -1
            for i in range(len(line) - 1):
                if line[i] == '"' and (i == 0 or line[i - 1] != "\\"):
                    in_double_quote = not in_double_quote
                elif line[i : i + 2] == "//" and not in_double_quote:
                    comment_pos = i
                    break
            if comment_pos >= 0:
                line = line[:comment_pos]

        line = re.sub(r'"[^"]*"', '""', line)

    return line.strip()


# ═══════════════════════════════════════════════════════════════════
#  PHP 行级赋值链追踪器（PHP TaintGraph MVP）
# ═══════════════════════════════════════════════════════════════════
# 不依赖 tree-sitter，纯正则 + 行扫描实现单函数内赋值链追踪。
# 目标：比朴素"向上 N 行找关键词"更精确，支持：
#   $x = $_GET['a']  →  $y = $x  →  sink($y)  ==> TP
#   $x = intval($_GET['a'])  →  sink($x)        ==> Medium（已净化）
# ═══════════════════════════════════════════════════════════════════

# PHP 用户输入 Source（超全局变量）
_PHP_SOURCE_RE = re.compile(
    r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES|SESSION)\s*\[",
    re.IGNORECASE,
)

# PHP 常见净化/校验函数（调用后返回净化值）
# stripslashes 去除反斜杠转义，虽不完整净化，但通常是防护链的一环，加入白名单
# 避免将"已调用 stripslashes 的变量"继续识别为高危 tainted
_PHP_SANITIZE_RE = re.compile(
    r"\b(intval|floatval|abs|is_numeric|ctype_digit|ctype_alpha|ctype_alnum"
    r"|preg_match|filter_var|htmlspecialchars|htmlentities|strip_tags"
    r"|addslashes|mysqli_real_escape_string|pg_escape_string"
    r"|stripslashes|strip_tags|number_format|round|ceil|floor"
    r"|in_array|array_search|array_key_exists"
    r"|basename|realpath|dirname|pathinfo)\s*\(",
    re.IGNORECASE,
)

# PHP 变量赋值：$var = <expr>
_PHP_ASSIGN_RE = re.compile(
    r"^\s*(\$[\w]+)\s*=\s*(.+?)\s*;?\s*$",
)

# PHP Sink 函数（用于 TaintGraph 结果输出）
_PHP_SINK_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # (pattern, vuln_type, severity)
    # SQL Sink：mysql_query / mysqli_query / $obj->query() / $obj->execute()
    (
        re.compile(
            r"(?:\b(?:mysql_query|mysqli_query|pg_query|sqlite_exec)\s*\("
            r"|\$\w+\s*->\s*(?:query|execute)\s*\("
            r")",
            re.IGNORECASE,
        ),
        "SQL_INJECTION",
        "High",
    ),
    # RCE Sink：shell_exec / exec / system 等
    (
        re.compile(
            r"\b(?:shell_exec|exec|system|passthru|popen|proc_open|pcntl_exec)\s*\(",
            re.IGNORECASE,
        ),
        "RCE_COMMAND_EXEC",
        "Critical",
    ),
    # XSS Sink：echo / print 语句
    (
        re.compile(
            r"\b(?:echo|print|printf|fprintf|var_dump)\s+",
            re.IGNORECASE,
        ),
        "XSS_RISK",
        "Medium",
    ),
    # Open Redirect Sink：header("location: ...")
    (
        re.compile(
            r"header\s*\(\s*['\"]location\s*:",
            re.IGNORECASE,
        ),
        "OPEN_REDIRECT",
        "Medium",
    ),
    # Path Traversal Sink：file_get_contents / include / require / fopen / readfile
    (
        re.compile(
            r"\b(?:file_get_contents|include|require|include_once|require_once|fopen|readfile)\s*\(",
            re.IGNORECASE,
        ),
        "PATH_TRAVERSAL",
        "High",
    ),
    # Deserialization Sink：unserialize / json_decode
    (
        re.compile(
            r"\b(?:unserialize|json_decode)\s*\(",
            re.IGNORECASE,
        ),
        "DESERIALIZATION",
        "High",
    ),
]


def _php_extract_var_name(expr: str) -> str | None:
    """
    从赋值右侧表达式中提取主要引用的变量名（第一个 ``$var``）。

    ``$id . ' more'`` → ``$id``
    ``intval($uid)`` → ``$uid``（首个 $var 子表达式）
    """
    m = re.search(r"(\$[\w]+)", expr)
    return m.group(1) if m else None


class PhpTaintGraph:
    """
    PHP 单文件行级赋值链追踪器。

    算法：
    1. 第一遍：扫描所有赋值行，建立 {var: (line_no, expr, is_tainted, is_sanitized)} 映射。
    2. 第二遍：对每个 Sink 调用行，往前追踪参数变量是否可达 Source。
    3. 若路径上出现净化函数，标记 ``is_sanitized=True``，降级或跳过。

    条件守护（if 分支感知）：
    - 若 tree-sitter PHP 可用，使用 AST 节点精确区分正向/否定守护
    - 否则降级到正则行扫描（保守：忽略否定守护，避免漏报）
    """

    # tree-sitter PHP 解析器（类级单例，延迟初始化）
    _php_parser: object = None
    _php_parser_init: bool = False

    @classmethod
    def _get_php_parser(cls) -> object | None:
        """
        获取 PHP tree-sitter 解析器（懒加载，类级单例）。

        Returns:
            Parser 实例，不可用时返回 None。
        """
        if cls._php_parser_init:
            return cls._php_parser
        cls._php_parser_init = True
        if not _TS_AVAILABLE:
            return None
        try:
            lang = _ts_get_language("php")
            parser = _TsParser()
            parser.set_language(lang)
            cls._php_parser = parser
            logger.debug("PHP tree-sitter 解析器初始化成功")
        except (ImportError, RuntimeError, OSError) as exc:
            logger.debug("PHP tree-sitter 解析器不可用（%s），将使用正则 fallback", exc)
            cls._php_parser = None
        return cls._php_parser

    def __init__(self, lines: list[str]) -> None:
        self._lines = lines
        # {varname: {"line": int, "expr": str, "tainted": bool, "sanitized": bool}}
        self._var_map: dict[str, dict] = {}
        self._tainted_vars: set[str] = set()
        self._sanitized_vars: set[str] = set()
        # 行范围级 sanitized：{varname: [(start_line, end_line), ...]}
        # 用于 CFG 分支感知：变量只在特定行范围内是安全的（如 if 正向/否定守护的特定分支）
        self._range_sanitized: dict[str, list[tuple[int, int]]] = {}
        self._build()

    # 条件守护净化识别正则：if( is_numeric($var) ... )
    # 这类 if 语句中的变量在后续赋值中视为已守护（sanitized）
    _GUARD_CONDITION_RE = re.compile(
        r"if\s*\(\s*(?:[^)]*\b)?"
        r"(?:is_numeric|intval|ctype_digit|ctype_alpha|ctype_alnum"
        r"|is_int|is_float|is_string|filter_var|preg_match|in_array)\s*\(\s*(\$[\w\[\]'\"]+)",
        re.IGNORECASE,
    )

    def _build(self) -> None:
        """
        一次遍历建立完整赋值映射和污点集合，并做条件守护净化扫描。

        优先级（从高到低）：
        1. 净化函数包裹（如 intval($_GET['id'])）→ 即使包含 Source 也视为已净化
        2. 直接 Source（$_GET / $_POST 等）→ 标记为 tainted
        3. 普通赋值（污点传播）

        条件守护（第二遍）：
        - if( is_numeric($var) ) 语句将 $var 及其后续派生变量视为已净化
        - 覆盖 DVWA impossible.php 等"白名单 + 重组"模式
        """
        for idx, raw_line in enumerate(self._lines):
            line = raw_line.strip()
            m = _PHP_ASSIGN_RE.match(line)
            if not m:
                continue
            var, expr = m.group(1), m.group(2)

            # ── 优先检查净化函数包裹 ──
            # 例如：$safe = intval($_GET['id'])  或  $safe = htmlspecialchars($raw)
            if _PHP_SANITIZE_RE.search(expr):
                # 取内部第一个 $var 或直接 Source
                inner = _php_extract_var_name(expr)
                # 内部变量已污染，或内部直接是 Source → 净化后标记 sanitized
                inner_tainted = bool((inner and inner in self._tainted_vars) or _PHP_SOURCE_RE.search(expr))
                self._var_map[var] = {
                    "line": idx + 1,
                    "expr": expr,
                    "tainted": inner_tainted,
                    "sanitized": inner_tainted,
                }
                if inner_tainted:
                    self._sanitized_vars.add(var)
                continue

            # ── 直接 Source ──
            if _PHP_SOURCE_RE.search(expr):
                self._var_map[var] = {"line": idx + 1, "expr": expr, "tainted": True, "sanitized": False}
                self._tainted_vars.add(var)
                continue

            # 普通赋值：传播污点
            inner = _php_extract_var_name(expr)
            if inner and inner in self._tainted_vars:
                is_san = inner in self._sanitized_vars
                self._var_map[var] = {"line": idx + 1, "expr": expr, "tainted": True, "sanitized": is_san}
                if is_san:
                    self._sanitized_vars.add(var)
                else:
                    self._tainted_vars.add(var)
            else:
                self._var_map[var] = {"line": idx + 1, "expr": expr, "tainted": False, "sanitized": False}

        # ── 第二遍：条件守护净化识别 ──
        # 扫描 if(is_numeric($var)...) 等守护语句，将守护变量标记为 sanitized
        self._apply_guard_conditions()

    # 用于从 AST 节点中识别守护函数名的集合
    _GUARD_FUNC_NAMES: frozenset[str] = frozenset(
        {
            "is_numeric",
            "intval",
            "ctype_digit",
            "ctype_alpha",
            "ctype_alnum",
            "is_int",
            "is_float",
            "is_string",
            "filter_var",
            "preg_match",
            "in_array",
        }
    )

    def _apply_guard_conditions(self) -> None:
        """
        第二遍扫描：识别 ``if(is_numeric($var)...)`` 等条件守护语句。

        **优先使用 tree-sitter PHP AST 分析**（精确区分正向/否定守护）：
        - 正向守护 ``if(is_numeric($var)) { ... }``：
          then 块中的变量视为已守护（sanitized）
        - 否定守护 ``if(!is_numeric($var)) { ... } else { ... }``：
          then 块中的变量**不**降级（危险路径），else 块中的变量才降级

        **tree-sitter 不可用时 fallback 到正则**（保守策略：
        对所有守护模式均降级，包括否定守护，避免漏报）。
        """
        parser = self._get_php_parser()
        if parser is not None:
            try:
                self._apply_guard_conditions_ast(parser)
                return
            except (RuntimeError, ValueError) as exc:
                logger.debug("PHP AST 守护分析失败（%s），降级到正则", exc)

        # ── Fallback：正则行扫描（保守：不区分正向/否定，均降级）──
        self._apply_guard_conditions_regex()

    def _apply_guard_conditions_ast(self, parser: object) -> None:
        """
        使用 tree-sitter PHP AST 精确识别 if 分支守护。

        正向守护（``if(is_numeric($var))``）：
            then 块范围内的行 → 变量在 sanitized 降级候选集
        否定守护（``if(!is_numeric($var))``）：
            then 块行范围不处理（危险路径）
            else 块行范围 → 变量在 sanitized 降级候选集

        只对首次赋值在守护块内或守护块之后的变量生效，
        避免将守护块之前已使用的变量错误降级。

        Args:
            parser: tree-sitter PHP Parser 实例
        """
        code = "\n".join(self._lines)
        tree = parser.parse(code.encode("utf-8", errors="replace"))

        # 收集守护块：{(start_line, end_line): is_safe}
        # is_safe=True 表示该行范围内的 $var 应被降级为 sanitized
        safe_line_ranges: list[tuple[int, int]] = []

        def _find_if_guards(node: object) -> None:
            """递归遍历 AST，找到所有 if_statement 节点并分析守护分支。"""
            if node.type == "if_statement":  # type: ignore[attr-defined]
                _process_if_node(node)
            for child in node.children:  # type: ignore[attr-defined]
                _find_if_guards(child)

        def _is_guard_condition(cond_node: object) -> tuple[bool, bool]:
            """
            分析条件节点是否为守护函数调用。

            Returns:
                (is_guard, is_negated)
                - is_guard: 是否命中守护函数（is_numeric 等）
                - is_negated: 是否取了否定（!）
            """
            # 直接守护：is_numeric($var)
            if cond_node.type == "function_call_expression":  # type: ignore[attr-defined]
                for child in cond_node.children:  # type: ignore[attr-defined]
                    if child.type == "name":  # type: ignore[attr-defined]
                        func_name = child.text.decode("utf-8", errors="replace").lower()  # type: ignore[attr-defined]
                        if func_name in self._GUARD_FUNC_NAMES:
                            return True, False
                return False, False

            # 否定守护：!is_numeric($var)
            if cond_node.type == "unary_op_expression":  # type: ignore[attr-defined]
                for child in cond_node.children:  # type: ignore[attr-defined]
                    if child.type == "!":  # type: ignore[attr-defined]
                        continue
                    is_g, _ = _is_guard_condition(child)
                    if is_g:
                        return True, True
                return False, False

            # 逻辑与复合守护：is_numeric($a) && is_numeric($b)
            if cond_node.type in ("binary_expression", "parenthesized_expression"):  # type: ignore[attr-defined]
                for child in cond_node.children:  # type: ignore[attr-defined]
                    is_g, is_n = _is_guard_condition(child)
                    if is_g:
                        return True, is_n
            return False, False

        def _extract_guarded_var_names(cond_node: object) -> set[str]:
            """
            从守护条件节点中提取被守护的变量名集合。

            例如 ``is_numeric($id)`` → ``{'$id'}``
            ``is_numeric($octet[0]) && is_numeric($octet[1])`` → ``{'$octet'}``
            """
            names: set[str] = set()
            for child in cond_node.children:  # type: ignore[attr-defined]
                if child.type == "variable_name":  # type: ignore[attr-defined]
                    text = child.text.decode("utf-8", errors="replace")  # type: ignore[attr-defined]
                    if text.startswith("$"):
                        names.add(text)
                elif child.type == "subscript_expression":  # type: ignore[attr-defined]
                    # $octet[0] → 取 $octet
                    for sub in child.children:  # type: ignore[attr-defined]
                        if sub.type == "variable_name":  # type: ignore[attr-defined]
                            t = sub.text.decode("utf-8", errors="replace")  # type: ignore[attr-defined]
                            if t.startswith("$"):
                                names.add(t)
                            break
                else:
                    names.update(_extract_guarded_var_names(child))
            return names

        def _process_if_node(if_node: object) -> None:
            """
            分析单个 if_statement 节点，收集安全行范围及被守护的变量名。

            策略：
            - 提取守护条件中出现的 $var 名称
            - 正向守护：在 then 块行范围内，这些 $var 视为 sanitized
            - 否定守护：在 else 块行范围内，这些 $var 视为 sanitized
            """
            condition_node = None
            then_node = None
            else_node = None

            for child in if_node.children:  # type: ignore[attr-defined]
                if child.type == "parenthesized_expression":  # type: ignore[attr-defined]
                    condition_node = child
                elif child.type == "compound_statement" and then_node is None:
                    then_node = child
                elif child.type == "else_clause":  # type: ignore[attr-defined]
                    else_node = child

            if condition_node is None or then_node is None:
                return

            # 提取括号内的实际条件子节点
            actual_cond = None
            for child in condition_node.children:  # type: ignore[attr-defined]
                if child.type not in ("(", ")"):
                    actual_cond = child
                    break

            if actual_cond is None:
                return

            is_guard, is_negated = _is_guard_condition(actual_cond)
            if not is_guard:
                return

            # 提取守护条件中出现的变量名（这些变量在安全分支中已被守护）
            guarded_in_cond = _extract_guarded_var_names(actual_cond)

            # tree-sitter 行号从 0 开始，转换为 1-indexed
            if is_negated:
                # 否定守护：then 块危险，else 块安全
                if else_node is not None:
                    for child in else_node.children:  # type: ignore[attr-defined]
                        if child.type == "compound_statement":  # type: ignore[attr-defined]
                            s = child.start_point[0] + 1  # type: ignore[attr-defined]
                            e = child.end_point[0] + 1  # type: ignore[attr-defined]
                            safe_line_ranges.append((s, e, guarded_in_cond))
            else:
                # 正向守护：then 块安全
                s = then_node.start_point[0] + 1  # type: ignore[attr-defined]
                e = then_node.end_point[0] + 1  # type: ignore[attr-defined]
                safe_line_ranges.append((s, e, guarded_in_cond))

        _find_if_guards(tree.root_node)

        if not safe_line_ranges:
            return

        # 将守护条件中出现的变量记录为行范围级 sanitized（不全局降级）
        # 这样 is_tainted_at_line(var, sink_line) 能正确感知守护分支
        for s, e, cond_vars in safe_line_ranges:
            for cvar in cond_vars:
                if cvar in self._tainted_vars:
                    if cvar not in self._range_sanitized:
                        self._range_sanitized[cvar] = []
                    self._range_sanitized[cvar].append((s, e))

        # 派生变量（在安全行范围内被赋值的）→ 全局降级（安全块内的新赋值已净化）
        guarded_vars: set[str] = set()
        for s, e, _ in safe_line_ranges:
            for var, info in self._var_map.items():
                var_line = info.get("line", 0)
                if s <= var_line <= e and var in self._tainted_vars:
                    guarded_vars.add(var)

        self._mark_guarded(guarded_vars)

    def _apply_guard_conditions_regex(self) -> None:
        """
        正则行扫描版本（fallback）：保守策略，对所有守护模式均降级，
        不区分正向/否定（极少数否定守护漏报是可接受的 tradeoff）。
        """
        guarded_vars: set[str] = set()
        for raw_line in self._lines:
            line = raw_line.strip()
            mg = self._GUARD_CONDITION_RE.search(line)
            if mg:
                raw_var = mg.group(1)
                var_m = re.match(r"(\$[\w]+)", raw_var)
                if var_m:
                    guarded_vars.add(var_m.group(1))
                    arr_m = re.match(r"(\$[\w]+)\[", raw_var)
                    if arr_m:
                        guarded_vars.add(arr_m.group(1))

        self._mark_guarded(guarded_vars)

    def _mark_guarded(self, guarded_vars: set[str]) -> None:
        """
        将一组变量从 tainted 降级为 sanitized，并传播到下游依赖变量。

        Args:
            guarded_vars: 需要降级的变量集合
        """
        if not guarded_vars:
            return

        for var in guarded_vars:
            if var in self._tainted_vars:
                self._sanitized_vars.add(var)
                if var in self._var_map:
                    self._var_map[var]["sanitized"] = True

        # 传播：依赖被守护变量的下游变量也降为 sanitized
        changed = True
        while changed:
            changed = False
            for var, info in self._var_map.items():
                if var in self._sanitized_vars:
                    continue
                if var not in self._tainted_vars:
                    continue
                expr = info.get("expr", "")
                inner = _php_extract_var_name(expr)
                if inner and inner in self._sanitized_vars:
                    self._sanitized_vars.add(var)
                    info["sanitized"] = True
                    changed = True

    def is_tainted(self, var: str, line: int = 0) -> bool:
        """
        变量是否在指定行携带未净化的用户输入污点。

        若提供 ``line``，还会检查行范围级 sanitized（CFG 分支守护）：
        若该行处于守护块的安全范围内，则视为已净化（非 tainted）。

        Args:
            var:  变量名（含 ``$`` 前缀）
            line: Sink 所在行号（1-indexed），0 表示不做行范围检查

        Returns:
            True 表示仍是 tainted（危险），False 表示安全。
        """
        if var not in self._tainted_vars:
            return False
        if var in self._sanitized_vars:
            return False
        # 行范围级 sanitized 检查（CFG 守护）
        if line > 0 and var in self._range_sanitized:
            for s, e in self._range_sanitized[var]:
                if s <= line <= e:
                    return False
        return True

    def is_sanitized(self, var: str, line: int = 0) -> bool:
        """
        变量是否已被净化（全局或在指定行范围内）。

        Args:
            var:  变量名
            line: Sink 所在行号（1-indexed），0 表示不做行范围检查

        Returns:
            True 表示已净化。
        """
        if var in self._sanitized_vars:
            return True
        if line > 0 and var in self._range_sanitized:
            for s, e in self._range_sanitized[var]:
                if s <= line <= e:
                    return True
        return False

    def get_source_line(self, var: str) -> int:
        """获取变量的初始赋值行号（调试用）。"""
        info = self._var_map.get(var)
        return info["line"] if info else 0

    def get_source_expr(self, var: str) -> str | None:
        """
        获取变量被标记为 sanitized 时对应的赋值表达式。

        用于 RCE 等规则判断净化函数是否属于"强类型约束"
        （如 intval），从而决定是否跳过 Low finding。

        Returns:
            赋值右侧表达式字符串；若变量不在追踪表中则返回 None。
        """
        info = self._var_map.get(var)
        if not info:
            return None
        return info.get("expr")


def php_taint_scan(code: str, file_path: str | None = None) -> list[dict]:
    """
    PHP 污点分析入口（行级赋值链追踪）。

    返回 findings 列表，格式与 ``scan_code_locally`` 一致。
    不替代 ``scan_code_locally``，而是在其基础上提供更精确的数据流判断：
    - 只报告能确认 Source→Sink 路径的漏洞；
    - 已净化的路径跳过或降级 severity。

    与 ``scan_code_locally`` 的分工：
    - ``scan_code_locally`` 做宽泛正则匹配（高召回）；
    - ``php_taint_scan`` 做精确数据流判断（高精度）；
    - 调用者可合并两者结果（取并集或交集）。
    """
    findings = []
    lines = code.split("\n")
    taint = PhpTaintGraph(lines)

    for idx, raw_line in enumerate(lines):
        line_num = idx + 1
        line = raw_line.strip()

        for sink_re, vuln_type, base_severity in _PHP_SINK_PATTERNS:
            if not sink_re.search(line):
                continue

            # 从 sink 调用中提取参数变量（首个 $var）
            # 优先级：echo/print 空格语法 > 圆括号参数 > 字符串拼接参数
            arg_var: str | None = None

            # echo/print $var 或 echo "..." . $var
            echo_m = re.search(r"\b(?:echo|print)\s+(?:[^$]*\.\s*)?(\$[\w]+)", line, re.IGNORECASE)
            if echo_m:
                arg_var = echo_m.group(1)
            else:
                # header("Location: " . $var) 或 func($var)
                # 找圆括号内出现的第一个 $var（跳过字符串字面量）
                paren_m = re.search(r"\(\s*(?:[^$)\"']*[\"'][^\"']*[\"']\s*\.\s*)?(\$[\w]+)", line)
                if paren_m:
                    arg_var = paren_m.group(1)

            if not arg_var:
                continue

            if taint.is_tainted(arg_var):
                findings.append(
                    {
                        "type": vuln_type,
                        "severity": base_severity,
                        "line": line_num,
                        "content": (
                            f"[TaintGraph] {vuln_type}：污点变量 {arg_var} "
                            f"源自用户输入（第 {taint.get_source_line(arg_var)} 行），"
                            f"未经净化流入 Sink。"
                        ),
                        "taint_source_line": taint.get_source_line(arg_var),
                        "taint_var": arg_var,
                        "confidence": "high",
                    }
                )
            elif taint.is_sanitized(arg_var):
                # 已净化：降级或跳过（此处记录为 Low，供人工确认）
                findings.append(
                    {
                        "type": vuln_type,
                        "severity": "Low",
                        "line": line_num,
                        "content": (
                            f"[TaintGraph] {vuln_type}（疑似已净化）：变量 {arg_var} "
                            f"经净化函数处理，但建议人工确认净化是否充分。"
                        ),
                        "taint_source_line": taint.get_source_line(arg_var),
                        "taint_var": arg_var,
                        "confidence": "low",
                    }
                )

    return findings


def scan_code_locally(code_content, file_path=None):
    """
    本地预扫描函数：不联网，纯靠规则匹配
    优化版本：排除注释和字符串字面量中的匹配

    Args:
        code_content: 源代码内容
        file_path: 文件路径（用于语言检测）
    """
    findings = []

    # 检测语言类型
    language = "python"  # 默认
    if file_path:
        ext = file_path.lower().split(".")[-1] if "." in file_path else ""
        file_name_lower = file_path.lower()

        # 【修复问题5】跳过帮助文档和纯 HTML 文件
        if "help" in file_name_lower and ext in ["php", "html", "htm"]:
            # help.php, help.html 等帮助文档文件，通常包含大量文档说明，跳过扫描
            return []

        if ext in ["js", "jsx", "mjs"]:
            language = "javascript"
        elif ext == "ts" or ext == "tsx":
            language = "typescript"
        elif ext == "java":
            language = "java"
        elif ext in ["c", "cpp", "cc", "cxx", "h", "hpp", "hxx"]:
            language = "cpp"
        elif ext == "go":
            language = "go"
        elif ext in ["php", "phtml"]:
            language = "php"
        elif ext in ["html", "htm", "xml"]:
            # HTML/XML 文件，跳过扫描（主要是文本内容）
            return []

    # 按行扫描，这样能拿到行号
    lines = code_content.split("\n")

    for line_idx, line in enumerate(lines):
        line_num = line_idx + 1

        # 跳过空行
        if not line.strip():
            continue

        # 【修复问题1】对于PHP，如果整行都是注释（以 # 或 // 开头），直接跳过
        if language == "php":
            stripped_line = line.strip()
            if stripped_line.startswith("#") or stripped_line.startswith("//"):
                continue

        # 移除注释和字符串，只检查实际代码
        code_only_line = _strip_comments_and_strings(line, language)

        # 如果移除注释和字符串后为空，跳过
        if not code_only_line:
            continue

        for vuln_type, compiled_list in VULN_SIGNATURES_COMPILED.items():
            for pat in compiled_list:
                # 忽略大小写匹配（已编译进 pat）
                # 【修复问题1】对于RCE检测，先检查原始行，避免正则表达式字面量被移除后误匹配
                if vuln_type == "RCE_COMMAND_EXEC" and language in ["javascript", "typescript"]:
                    # 先检查原始行是否是 RegExp.exec() 模式
                    if re.search(r"/.*/\.exec\s*\(", line, re.IGNORECASE):
                        continue  # 跳过，这是正则表达式方法

                # PHP：对 SQL_INJECTION / OPEN_REDIRECT 用原始行匹配，
                # 避免 _strip_comments_and_strings 剥掉字符串内容（如 "location: "、'$id'）
                match_line = code_only_line
                if language == "php" and vuln_type in ("SQL_INJECTION", "OPEN_REDIRECT"):
                    match_line = line.strip()
                if pat.search(match_line):
                    impossible_rce_note = False  # 仅 PHP impossible 类 RCE 时为 True，用于 content 追加说明
                    # 【P1优化】关键词匹配改进：检查函数调用、第三方库、语言特性
                    if vuln_type == "RCE_COMMAND_EXEC" and language in ["javascript", "typescript"]:
                        # 检查是否是函数调用（不是函数定义）
                        # 函数定义通常格式：function name() 或 async function name()
                        if re.search(r"^\s*(async\s+)?function\s+\w*[Ss]ystem", code_only_line, re.IGNORECASE):
                            continue  # 跳过函数定义

                        # 检查是否是第三方库对象（THREE.ParticleSystem等）
                        # 匹配模式：THREE.ParticleSystem, jQuery.System, React.System等
                        third_party_patterns = [
                            r"THREE\.\w*[Ss]ystem",
                            r"jQuery\.\w*[Ss]ystem",
                            r"\$\.\w*[Ss]ystem",
                            r"React\.\w*[Ss]ystem",
                            r"Vue\.\w*[Ss]ystem",
                            r"Angular\.\w*[Ss]ystem",
                            r"Backbone\.\w*[Ss]ystem",
                            r"Underscore\.\w*[Ss]ystem",
                            r"Lodash\.\w*[Ss]ystem",
                            r"_\w*\.\w*[Ss]ystem",
                        ]
                        if any(re.search(pattern, code_only_line, re.IGNORECASE) for pattern in third_party_patterns):
                            continue  # 跳过第三方库对象

                        # 检查是否是类名/变量名（不是函数调用）
                        # 匹配模式：new ParticleSystem(), var system = ..., class System
                        if re.search(
                            r"(new\s+\w*[Ss]ystem|var\s+\w*[Ss]ystem|let\s+\w*[Ss]ystem|const\s+\w*[Ss]ystem|class\s+\w*[Ss]ystem)",
                            code_only_line,
                            re.IGNORECASE,
                        ):
                            continue  # 跳过类名/变量名

                        # JavaScript中，system() 不存在，只有 child_process.exec()
                        # 如果匹配到 system() 但没有 child_process，可能是误报
                        if re.search(r"\bsystem\s*\(", code_only_line, re.IGNORECASE):
                            if "child_process" not in code_only_line and "process" not in code_only_line:
                                # 检查上下文，看是否是真正的system调用
                                context_start = max(0, line_idx - 3)
                                context_end = min(len(lines), line_idx + 3)
                                context_lines = "\n".join(lines[context_start:context_end])
                                if (
                                    "child_process" not in context_lines.lower()
                                    and "process" not in context_lines.lower()
                                ):
                                    continue  # 跳过，JavaScript中没有system()函数

                    # 【修复问题4】硬编码凭证特殊处理：排除 SQL 查询中的字段名
                    if vuln_type == "HARDCODED_CREDENTIALS":
                        # 检查是否是 SQL 查询中的字段名（如 WHERE password='$pass'）
                        # SQL 查询通常包含 SELECT, WHERE, FROM, UPDATE, INSERT 等关键词
                        sql_keywords = ["SELECT", "WHERE", "FROM", "UPDATE", "INSERT", "SET", "AND", "OR"]
                        if any(keyword in code_only_line.upper() for keyword in sql_keywords):
                            # 如果包含 SQL 关键词，且 password 后面是 = 或 IN，可能是字段名
                            if re.search(r"password\s*[=\(]", code_only_line, re.IGNORECASE):
                                continue  # 跳过，这是 SQL 字段名，不是硬编码凭证

                    # 【修复问题3】缓冲区溢出特殊处理：排除JavaScript/Python等高级语言
                    if vuln_type == "BUFFER_OVERFLOW":
                        # JavaScript/Python/Java等高级语言不会有经典缓冲区溢出
                        # 只检测C/C++/Go等系统级语言
                        if language in ["javascript", "typescript", "python", "java"]:
                            continue  # 跳过，高级语言不会有经典缓冲区溢出
                        # 对于C/C++，保留检测（这些语言确实有缓冲区溢出风险）

                    # 获取严重程度（从 VULN_SEVERITY 字典）
                    severity = VULN_SEVERITY.get(vuln_type, "Medium")

                    # SQL 注入特殊处理：排除 prepare()、参数化查询和转义函数
                    if vuln_type == "SQL_INJECTION":
                        # 【优化6】扩展上下文检查范围
                        context_start = max(0, line_idx - 5)  # 检查前5行
                        context_end = min(len(lines), line_idx + 5)  # 检查后5行
                        context_lines = "\n".join(lines[context_start:context_end])

                        # 【修复问题2】优先检查 prepare() - 这是防御 SQL 注入的标准方案，不应该被误报
                        # 检查 PDO/mysqli prepare() 调用
                        if re.search(r"->prepare\s*\(|\.prepare\s*\(", code_only_line, re.IGNORECASE):
                            continue  # 跳过，这是安全的参数化查询
                        # 检查参数化查询标记（:param, ?）- 通常与 prepare() 一起使用
                        # 如果包含参数化标记，且上下文中有 prepare，跳过
                        if re.search(r":\w+|\\?", code_only_line):
                            if "prepare" in context_lines.lower():
                                continue

                        # 【优化7】识别更多SQL安全函数
                        if language == "php":
                            # mysqli_real_escape_string() - SQL转义函数
                            if re.search(r"mysqli_real_escape_string\s*\(", context_lines, re.IGNORECASE):
                                # 检查变量是否经过转义（简单检查：同一行或前后行）
                                # TODO: 需要完整的污点分析才能准确判断
                                pass  # 暂时不跳过，因为需要确认变量是否真的经过转义

                            # addslashes() - 虽然不安全，但至少做了处理
                            # 这里不跳过，因为addslashes()不足以防御SQL注入

                    # 【P0优化1】PATH_TRAVERSAL调用者类型识别：区分文件操作和UI操作
                    if vuln_type == "PATH_TRAVERSAL" and language in ["javascript", "typescript"]:
                        # 检查上下文，区分文件操作和UI操作
                        context_start = max(0, line_idx - 5)
                        context_end = min(len(lines), line_idx + 5)
                        context_lines = "\n".join(lines[context_start:context_end])

                        # UI操作模式（排除）
                        ui_operation_patterns = [
                            r"snackBar\.open\s*\(",
                            r"window\.open\s*\(",
                            r"dialog\.open\s*\(",
                            r"modal\.open\s*\(",
                            r"toast\.open\s*\(",
                            r"alert\.open\s*\(",
                            r"popup\.open\s*\(",
                            r'\.open\s*\(\s*["\']',  # .open('...') - 通常是UI操作
                        ]

                        # 文件操作模式（保留检测）
                        file_operation_patterns = [
                            r"fs\.open\s*\(",
                            r"fs\.readFile\s*\(",
                            r"fs\.writeFile\s*\(",
                            r"fs\.createReadStream\s*\(",
                            r"fs\.createWriteStream\s*\(",
                            r"path\.join\s*\(",
                            r'require\s*\(\s*["\']fs["\']',
                        ]

                        # 如果是UI操作，跳过
                        if any(re.search(pattern, context_lines, re.IGNORECASE) for pattern in ui_operation_patterns):
                            continue  # 跳过UI操作

                        # 如果没有明确的文件操作模式，可能是UI操作，跳过
                        if not any(
                            re.search(pattern, context_lines, re.IGNORECASE) for pattern in file_operation_patterns
                        ):
                            # 检查是否是通用的open()调用（可能是UI操作）
                            if re.search(r'\.open\s*\(\s*["\']', code_only_line, re.IGNORECASE):
                                continue  # 跳过，可能是UI操作

                    # 格式化字符串特殊处理：排除安全的 sprintf() 使用
                    if vuln_type == "FORMAT_STRING":
                        # 如果 sprintf() 的格式字符串是字面量（如 "%02x"），跳过
                        if re.search(r'sprintf\s*\([^,]+,\s*["\']', code_only_line):
                            continue  # 格式字符串是字面量，安全

                    # 【P1优化】JSON.parse规则重写：针对JavaScript特性
                    if vuln_type == "DESERIALIZATION":
                        # JavaScript/TypeScript 中的 JSON.parse 不是反序列化漏洞（不像Java的readObject）
                        # 只有在配合原型污染的场景下才算利用点
                        if language in ["javascript", "typescript"]:
                            # 【P1优化1】扩展安全的API响应处理模式
                            safe_api_patterns = [
                                r"JSON\.parse\s*\(\s*(this\.)?response(Text|Body)",
                                r"JSON\.parse\s*\(\s*\w+\.response(Text|Body)",
                                r"JSON\.parse\s*\(\s*(await\s+)?fetch\s*\(",
                                r"JSON\.parse\s*\(\s*axios\.(get|post|put|delete)",
                                r"JSON\.parse\s*\(\s*\.then\s*\(",
                                r"JSON\.parse\s*\(\s*\.json\s*\(",
                                r"JSON\.parse\s*\(\s*response\.(text|body|data)",
                                r"JSON\.parse\s*\(\s*result\.(text|body|data)",
                            ]
                            if any(re.search(pattern, code_only_line, re.IGNORECASE) for pattern in safe_api_patterns):
                                continue  # 跳过，这是安全的API响应处理

                            # 【P1优化2】Node.js/Express标准操作 - 扩展上下文检查
                            context_start = max(0, line_idx - 5)
                            context_end = min(len(lines), line_idx + 5)
                            context_lines = "\n".join(lines[context_start:context_end])

                            # Express/Node.js 标准模式：JSON.parse(req.body), JSON.parse(body)
                            if re.search(
                                r"JSON\.parse\s*\(\s*(req\.body|body|request\.body)", code_only_line, re.IGNORECASE
                            ):
                                # 检查上下文是否包含Express/Node.js关键词
                                express_keywords = [
                                    "app.",
                                    "router.",
                                    "express.",
                                    "req.",
                                    "res.",
                                    "next(",
                                    "middleware",
                                    "app.use",
                                    "app.post",
                                    "app.get",
                                    "router.post",
                                    "router.get",
                                ]
                                if any(keyword in context_lines.lower() for keyword in express_keywords):
                                    continue  # 跳过，这是Express标准操作

                            # 【P1优化3】检查是否是函数定义（不是函数调用）
                            # 函数定义：function parseJSON() 或 async function parseJSON()
                            if re.search(r"^\s*(async\s+)?function\s+\w*[Pp]arse", code_only_line, re.IGNORECASE):
                                continue  # 跳过函数定义

                            # 【P1优化4】检查是否是变量赋值（不是函数调用）
                            # var json = JSON.parse(...) 或 const json = JSON.parse(...)
                            # 这种情况通常是安全的，因为JSON.parse本身不是漏洞
                            # 只有在配合原型污染时才危险，需要更深入的污点分析
                            # 这里先降级为Low或跳过，因为误报率太高
                            if re.search(r"(var|let|const)\s+\w+\s*=\s*JSON\.parse", code_only_line, re.IGNORECASE):
                                # 检查是否是处理不可信数据
                                untrusted_patterns = [
                                    r"localStorage",
                                    r"sessionStorage",
                                    r"document\.cookie",
                                    r"location\.(search|hash)",
                                    r"window\.name",
                                    r"postMessage",
                                ]
                                if not any(
                                    re.search(pattern, code_only_line, re.IGNORECASE) for pattern in untrusted_patterns
                                ):
                                    # 不是处理不可信数据，跳过或降级
                                    continue  # 跳过安全的JSON.parse使用

                            # 【P1优化5】完全排除localStorage和sessionStorage的JSON.parse
                            # 在现代Web安全视角下，解析本地存储的JSON是安全的
                            # 除非能证明攻击者能控制localStorage（那通常意味着已经有XSS了）
                            # 如果已经有XSS，那JSON.parse不是主要问题
                            if re.search(
                                r"JSON\.parse\s*\(\s*(localStorage|sessionStorage)", code_only_line, re.IGNORECASE
                            ):
                                continue  # 完全跳过，不是漏洞

                            # 只有处理URL参数、用户输入等不可信数据时才报告
                            untrusted_sources = [
                                r"location\.(search|hash)",
                                r"window\.name",
                                r"postMessage",
                                r"URLSearchParams",
                                r"req\.(query|params|body)",  # Express请求参数
                                r"request\.(query|params|body)",  # 通用请求参数
                                r"document\.cookie",  # Cookie可能被攻击者控制
                            ]
                            if not any(
                                re.search(pattern, code_only_line, re.IGNORECASE) for pattern in untrusted_sources
                            ):
                                # 不是处理不可信数据，跳过
                                continue

                    # 【优化案例B】XSS 特殊处理：检查上下文（json_encode、header() 设置等）
                    if vuln_type == "XSS_RISK":
                        if language == "php":
                            # header("location:") 是 Open Redirect（CWE-601），不归 XSS
                            if _RE_OPEN_REDIRECT_HDR.search(line):
                                continue

                            # 普通上下文：前10行 + 后5行
                            context_start = max(0, line_idx - 10)
                            context_end = min(len(lines), line_idx + 5)
                            context_lines = "\n".join(lines[context_start:context_end])

                            if _RE_PHP_JSON_ENCODE.search(context_lines):
                                continue  # json_encode 输出，安全
                            if _RE_PHP_HTMLSPECIAL.search(context_lines):
                                continue  # htmlspecialchars / htmlentities，安全
                            if _RE_PHP_FILTER_SANIT.search(context_lines):
                                continue  # filter_var(FILTER_SANITIZE)，安全
                            if _RE_PHP_CONTENT_JSON.search(context_lines):
                                continue  # Content-Type: application/json，安全

                            # echo $response['...']：$response 由内部方法构造，扫全文件确认
                            if re.search(r"\becho\s+\$response\s*\[", line, re.IGNORECASE):
                                full_code = "\n".join(lines)
                                if _RE_PHP_RESP_JSONENC.search(full_code) or _RE_PHP_RESP_METHOD.search(full_code):
                                    continue  # 内部 API 响应，跳过

                            # XSS 类型判断：区分 Reflected / Stored
                            if _RE_PHP_DB_QUERY.search(context_lines):
                                pass  # Stored XSS，保持 High
                            elif _RE_PHP_USER_INPUT.search(context_lines):
                                severity = "Medium"  # Reflected XSS

                    # 【修复案例C + 问题1】RCE 命令执行特殊处理：排除数组定义、字符串字面量和RegExp.exec()
                    if vuln_type == "RCE_COMMAND_EXEC":
                        # 检查原始行是否在字符串字面量中（简单检查）
                        original_line = line.strip()

                        # PHP 中的 fpassthru() 是文件读取/输出函数，不是命令执行，避免误报为 RCE
                        if language == "php" and _RE_PHP_FPASSTHRU.search(code_only_line):
                            continue

                        # ── 业务形态感知 ①：安装/初始化脚本降级 ──
                        # setup.php / install.php / migrate.php 等运维脚本里的 shell_exec 通常
                        # 不含用户可控输入，不属于可被攻击者利用的 RCE，降级为 Low。
                        if file_path:
                            _basename = file_path.lower().replace("\\", "/").split("/")[-1]
                            _setup_names = (
                                "setup",
                                "install",
                                "migrate",
                                "upgrade",
                                "seed",
                                "bootstrap",
                                "fixture",
                                "deploy",
                                "init",
                            )
                            if any(_basename.startswith(n) or _basename == n + ".php" for n in _setup_names):
                                _near = "\n".join(lines[max(0, line_idx - 5) : line_idx + 3])
                                if not _RE_PHP_USER_INPUT.search(_near):
                                    severity = "Low"

                        # ── 业务形态感知 ②：调用前存在通用输入校验 → 降级 Medium ──
                        # 替代原来 DVWA 硬编码的 3 个模式，改为检测调用前是否存在任意
                        # 数值/格式校验函数，泛化到真实项目中常见的防御写法。
                        if language == "php" and _RE_PHP_SHELL_EXEC.search(code_only_line):
                            ctx_start = max(0, line_idx - 30)
                            ctx = "\n".join(lines[ctx_start:line_idx])
                            if _RE_PHP_VALIDATION.search(ctx):
                                severity = "Medium"
                                impossible_rce_note = True

                        # 【修复问题1】排除 RegExp.exec() - 这是正则表达式方法，不是命令执行
                        if language in ["javascript", "typescript"]:
                            # 方法1：检查是否是正则表达式字面量后跟.exec()
                            if _RE_JS_REGEX_EXEC.search(original_line):
                                continue  # 跳过，这是正则表达式方法

                            # 方法2：检查变量名后跟.exec()，且上下文中有正则表达式
                            if re.search(r"\w+\.exec\s*\(", code_only_line):
                                # 检查上下文：如果前面是正则表达式字面量或RegExp对象，跳过
                                context_start = max(0, line_idx - 3)
                                context_end = min(len(lines), line_idx + 1)
                                context_lines = "\n".join(lines[context_start:context_end])

                                # 如果包含正则表达式模式（/.../ 或 RegExp 或 new RegExp），跳过
                                if re.search(r"/.*/|RegExp|new RegExp", context_lines, re.IGNORECASE):
                                    continue  # 跳过，这是正则表达式方法，不是命令执行

                                # 如果变量名包含 regex、pattern、reg 等关键词，可能是正则表达式
                                var_match = re.search(r"(\w+)\.exec\s*\(", code_only_line)
                                if var_match:
                                    var_name = var_match.group(1).lower()
                                    if any(
                                        keyword in var_name
                                        for keyword in ["regex", "pattern", "reg", "match", "color", "rgb"]
                                    ):
                                        continue  # 跳过，可能是正则表达式变量

                            # 方法3：确保只检测真正的命令执行：child_process.exec, shell_exec等
                            # 如果只是简单的 exec()，且不在 child_process 上下文中，可能是误报
                            if re.search(r"^\s*\w+\.exec\s*\(", code_only_line):
                                # 检查是否是真正的命令执行函数
                                if not re.search(
                                    r"child_process|shell_exec|Runtime\.getRuntime|ProcessBuilder",
                                    code_only_line,
                                    re.IGNORECASE,
                                ):
                                    # 可能是 RegExp.exec()，跳过
                                    continue

                            # 方法4：如果匹配的是 r"\bexec\s*\(" 规则，且不在命令执行上下文中，跳过
                            # 检查原始行：如果是 /regex/.exec() 模式，跳过
                            if re.search(r"/.*/\.exec\s*\(", original_line):
                                continue

                        # 检查是否是数组定义（如 var a=['fromCharCode'...]）
                        # 数组定义本身不是RCE，只有调用这些函数才是
                        if re.search(r"var\s+\w+\s*=\s*\[", original_line, re.IGNORECASE):
                            # 如果只是数组定义，且没有实际调用 eval/exec，跳过
                            # 检查是否在同一行或附近有实际调用
                            context_start = max(0, line_idx)
                            context_end = min(len(lines), line_idx + 3)
                            context_lines = "\n".join(lines[context_start:context_end])
                            # 如果没有实际的函数调用（eval(...), exec(...)），跳过
                            if not re.search(r"\b(eval|exec|system|shell_exec)\s*\(", context_lines, re.IGNORECASE):
                                continue  # 跳过，这只是数组定义，不是实际的RCE调用

                        # 检查是否在 HTML 标签或 PHP echo/print 的字符串中
                        if _RE_HTML_TAG_RCE.search(original_line):
                            continue
                        if _RE_ECHO_PRINT_RCE.search(original_line):
                            continue

                    # OPEN_REDIRECT 后处理：
                    # 若 header("location: " . $localVar) 中的变量不是 $_GET/$_POST 等超全局变量，
                    # 检查上下文中该变量是否从用户输入派生。若上下文只有硬编码赋值（switch/case 等），
                    # 则视为安全（如 impossible.php 中的 $target）。
                    if vuln_type == "OPEN_REDIRECT" and language == "php":
                        raw = line.strip()
                        # 若行中直接含超全局变量，肯定是开放重定向，保留
                        if _RE_PHP_USER_INPUT.search(raw):
                            pass  # 直接来自用户输入，保留
                        else:
                            # 提取 header 调用里最后一个 $ 变量名
                            _var_m = re.search(r"\.\s*(\$\w+)\s*[;)]", raw)
                            if _var_m:
                                _var = re.escape(_var_m.group(1))
                                # 在前 20 行查该变量是否被赋予用户输入
                                _ctx = "\n".join(lines[max(0, line_idx - 20) : line_idx])
                                _user_assign = re.search(
                                    rf"{_var}\s*=\s*.*\$_(GET|POST|REQUEST|COOKIE)", _ctx, re.IGNORECASE
                                )
                                if not _user_assign:
                                    continue  # 变量无用户输入来源，跳过

                    content_for_finding = line.strip()
                    if impossible_rce_note:
                        content_for_finding = content_for_finding + " （检测到输入校验，建议人工确认）"
                    findings.append(
                        {
                            "type": vuln_type,
                            "line": line_num,
                            "content": content_for_finding,
                            "severity": severity,  # 使用定义的严重程度
                            "confidence": "Medium",  # 规则匹配通常是中等置信度
                        }
                    )
                    break  # 同一行同一种漏洞只报一次

    return findings
