"""
rag_enhancer.py - RAG 增强模块

将扫描结果关联 CVE 知识库，为每个漏洞添加：
- 相关的 CVE 信息
- 修复建议
- 参考链接

设计原则：
- 轻量级：不强制依赖 ChromaDB，支持降级
- 实用性：即使没有 RAG，也能提供基本的修复建议
- 可扩展：支持自定义知识库
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Any, Protocol, cast

logger = logging.getLogger(__name__)


class SupportsCountCollection(Protocol):
    def count(self) -> int: ...


# 内置修复建议（不依赖外部 RAG）
BUILTIN_REMEDIATION = {
    "SQL_INJECTION": {
        "description": "SQL 注入漏洞允许攻击者通过操纵 SQL 查询来访问或修改数据库内容。",
        "remediation": [
            "使用参数化查询（Prepared Statements）",
            "使用 ORM 框架（如 SQLAlchemy, Sequelize）",
            "对用户输入进行严格的白名单验证",
            "使用最小权限原则配置数据库账户",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
        "cwe": "CWE-89",
        # 通用示例（无框架信息时使用）
        "suggested_code": (
            "// ✅ 参数化查询示例（根据项目框架选择对应方式）\n\n"
            "// ── mysql2（Node.js）──\n"
            "const [rows] = await connection.execute(\n"
            "  'SELECT * FROM users WHERE id = ?',\n"
            "  [userId]\n"
            ");\n\n"
            "// ── Sequelize（Node.js ORM）──\n"
            "const user = await User.findOne({ where: { id: userId } });\n\n"
            "// ── pymysql / psycopg2（Python）──\n"
            "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n\n"
            "// ── SQLAlchemy（Python ORM）──\n"
            "result = db.execute(text('SELECT * FROM users WHERE id = :id'), {'id': user_id})"
        ),
        # 框架专用示例（LSP hover / Code Action 按需选择）
        "framework_suggested_code": {
            "mysql2": (
                "// mysql2 参数化查询\n"
                "const [rows] = await connection.execute(\n"
                "  'SELECT * FROM users WHERE id = ?',\n"
                "  [userId]\n"
                ");"
            ),
            "mysql": (
                "// mysql 参数化查询（回调风格）\n"
                "connection.query(\n"
                "  'SELECT * FROM users WHERE id = ?',\n"
                "  [userId],\n"
                "  (err, results) => { /* ... */ }\n"
                ");"
            ),
            "sequelize": (
                "// Sequelize ORM 安全查询\n"
                "const user = await User.findOne({ where: { id: userId } });\n"
                "// 需要原始 SQL 时:\n"
                "const [results] = await sequelize.query(\n"
                "  'SELECT * FROM users WHERE id = :id',\n"
                "  { replacements: { id: userId } }\n"
                ");"
            ),
            "knex": (
                "// Knex 查询构建器（自动参数化）\nconst user = await knex('users').where({ id: userId }).first();"
            ),
            "typeorm": (
                "// TypeORM 参数化查询\n"
                "const user = await userRepository.findOne({ where: { id: userId } });\n"
                "// 原始查询:\n"
                "const result = await dataSource.query(\n"
                "  'SELECT * FROM users WHERE id = $1',\n"
                "  [userId]\n"
                ");"
            ),
            "prisma": (
                "// Prisma ORM（自动参数化）\nconst user = await prisma.user.findUnique({ where: { id: userId } });"
            ),
            "pymysql": (
                "# pymysql 参数化查询\n"
                "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
                "rows = cursor.fetchall()"
            ),
            "psycopg2": (
                "# psycopg2 参数化查询\n"
                "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
                "rows = cursor.fetchall()"
            ),
            "sqlalchemy": (
                "# SQLAlchemy ORM 安全查询\n"
                "user = session.get(User, user_id)\n"
                "# 原始 SQL 时使用 text() 绑定参数:\n"
                "from sqlalchemy import text\n"
                "result = db.execute(text('SELECT * FROM users WHERE id = :id'), {'id': user_id})"
            ),
            "django-orm": (
                "# Django ORM（自动参数化）\n"
                "user = User.objects.get(pk=user_id)\n"
                "# 原始 SQL:\n"
                "User.objects.raw('SELECT * FROM users WHERE id = %s', [user_id])"
            ),
            "jdbc": (
                "// Java: JDBC PreparedStatement 参数化查询\n"
                'String sql = "SELECT * FROM users WHERE id = ?";\n'
                "try (PreparedStatement ps = connection.prepareStatement(sql)) {\n"
                "    ps.setInt(1, userId);\n"
                "    try (ResultSet rs = ps.executeQuery()) {\n"
                "        // TODO: 处理结果集\n"
                "    }\n"
                "}"
            ),
            "spring": (
                "// Java: Spring JdbcTemplate 参数化查询\n"
                'String sql = "SELECT * FROM users WHERE id = ?";\n'
                "User user = jdbcTemplate.queryForObject(\n"
                "    sql,\n"
                "    new Object[] { userId },\n"
                "    (rs, rowNum) -> mapUser(rs)\n"
                ");"
            ),
            "hibernate": (
                "// Java: Hibernate HQL 参数化查询\n"
                'String hql = "FROM User u WHERE u.id = :id";\n'
                "User user = session.createQuery(hql, User.class)\n"
                '    .setParameter("id", userId)\n'
                "    .uniqueResult();"
            ),
            "mybatis": (
                "// Java: MyBatis 使用 #{id} 占位符（自动参数化）\n"
                "// Mapper XML:\n"
                '// <select id="findUser" resultType="User">\n'
                "//   SELECT * FROM users WHERE id = #{id}\n"
                "// </select>\n"
                "User user = userMapper.findUser(userId);"
            ),
        },
    },
    "NOSQL_INJECTION": {
        "description": "NoSQL 注入漏洞允许攻击者通过操纵 NoSQL 查询（如 MongoDB）来绕过认证或访问敏感数据。",
        "remediation": [
            "避免直接将用户输入传入查询条件",
            "使用 ODM 框架（如 Mongoose）的安全方法",
            "禁用或限制危险操作符（$where, $ne 等）",
            "对查询参数进行类型检查和白名单验证",
        ],
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
            "https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html",
        ],
        "cwe": "CWE-943",
        "suggested_code": (
            "// ✅ NoSQL 注入防御示例\n\n"
            "// ── Mongoose（推荐方式）──\n"
            "// 严格类型检查后再查询\n"
            "if (typeof username !== 'string') throw new Error('Invalid input');\n"
            "const user = await User.findOne({ username: username }).lean();\n\n"
            "// ── 原生 MongoDB Driver ──\n"
            "// 强制转换为字符串，禁止对象类型注入\n"
            "const safeId = String(req.body.id);\n"
            "const result = await collection.findOne({ _id: new ObjectId(safeId) });"
        ),
        "framework_suggested_code": {
            "mongoose": (
                "// Mongoose 安全查询\n"
                "// 1. 严格类型校验\n"
                "if (typeof username !== 'string' || !username.trim()) {\n"
                "  return res.status(400).json({ error: 'Invalid username' });\n"
                "}\n"
                "// 2. 使用 Mongoose 模型查询（自动转义）\n"
                "const user = await User.findOne({ username: username.trim() }).lean();"
            ),
            "mongodb": (
                "// 原生 MongoDB Driver 安全查询\n"
                "const { ObjectId } = require('mongodb');\n"
                "// 强制类型转换防止操作符注入\n"
                "const safeQuery = {\n"
                "  username: String(req.body.username),\n"
                "};\n"
                "const user = await collection.findOne(safeQuery);"
            ),
        },
    },
    "RCE_COMMAND_EXEC": {
        "description": "远程代码执行漏洞允许攻击者在服务器上执行任意代码或命令。",
        "remediation": [
            "避免使用 eval()、exec()、system() 等危险函数",
            "如必须执行外部命令，使用白名单验证",
            "使用沙箱环境隔离代码执行",
            "对用户输入进行严格的转义和验证",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/Command_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        ],
        "cwe": "CWE-78",
        "suggested_code": (
            "// ✅ 避免命令注入\n\n"
            "// ── Node.js：用 execFile + 参数数组替代 exec ──\n"
            "const { execFile } = require('child_process');\n"
            "const ALLOWED_CMDS = ['ls', 'pwd'];\n"
            "if (!ALLOWED_CMDS.includes(cmd)) throw new Error('Disallowed command');\n"
            "execFile(cmd, [], (err, stdout) => { /* 安全 */ });\n\n"
            "// ── Python：用列表参数替代 shell=True ──\n"
            "import subprocess\n"
            "result = subprocess.run(['ls', '-la', safe_path], capture_output=True, text=True)\n\n"
            "// ── 避免 eval() 动态执行 ──\n"
            "// 将 eval(\"require('crypto')\") 改为直接 require('crypto')"
        ),
        "framework_suggested_code": {
            "child_process": (
                "// Node.js: 用 execFile + 参数数组替代 exec\n"
                "const { execFile } = require('child_process');\n"
                "const ALLOWED_CMDS = ['ls', 'pwd'];\n"
                "if (!ALLOWED_CMDS.includes(cmd)) throw new Error('Disallowed');\n"
                "execFile(cmd, [], (err, stdout) => { /* 安全 */ });"
            ),
            "subprocess": (
                "# Python: 用列表参数替代 shell=True\n"
                "import subprocess\n"
                "result = subprocess.run(['ls', '-la', safe_path], capture_output=True, text=True)"
            ),
            "escapeshellarg": (
                "// PHP: 使用 escapeshellarg 转义参数\n$safe = escapeshellarg($user_input);\nexec('ls ' . $safe);"
            ),
        },
    },
    "XSS": {
        "description": "跨站脚本攻击允许攻击者在用户浏览器中执行恶意脚本。",
        "remediation": [
            "对所有输出进行 HTML 实体编码",
            "使用 Content-Security-Policy (CSP) 头",
            "使用框架自带的 XSS 防护（如 Angular 的 DomSanitizer）",
            "避免使用 innerHTML、document.write 等危险 API",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
        "cwe": "CWE-79",
        "suggested_code": (
            "// ✅ XSS 防御示例\n\n"
            "// ── 前端：避免 innerHTML，使用 textContent ──\n"
            "element.textContent = userInput;  // 安全\n"
            "// 或使用 DOMPurify 净化后插入:\n"
            "element.innerHTML = DOMPurify.sanitize(userInput);\n\n"
            "// ── Node.js/Express 服务端输出 ──\n"
            "const he = require('he');\n"
            "res.send(`<p>${he.encode(userInput)}</p>`);\n\n"
            "// ── Angular（DomSanitizer）──\n"
            "// 在模板中使用 {{ userInput }}（自动转义），\n"
            "// 避免 [innerHTML]，若必须使用则:\n"
            "// this.sanitizer.bypassSecurityTrustHtml(content)"
        ),
        "framework_suggested_code": {
            "dompurify": ("// DOMPurify 净化后插入\nelement.innerHTML = DOMPurify.sanitize(userInput);"),
            "he": (
                "// Node.js 服务端: he 编码\nconst he = require('he');\nres.send(`<p>${he.encode(userInput)}</p>`);"
            ),
            "dom_sanitizer": (
                "// Angular: 模板中 {{ userInput }} 自动转义\n"
                "// 必须用 [innerHTML] 时: this.sanitizer.sanitize(SecurityContext.HTML, content)"
            ),
            "html_escape": ("# Python: html.escape\nimport html\nsafe = html.escape(user_input)"),
            "markupsafe": ("# Jinja2 / MarkupSafe\nfrom markupsafe import escape\nsafe = escape(user_input)"),
            "htmlspecialchars": ("// PHP: 输出前转义\necho htmlspecialchars($var, ENT_QUOTES, 'UTF-8');"),
        },
    },
    "PATH_TRAVERSAL": {
        "description": "路径穿越漏洞允许攻击者访问服务器上的任意文件。",
        "remediation": [
            "对文件路径进行规范化（canonicalize）",
            "验证文件路径是否在允许的目录内",
            "使用白名单限制可访问的文件",
            "避免直接使用用户输入构造文件路径",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
        ],
        "cwe": "CWE-22",
        "suggested_code": (
            "// ✅ 路径穿越防御\n\n"
            "// ── Node.js ──\n"
            "const path = require('path');\n"
            "const BASE_DIR = path.resolve('/var/www/uploads');\n"
            "const requested = path.resolve(BASE_DIR, req.params.filename);\n"
            "if (!requested.startsWith(BASE_DIR + path.sep)) {\n"
            "  return res.status(403).send('Forbidden');\n"
            "}\n"
            "// 安全读取\n"
            "fs.readFile(requested, 'utf8', callback);\n\n"
            "# ── Python ──\n"
            "import os\n"
            "BASE_DIR = os.path.realpath('/var/www/uploads')\n"
            "requested = os.path.realpath(os.path.join(BASE_DIR, filename))\n"
            "if not requested.startswith(BASE_DIR + os.sep):\n"
            "    raise PermissionError('Path traversal detected')"
        ),
        "framework_suggested_code": {
            "path_resolve": (
                "// Node.js: path.resolve + startsWith 校验\n"
                "const path = require('path');\n"
                "const BASE_DIR = path.resolve('/var/www/uploads');\n"
                "const requested = path.resolve(BASE_DIR, req.params.filename);\n"
                "if (!requested.startsWith(BASE_DIR + path.sep)) return res.status(403).send('Forbidden');\n"
                "fs.readFile(requested, 'utf8', callback);"
            ),
            "os_path": (
                "# Python: os.path.realpath + startswith\n"
                "import os\n"
                "BASE_DIR = os.path.realpath('/var/www/uploads')\n"
                "requested = os.path.realpath(os.path.join(BASE_DIR, filename))\n"
                "if not requested.startswith(BASE_DIR + os.sep):\n"
                "    raise PermissionError('Path traversal detected')"
            ),
            "basename_realpath": (
                "// PHP: basename 或 realpath 限制在目录内\n"
                "$base = realpath('/var/www/uploads');\n"
                "$file = $base . '/' . basename($_GET['file']);\n"
                "if (strpos(realpath($file), $base) !== 0) exit('Forbidden');\n"
                "readfile($file);"
            ),
            "database_sql": (
                "// Go: database/sql 使用占位符参数\n"
                'row := db.QueryRow("SELECT * FROM users WHERE id = ?", userID)\n'
                "var user User\n"
                "if err := row.Scan(&user.ID, &user.Name); err != nil {\n"
                "    // 处理错误\n"
                "}"
            ),
            "gorm": (
                "// Go: GORM 查询（自动参数化）\n"
                "var user User\n"
                'if err := db.Where("id = ?", userID).First(&user).Error; err != nil {\n'
                "    // 处理错误\n"
                "}"
            ),
        },
    },
    "HARDCODED_CREDENTIALS": {
        "description": "硬编码凭证会导致敏感信息泄露，攻击者可利用这些凭证访问系统。",
        "remediation": [
            "使用环境变量存储敏感信息",
            "使用配置管理工具（如 Vault、AWS Secrets Manager）",
            "在代码审查中检查敏感信息",
            "使用 .gitignore 排除配置文件",
        ],
        "references": [
            "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        ],
        "cwe": "CWE-798",
        "suggested_code": (
            "// 使用环境变量或密钥管理服务\n"
            "// Node: process.env.DB_PASSWORD\n"
            "# Python: os.environ.get('DB_PASSWORD')\n"
            "// PHP: getenv('DB_PASSWORD')"
        ),
        "framework_suggested_code": {
            "process_env": ("// Node.js: 环境变量\nconst password = process.env.DB_PASSWORD;"),
            "os_environ": ("# Python: 环境变量\nimport os\npassword = os.environ.get('DB_PASSWORD')"),
            "getenv": ("// PHP: getenv\n$password = getenv('DB_PASSWORD');"),
            "dotenv": (
                "// 通用: .env 文件（不要提交到 Git）\n"
                "// Node: require('dotenv').config(); process.env.KEY\n"
                "# Python: python-dotenv 加载 .env"
            ),
        },
    },
    "DESERIALIZATION": {
        "description": "不安全的反序列化可能导致远程代码执行或拒绝服务攻击。",
        "remediation": [
            "避免反序列化不受信任的数据",
            "使用安全的序列化格式（如 JSON）",
            "实现严格的类型检查",
            "使用签名或加密验证序列化数据的完整性",
        ],
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.5-Testing_for_HTTP_Incoming_Requests",
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
        ],
        "cwe": "CWE-502",
        "suggested_code": (
            "// 使用 JSON 等安全格式替代 pickle/unserialize\n"
            "// JS: JSON.parse()\n"
            "# Python: json.loads() / yaml.safe_load()\n"
            "// PHP: json_decode()"
        ),
        "framework_suggested_code": {
            "json_parse": ("// JavaScript: 使用 JSON 替代不安全反序列化\nconst data = JSON.parse(userInput);"),
            "json_loads": ("# Python: json.loads\nimport json\ndata = json.loads(user_input)"),
            "json_decode": ("// PHP: json_decode 替代 unserialize\n$data = json_decode($input, true);"),
            "yaml_safe_load": (
                "# Python: yaml.safe_load（勿用 yaml.load）\nimport yaml\ndata = yaml.safe_load(user_input)"
            ),
            "gin": (
                "// Go: Gin 框架中安全绑定 JSON（并做字段校验）\n"
                "type LoginRequest struct {\n"
                '    Username string `json:"username" binding:"required"`\n'
                '    Password string `json:"password" binding:"required"`\n'
                "}\n"
                "var req LoginRequest\n"
                "if err := c.ShouldBindJSON(&req); err != nil {\n"
                '    c.JSON(400, gin.H{"error": "invalid input"})\n'
                "    return\n"
                "}"
            ),
            "echo": (
                "// Go: Echo 框架中安全绑定 JSON\n"
                "type LoginRequest struct {\n"
                '    Username string `json:"username" validate:"required"`\n'
                '    Password string `json:"password" validate:"required"`\n'
                "}\n"
                "var req LoginRequest\n"
                "if err := c.Bind(&req); err != nil {\n"
                '    return c.JSON(400, map[string]string{"error": "invalid input"})\n'
                "}"
            ),
        },
    },
    "OPEN_REDIRECT": {
        "description": "任意 URL 跳转（CWE-601）允许攻击者将受害者重定向到钓鱼或恶意站点，常被用于绕过安全检查。",
        "remediation": [
            "使用跳转目标白名单，只允许跳转到已知安全域名",
            "避免直接将 $_GET/$_POST 的值传给 header('location:')",
            "跳转前校验目标 URL 的域名是否属于本站",
            "使用枚举/映射替代直接传参（如 ?redirect=1 对应固定页面）",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/601.html",
        ],
        "cwe": "CWE-601",
        "suggested_code": (
            "// PHP 安全跳转示例：使用白名单\n"
            "$allowed = ['info.php', 'home.php', 'dashboard.php'];\n"
            "$target = $_GET['redirect'] ?? '';\n"
            "if (in_array($target, $allowed)) {\n"
            "    header('location: ' . $target);\n"
            "} else {\n"
            "    http_response_code(400);\n"
            "    exit('Invalid redirect target');\n"
            "}"
        ),
        "framework_suggested_code": {
            "url_whitelist_js": (
                "// JavaScript: 白名单校验 URL\n"
                "const allowedHosts = ['example.com'];\n"
                "const url = new URL(userRedirect);\n"
                "if (!allowedHosts.includes(url.hostname)) throw new Error('Invalid redirect');\n"
                "location.href = url.toString();"
            ),
            "url_has_allowed_host_and_scheme": (
                "# Django: url_has_allowed_host_and_scheme\n"
                "from django.utils.http import url_has_allowed_host_and_scheme\n"
                "if not url_has_allowed_host_and_scheme(redirect_to, allowed_hosts):\n"
                "    raise ValueError('Invalid redirect')"
            ),
            "in_array": (
                "// PHP: 白名单\n"
                "$allowed = ['info.php', 'home.php'];\n"
                "$target = $_GET['redirect'] ?? '';\n"
                "if (in_array($target, $allowed)) header('Location: ' . $target);\n"
                "else http_response_code(400);"
            ),
        },
    },
    "XSS_RISK": {
        "description": "跨站脚本攻击（XSS）允许攻击者在用户浏览器中执行恶意脚本，窃取会话或重定向用户。",
        "remediation": [
            "PHP: 使用 htmlspecialchars($var, ENT_QUOTES, 'UTF-8') 转义输出",
            "避免直接将 $_GET/$_POST 拼入 HTML，先经过净化函数",
            "使用 Content-Security-Policy 响应头限制脚本来源",
            "JS: 避免 innerHTML，改用 textContent 或 setAttribute",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
        "cwe": "CWE-79",
        "suggested_code": ("// PHP 安全输出示例\necho htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');"),
        "framework_suggested_code": {
            "htmlspecialchars": ("// PHP: 输出前转义\necho htmlspecialchars($var, ENT_QUOTES, 'UTF-8');"),
            "dompurify": ("// 前端: DOMPurify\nelement.innerHTML = DOMPurify.sanitize(userInput);"),
            "textcontent": ("// 安全: 使用 textContent 替代 innerHTML\nelement.textContent = userInput;"),
        },
    },
}


class RAGEnhancer:
    """
    RAG 增强器。

    功能：
    - 为扫描结果添加 CVE 相关信息
    - 提供修复建议
    - 支持 ChromaDB 知识库（可选）
    """

    def __init__(
        self,
        db_path: str | None = None,
        use_rag: bool = True,
        timeout_seconds: float = 5.0,
    ) -> None:
        """
        初始化 RAG 增强器。

        Args:
            db_path: ChromaDB 数据库路径（可选）
            use_rag: 是否使用 RAG 增强（默认 True）
            timeout_seconds: RAG 检索超时秒数（TDD 10.2），超时则仅跳过 RAG 不阻塞
        """
        self.use_rag = use_rag
        self.collection = None
        self.timeout_seconds = max(0.1, float(timeout_seconds))

        if use_rag and db_path:
            self._init_chromadb(db_path)

    def _init_chromadb(self, db_path: str) -> None:
        """初始化 ChromaDB 连接"""
        try:
            import chromadb

            client = chromadb.PersistentClient(path=db_path)
            self.collection = client.get_collection(name="cve_core")
            collection = cast(SupportsCountCollection, self.collection)
            logger.info("RAG 知识库已连接，包含 %d 条 CVE 记录", collection.count())
        except (RuntimeError, ValueError, KeyError, ImportError) as e:
            logger.warning("RAG 知识库连接失败: %s，将使用内置修复建议", e)
            self.collection = None

    def enhance_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        增强扫描结果。
        TDD 10.2：RAG 失败或超时时仅跳过增强，不阻塞、不丢弃已有 findings。
        """
        try:
            enhanced = []
            for finding in findings:
                enhanced_finding = self._enhance_single_finding(finding)
                enhanced.append(enhanced_finding)
            return enhanced
        except (OSError, UnicodeDecodeError, RuntimeError, ImportError) as e:
            logger.warning("RAG 增强过程异常，返回原始 findings: %s", e)
            return findings

    def _enhance_single_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """
        增强单个扫描结果。

        Args:
            finding: 原始扫描结果

        Returns:
            增强后的扫描结果
        """
        # 复制原始结果
        enhanced = finding.copy()

        # 获取漏洞类型
        vuln_type = finding.get("type", "UNKNOWN")

        # 添加内置修复建议
        builtin = BUILTIN_REMEDIATION.get(vuln_type, {})
        enhanced["remediation"] = {
            "description": builtin.get("description", ""),
            "suggestions": builtin.get("remediation", []),
            "references": builtin.get("references", []),
            "cwe": builtin.get("cwe", ""),
        }

        # 如果有 RAG 知识库，在超时内尝试获取相关 CVE（TDD 10.2）
        if self.collection:
            related_cves = self._query_related_cves_with_timeout(vuln_type, finding)
            enhanced["related_cves"] = related_cves
        else:
            enhanced["related_cves"] = []

        return enhanced

    def _query_related_cves_with_timeout(self, vuln_type: str, finding: dict[str, Any]) -> list[dict[str, Any]]:
        """
        带超时的 RAG 查询。超时或异常时返回 []，不阻塞、不丢弃已有 finding。
        """
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(self._query_related_cves, vuln_type, finding)
            try:
                return future.result(timeout=self.timeout_seconds)
            except FuturesTimeoutError:
                logger.warning(
                    "RAG 检索超时 (%.1fs)，跳过 CVE 增强: type=%s",
                    self.timeout_seconds,
                    vuln_type,
                )
                return []
            except (RuntimeError, ValueError, KeyError, ImportError) as e:
                logger.warning("RAG 检索异常，跳过 CVE 增强: %s", e)
                return []

    def _query_related_cves(self, vuln_type: str, finding: dict[str, Any]) -> list[dict[str, Any]]:
        """
        查询相关 CVE。

        Args:
            vuln_type: 漏洞类型
            finding: 扫描结果

        Returns:
            相关 CVE 列表
        """
        if not self.collection:
            return []

        try:
            # 构建查询
            query = f"{vuln_type} {finding.get('details', '')}"

            # 从 RAG 优化器导入
            from src.rag.rag_optimizer import optimized_rag_retrieval

            result = optimized_rag_retrieval(self.collection, query, top_k=5, return_top_n=3)

            if not result.get("has_match"):
                return []

            # 提取 CVE 信息
            cves = []
            for item, score in result.get("ranked_results", []):
                cves.append(
                    {
                        "cve_id": item.get("id", ""),
                        "description": item.get("document", "")[:200] + "...",
                        "relevance": round(score, 2),
                    }
                )

            return cves
        except (RuntimeError, ValueError, KeyError, ImportError) as e:
            logger.debug("CVE 查询失败: %s", e)
            return []

    def get_remediation_summary(self, findings: list[dict[str, Any]]) -> str:
        """
        生成修复建议摘要。

        Args:
            findings: 扫描结果列表

        Returns:
            修复建议摘要字符串
        """
        # 按漏洞类型分组
        by_type: dict[str, int] = {}
        for finding in findings:
            vuln_type = finding.get("type", "UNKNOWN")
            by_type[vuln_type] = by_type.get(vuln_type, 0) + 1

        lines = ["## 📋 修复建议摘要\n"]

        for vuln_type, count in sorted(by_type.items(), key=lambda x: -x[1]):
            builtin = BUILTIN_REMEDIATION.get(vuln_type, {})

            lines.append(f"### {vuln_type} ({count} 处)")
            lines.append(f"**描述**: {builtin.get('description', '未知漏洞类型')}")
            lines.append("")

            suggestions = builtin.get("remediation", [])
            if suggestions:
                lines.append("**修复建议**:")
                for i, suggestion in enumerate(suggestions, 1):
                    lines.append(f"  {i}. {suggestion}")

            refs = builtin.get("references", [])
            if refs:
                lines.append("")
                lines.append("**参考链接**:")
                for ref in refs:
                    lines.append(f"  - {ref}")

            lines.append("")

        return "\n".join(lines)


# 便捷函数
def enhance_scan_results(findings: list[dict[str, Any]], db_path: str | None = None) -> list[dict[str, Any]]:
    """
    便捷函数：增强扫描结果。

    Args:
        findings: 原始扫描结果列表
        db_path: ChromaDB 数据库路径（可选）

    Returns:
        增强后的扫描结果列表
    """
    enhancer = RAGEnhancer(db_path=db_path)
    return enhancer.enhance_findings(findings)


__all__ = ["RAGEnhancer", "enhance_scan_results", "BUILTIN_REMEDIATION"]
