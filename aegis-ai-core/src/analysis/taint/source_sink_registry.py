"""
source_sink_registry.py - 污点源/汇点注册表

定义：
- Source（污点源）：用户可控的输入点
- Sink（汇点）：敏感操作点
- Sanitizer（净化器）：清理污点的函数

按漏洞类型分类：
- SQL_INJECTION: SQL 注入相关的 Sink
- NOSQL_INJECTION: NoSQL 注入相关的 Sink
- RCE: 远程代码执行相关的 Sink
- XSS: 跨站脚本相关的 Sink
- PATH_TRAVERSAL: 路径穿越相关的 Sink
- DESERIALIZATION: 反序列化相关的 Sink
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Pattern
import re


class VulnCategory(Enum):
    """漏洞类型"""
    SQL_INJECTION = "sql_injection"
    NOSQL_INJECTION = "nosql_injection"
    RCE = "rce"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    DESERIALIZATION = "deserialization"
    SSRF = "ssrf"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    OPEN_REDIRECT = "open_redirect"


class TaintLevel(Enum):
    """污点级别"""
    CRITICAL = 4    # 极高风险（直接用户输入）
    HIGH = 3        # 高风险
    MEDIUM = 2      # 中风险
    LOW = 1         # 低风险
    CLEAN = 0       # 干净


@dataclass
class SourcePattern:
    """
    污点源模式。
    
    定义用户可控的输入点。
    """
    # 基本信息
    name: str                           # 模式名称
    pattern: str                        # 匹配模式（正则或字符串）
    is_regex: bool = False              # 是否使用正则
    
    # 分类
    languages: List[str] = field(default_factory=list)  # 适用语言
    taint_level: TaintLevel = TaintLevel.HIGH
    
    # 描述
    description: str = ""               # 描述
    example: str = ""                   # 示例
    
    # 编译后的正则（内部使用）
    _compiled: Optional[Pattern] = field(default=None, repr=False)
    
    def __post_init__(self):
        """编译正则表达式"""
        if self.is_regex and self._compiled is None:
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
    
    def matches(self, text: str) -> bool:
        """检查文本是否匹配此模式"""
        if self.is_regex:
            if self._compiled is None:
                self._compiled = re.compile(self.pattern, re.IGNORECASE)
            return bool(self._compiled.search(text))
        else:
            return self.pattern.lower() in text.lower()


@dataclass
class SinkPattern:
    """
    汇点模式。
    
    定义敏感操作点。
    """
    # 基本信息
    name: str                           # 模式名称
    pattern: str                        # 匹配模式（正则或字符串）
    is_regex: bool = False              # 是否使用正则
    
    # 分类
    category: VulnCategory = VulnCategory.RCE  # 漏洞类型
    languages: List[str] = field(default_factory=list)  # 适用语言
    severity: str = "High"              # 严重级别
    
    # 参数信息
    dangerous_arg_indices: List[int] = field(default_factory=list)  # 危险参数位置
    
    # 描述
    description: str = ""               # 描述
    cwe: str = ""                       # CWE 编号
    
    # 编译后的正则（内部使用）
    _compiled: Optional[Pattern] = field(default=None, repr=False)
    
    def __post_init__(self):
        """编译正则表达式"""
        if self.is_regex and self._compiled is None:
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
    
    def matches(self, text: str) -> bool:
        """检查文本是否匹配此模式"""
        if self.is_regex:
            if self._compiled is None:
                self._compiled = re.compile(self.pattern, re.IGNORECASE)
            return bool(self._compiled.search(text))
        else:
            return self.pattern.lower() in text.lower()


@dataclass
class SanitizerPattern:
    """
    净化器模式。
    
    定义清理污点的函数。
    """
    # 基本信息
    name: str                           # 模式名称
    pattern: str                        # 匹配模式
    is_regex: bool = False              # 是否使用正则
    
    # 分类
    sanitizes_categories: List[VulnCategory] = field(default_factory=list)  # 净化的漏洞类型
    languages: List[str] = field(default_factory=list)  # 适用语言
    
    # 描述
    description: str = ""               # 描述
    
    # 编译后的正则（内部使用）
    _compiled: Optional[Pattern] = field(default=None, repr=False)
    
    def matches(self, text: str) -> bool:
        """检查文本是否匹配此模式"""
        if self.is_regex:
            if self._compiled is None:
                self._compiled = re.compile(self.pattern, re.IGNORECASE)
            return bool(self._compiled.search(text))
        else:
            return self.pattern.lower() in text.lower()


class SourceSinkRegistry:
    """
    污点源/汇点注册表。
    
    管理所有 Source、Sink、Sanitizer 模式。
    
    使用示例：
        registry = SourceSinkRegistry()
        registry.load_defaults()
        
        # 检查是否是 Source
        if registry.is_source("req.body", "javascript"):
            ...
        
        # 检查是否是 Sink
        sink = registry.find_sink("eval(data)", "javascript")
        if sink:
            print(f"Found sink: {sink.category}")
    """
    
    def __init__(self):
        """初始化空的注册表"""
        self._sources: List[SourcePattern] = []
        self._sinks: List[SinkPattern] = []
        self._sanitizers: List[SanitizerPattern] = []
        
        # 按语言索引
        self._sources_by_lang: Dict[str, List[SourcePattern]] = {}
        self._sinks_by_lang: Dict[str, List[SinkPattern]] = {}
        self._sanitizers_by_lang: Dict[str, List[SanitizerPattern]] = {}
    
    def register_source(self, source: SourcePattern) -> None:
        """注册 Source 模式"""
        self._sources.append(source)
        for lang in source.languages or ["*"]:
            if lang not in self._sources_by_lang:
                self._sources_by_lang[lang] = []
            self._sources_by_lang[lang].append(source)
    
    def register_sink(self, sink: SinkPattern) -> None:
        """注册 Sink 模式"""
        self._sinks.append(sink)
        for lang in sink.languages or ["*"]:
            if lang not in self._sinks_by_lang:
                self._sinks_by_lang[lang] = []
            self._sinks_by_lang[lang].append(sink)
    
    def register_sanitizer(self, sanitizer: SanitizerPattern) -> None:
        """注册 Sanitizer 模式"""
        self._sanitizers.append(sanitizer)
        for lang in sanitizer.languages or ["*"]:
            if lang not in self._sanitizers_by_lang:
                self._sanitizers_by_lang[lang] = []
            self._sanitizers_by_lang[lang].append(sanitizer)
    
    def is_source(self, text: str, language: str = "*") -> bool:
        """检查文本是否匹配任何 Source 模式"""
        return self.find_source(text, language) is not None
    
    def find_source(self, text: str, language: str = "*") -> Optional[SourcePattern]:
        """查找匹配的 Source 模式"""
        # 检查特定语言的模式
        for source in self._sources_by_lang.get(language, []):
            if source.matches(text):
                return source
        
        # 检查通用模式
        for source in self._sources_by_lang.get("*", []):
            if source.matches(text):
                return source
        
        return None
    
    def is_sink(self, text: str, language: str = "*") -> bool:
        """检查文本是否匹配任何 Sink 模式"""
        return self.find_sink(text, language) is not None
    
    def find_sink(self, text: str, language: str = "*") -> Optional[SinkPattern]:
        """查找匹配的 Sink 模式"""
        # 检查特定语言的模式
        for sink in self._sinks_by_lang.get(language, []):
            if sink.matches(text):
                return sink
        
        # 检查通用模式
        for sink in self._sinks_by_lang.get("*", []):
            if sink.matches(text):
                return sink
        
        return None
    
    def find_sinks_by_category(
        self,
        category: VulnCategory,
        language: str = "*"
    ) -> List[SinkPattern]:
        """按漏洞类型查找 Sink 模式"""
        result = []
        for sink in self._sinks_by_lang.get(language, []):
            if sink.category == category:
                result.append(sink)
        for sink in self._sinks_by_lang.get("*", []):
            if sink.category == category:
                result.append(sink)
        return result
    
    def is_sanitizer(self, text: str, language: str = "*") -> bool:
        """检查文本是否匹配任何 Sanitizer 模式"""
        return self.find_sanitizer(text, language) is not None
    
    def find_sanitizer(self, text: str, language: str = "*") -> Optional[SanitizerPattern]:
        """查找匹配的 Sanitizer 模式"""
        for sanitizer in self._sanitizers_by_lang.get(language, []):
            if sanitizer.matches(text):
                return sanitizer
        for sanitizer in self._sanitizers_by_lang.get("*", []):
            if sanitizer.matches(text):
                return sanitizer
        return None
    
    def load_defaults(self) -> None:
        """加载默认的 Source/Sink/Sanitizer 模式"""
        self._load_javascript_sources()
        self._load_python_sources()
        self._load_php_sources()
        self._load_java_sources()
        self._load_go_sources()
        self._load_javascript_sinks()
        self._load_python_sinks()
        self._load_php_sinks()
        self._load_java_sinks()
        self._load_go_sinks()
        self._load_sanitizers()
        self._load_php_sanitizers()
        self._load_java_sanitizers()
        self._load_go_sanitizers()
    
    def _load_javascript_sources(self) -> None:
        """加载 JavaScript/TypeScript 的 Source 模式"""
        js_sources = [
            # Express.js
            SourcePattern(
                name="express_req_body",
                pattern="req.body",
                languages=["javascript", "typescript"],
                taint_level=TaintLevel.CRITICAL,
                description="Express 请求体",
                example="req.body.username",
            ),
            SourcePattern(
                name="express_req_query",
                pattern="req.query",
                languages=["javascript", "typescript"],
                taint_level=TaintLevel.CRITICAL,
                description="Express 查询参数",
                example="req.query.id",
            ),
            SourcePattern(
                name="express_req_params",
                pattern="req.params",
                languages=["javascript", "typescript"],
                taint_level=TaintLevel.CRITICAL,
                description="Express 路径参数",
                example="req.params.userId",
            ),
            SourcePattern(
                name="express_req_cookies",
                pattern="req.cookies",
                languages=["javascript", "typescript"],
                taint_level=TaintLevel.HIGH,
                description="Express Cookie",
                example="req.cookies.sessionId",
            ),
            SourcePattern(
                name="express_req_headers",
                pattern="req.headers",
                languages=["javascript", "typescript"],
                taint_level=TaintLevel.HIGH,
                description="Express 请求头",
                example="req.headers['x-forwarded-for']",
            ),
            
            # Koa.js
            SourcePattern(
                name="koa_ctx_request_body",
                pattern="ctx.request.body",
                languages=["javascript", "typescript"],
                taint_level=TaintLevel.CRITICAL,
                description="Koa 请求体",
            ),
            SourcePattern(
                name="koa_ctx_query",
                pattern="ctx.query",
                languages=["javascript", "typescript"],
                taint_level=TaintLevel.CRITICAL,
                description="Koa 查询参数",
            ),
            
            # 浏览器 API
            SourcePattern(
                name="location_search",
                pattern="location.search",
                languages=["javascript", "typescript"],
                taint_level=TaintLevel.CRITICAL,
                description="URL 查询字符串",
            ),
            SourcePattern(
                name="location_hash",
                pattern="location.hash",
                languages=["javascript", "typescript"],
                taint_level=TaintLevel.HIGH,
                description="URL 哈希",
            ),
            SourcePattern(
                name="document_cookie",
                pattern="document.cookie",
                languages=["javascript", "typescript"],
                taint_level=TaintLevel.HIGH,
                description="Document Cookie",
            ),
            SourcePattern(
                name="local_storage",
                pattern=r"localStorage\.(getItem|get)",
                is_regex=True,
                languages=["javascript", "typescript"],
                taint_level=TaintLevel.MEDIUM,
                description="LocalStorage",
            ),
            
            # Node.js
            SourcePattern(
                name="process_argv",
                pattern="process.argv",
                languages=["javascript", "typescript"],
                taint_level=TaintLevel.HIGH,
                description="命令行参数",
            ),
            SourcePattern(
                name="process_env",
                pattern="process.env",
                languages=["javascript", "typescript"],
                taint_level=TaintLevel.MEDIUM,
                description="环境变量",
            ),
        ]
        
        for source in js_sources:
            self.register_source(source)
    
    def _load_python_sources(self) -> None:
        """加载 Python 的 Source 模式"""
        py_sources = [
            # Flask
            SourcePattern(
                name="flask_request_form",
                pattern="request.form",
                languages=["python"],
                taint_level=TaintLevel.CRITICAL,
                description="Flask 表单数据",
            ),
            SourcePattern(
                name="flask_request_args",
                pattern="request.args",
                languages=["python"],
                taint_level=TaintLevel.CRITICAL,
                description="Flask 查询参数",
            ),
            SourcePattern(
                name="flask_request_json",
                pattern="request.json",
                languages=["python"],
                taint_level=TaintLevel.CRITICAL,
                description="Flask JSON 数据",
            ),
            SourcePattern(
                name="flask_request_data",
                pattern="request.data",
                languages=["python"],
                taint_level=TaintLevel.CRITICAL,
                description="Flask 原始数据",
            ),
            SourcePattern(
                name="flask_request_values",
                pattern="request.values",
                languages=["python"],
                taint_level=TaintLevel.CRITICAL,
                description="Flask 混合参数",
            ),
            SourcePattern(
                name="flask_request_cookies",
                pattern="request.cookies",
                languages=["python"],
                taint_level=TaintLevel.HIGH,
                description="Flask Cookie",
            ),
            
            # Django
            SourcePattern(
                name="django_request_get",
                pattern="request.GET",
                languages=["python"],
                taint_level=TaintLevel.CRITICAL,
                description="Django GET 参数",
            ),
            SourcePattern(
                name="django_request_post",
                pattern="request.POST",
                languages=["python"],
                taint_level=TaintLevel.CRITICAL,
                description="Django POST 参数",
            ),
            SourcePattern(
                name="django_request_files",
                pattern="request.FILES",
                languages=["python"],
                taint_level=TaintLevel.CRITICAL,
                description="Django 文件上传",
            ),
            
            # 标准库
            SourcePattern(
                name="sys_argv",
                pattern="sys.argv",
                languages=["python"],
                taint_level=TaintLevel.HIGH,
                description="命令行参数",
            ),
            SourcePattern(
                name="os_environ",
                pattern="os.environ",
                languages=["python"],
                taint_level=TaintLevel.MEDIUM,
                description="环境变量",
            ),
            SourcePattern(
                name="input_func",
                # 使用词边界正则，避免命中 validate_input( / user_input( 等函数名
                pattern=r"\binput\(",
                is_regex=True,
                languages=["python"],
                taint_level=TaintLevel.HIGH,
                description="标准输入",
            ),
        ]
        
        for source in py_sources:
            self.register_source(source)

    def _load_php_sources(self) -> None:
        """加载 PHP 的 Source 模式（超全局变量与 php://input）"""
        php_sources = [
            SourcePattern(
                name="php_get",
                pattern=r"\$_GET\s*\[",
                is_regex=True,
                languages=["php"],
                taint_level=TaintLevel.CRITICAL,
                description="PHP GET 参数",
            ),
            SourcePattern(
                name="php_post",
                pattern=r"\$_POST\s*\[",
                is_regex=True,
                languages=["php"],
                taint_level=TaintLevel.CRITICAL,
                description="PHP POST 参数",
            ),
            SourcePattern(
                name="php_request",
                pattern=r"\$_REQUEST\s*\[",
                is_regex=True,
                languages=["php"],
                taint_level=TaintLevel.CRITICAL,
                description="PHP REQUEST 参数",
            ),
            SourcePattern(
                name="php_cookie",
                pattern=r"\$_COOKIE\s*\[",
                is_regex=True,
                languages=["php"],
                taint_level=TaintLevel.HIGH,
                description="PHP Cookie",
            ),
            SourcePattern(
                name="php_server",
                pattern=r"\$_SERVER\s*\[",
                is_regex=True,
                languages=["php"],
                taint_level=TaintLevel.HIGH,
                description="PHP SERVER 变量",
            ),
            SourcePattern(
                name="php_files",
                pattern=r"\$_FILES\s*\[",
                is_regex=True,
                languages=["php"],
                taint_level=TaintLevel.CRITICAL,
                description="PHP 上传文件",
            ),
            SourcePattern(
                name="php_session",
                pattern=r"\$_SESSION\s*\[",
                is_regex=True,
                languages=["php"],
                taint_level=TaintLevel.HIGH,
                description="PHP Session",
            ),
            SourcePattern(
                name="php_input_stream",
                pattern=r'file_get_contents\s*\(\s*["\']php://input["\']',
                is_regex=True,
                languages=["php"],
                taint_level=TaintLevel.CRITICAL,
                description="PHP 原始输入流",
            ),
        ]
        for source in php_sources:
            self.register_source(source)

    def _load_java_sources(self) -> None:
        """加载 Java 的 Source 模式"""
        java_sources = [
            # Servlet API
            SourcePattern(
                name="java_http_servlet_request_get_parameter",
                pattern=r"\.getParameter\s*\(",
                is_regex=True,
                languages=["java"],
                taint_level=TaintLevel.CRITICAL,
                description="HttpServletRequest.getParameter / request.getParameter",
                example='request.getParameter("id")',
            ),
            SourcePattern(
                name="java_http_servlet_request_get_header",
                pattern=r"\.getHeader\s*\(",
                is_regex=True,
                languages=["java"],
                taint_level=TaintLevel.CRITICAL,
                description="HttpServletRequest.getHeader / request.getHeader",
            ),
            SourcePattern(
                name="java_http_servlet_request_get_cookies",
                pattern=r"\.getCookies\s*\(",
                is_regex=True,
                languages=["java"],
                taint_level=TaintLevel.HIGH,
                description="HttpServletRequest.getCookies / request.getCookies",
            ),

            # Spring MVC Annotations（主要为规则层提供上下文）
            SourcePattern(
                name="java_spring_request_param",
                pattern="@RequestParam",
                languages=["java"],
                taint_level=TaintLevel.CRITICAL,
                description="Spring @RequestParam 注解",
            ),
            SourcePattern(
                name="java_spring_request_body",
                pattern="@RequestBody",
                languages=["java"],
                taint_level=TaintLevel.CRITICAL,
                description="Spring @RequestBody 注解",
            ),

            # 标准输入
            SourcePattern(
                name="java_scanner_stdin",
                pattern="System.in",
                languages=["java"],
                taint_level=TaintLevel.HIGH,
                description="Scanner(System.in) 标准输入",
            ),
        ]
        for source in java_sources:
            self.register_source(source)

    def _load_go_sources(self) -> None:
        """加载 Go 的 Source 模式"""
        go_sources = [
            # net/http Request
            SourcePattern(
                name="go_http_url_query",
                pattern=r"\.URL\.Query\(",
                is_regex=True,
                languages=["go"],
                taint_level=TaintLevel.CRITICAL,
                description="net/http: r.URL.Query()",
            ),
            SourcePattern(
                name="go_http_form_value",
                pattern=r"\.FormValue\s*\(",
                is_regex=True,
                languages=["go"],
                taint_level=TaintLevel.CRITICAL,
                description="net/http: r.FormValue()",
            ),
            SourcePattern(
                name="go_http_header_get",
                pattern=r"\.Header\.Get\s*\(",
                is_regex=True,
                languages=["go"],
                taint_level=TaintLevel.HIGH,
                description="net/http: r.Header.Get()",
            ),
            SourcePattern(
                name="go_http_body",
                pattern=r"\.Body\b",
                is_regex=True,
                languages=["go"],
                taint_level=TaintLevel.CRITICAL,
                description="net/http: r.Body（原始请求体）",
            ),
            # 命令行参数
            SourcePattern(
                name="go_os_args",
                pattern="os.Args",
                languages=["go"],
                taint_level=TaintLevel.HIGH,
                description="os.Args 命令行参数",
            ),
        ]
        for source in go_sources:
            self.register_source(source)
    
    def _load_javascript_sinks(self) -> None:
        """加载 JavaScript/TypeScript 的 Sink 模式"""
        js_sinks = [
            # RCE
            SinkPattern(
                name="eval",
                pattern="eval(",
                category=VulnCategory.RCE,
                languages=["javascript", "typescript"],
                severity="Critical",
                description="代码执行",
                cwe="CWE-94",
            ),
            SinkPattern(
                name="function_constructor",
                pattern="Function(",
                category=VulnCategory.RCE,
                languages=["javascript", "typescript"],
                severity="Critical",
                description="动态函数创建",
                cwe="CWE-94",
            ),
            SinkPattern(
                name="child_process_exec",
                pattern=r"(exec|execSync|spawn|spawnSync)\(",
                is_regex=True,
                category=VulnCategory.RCE,
                languages=["javascript", "typescript"],
                severity="Critical",
                description="命令执行",
                cwe="CWE-78",
            ),
            SinkPattern(
                name="vm_run",
                pattern=r"vm\.runIn(NewContext|Context|ThisContext)\(",
                is_regex=True,
                category=VulnCategory.RCE,
                languages=["javascript", "typescript"],
                severity="Critical",
                description="VM 代码执行",
                cwe="CWE-94",
            ),
            SinkPattern(
                name="unserialize",
                pattern="unserialize(",
                category=VulnCategory.RCE,
                languages=["javascript", "typescript"],
                severity="Critical",
                description="不安全反序列化",
                cwe="CWE-502",
            ),
            
            # SQL Injection
            # execute( 加词边界，且要求调用者是已知 DB driver 对象（connection/db/pool/client/cursor）
            # 避免 promise.execute() / workflow.execute() 等非数据库操作误报
            SinkPattern(
                name="sql_query",
                pattern=r"\b(?:connection|db|pool|client|cursor|sequelize|knex|pg|mysql|sqlite)\b.*?\.(query|execute|raw)\(",
                is_regex=True,
                category=VulnCategory.SQL_INJECTION,
                languages=["javascript", "typescript"],
                severity="High",
                description="SQL 查询",
                cwe="CWE-89",
            ),
            
            # NoSQL Injection
            SinkPattern(
                name="mongo_find",
                pattern=r"\.(find|findOne|findById|findOneAndUpdate|findOneAndDelete)\(",
                is_regex=True,
                category=VulnCategory.NOSQL_INJECTION,
                languages=["javascript", "typescript"],
                severity="High",
                description="MongoDB 查询",
                cwe="CWE-943",
            ),
            SinkPattern(
                name="mongo_update",
                pattern=r"\.(update|updateOne|updateMany)\(",
                is_regex=True,
                category=VulnCategory.NOSQL_INJECTION,
                languages=["javascript", "typescript"],
                severity="High",
                description="MongoDB 更新",
                cwe="CWE-943",
            ),
            SinkPattern(
                name="mongo_delete",
                pattern=r"\.(delete|deleteOne|deleteMany|remove)\(",
                is_regex=True,
                category=VulnCategory.NOSQL_INJECTION,
                languages=["javascript", "typescript"],
                severity="High",
                description="MongoDB 删除",
                cwe="CWE-943",
            ),
            SinkPattern(
                name="mongo_aggregate",
                pattern=r"\.aggregate\(",
                is_regex=True,
                category=VulnCategory.NOSQL_INJECTION,
                languages=["javascript", "typescript"],
                severity="High",
                description="MongoDB 聚合",
                cwe="CWE-943",
            ),
            
            # XSS
            SinkPattern(
                name="inner_html",
                pattern="innerHTML",
                category=VulnCategory.XSS,
                languages=["javascript", "typescript"],
                severity="High",
                description="HTML 注入",
                cwe="CWE-79",
            ),
            SinkPattern(
                name="document_write",
                pattern="document.write(",
                category=VulnCategory.XSS,
                languages=["javascript", "typescript"],
                severity="High",
                description="文档写入",
                cwe="CWE-79",
            ),
            SinkPattern(
                name="angular_bypass_security",
                pattern=r"bypassSecurityTrust(Html|Script|Style|Url|ResourceUrl)\(",
                is_regex=True,
                category=VulnCategory.XSS,
                languages=["javascript", "typescript"],
                severity="High",
                description="Angular 安全绕过",
                cwe="CWE-79",
            ),
            
            # Path Traversal
            SinkPattern(
                name="fs_read",
                pattern=r"(readFile|readFileSync|createReadStream)\(",
                is_regex=True,
                category=VulnCategory.PATH_TRAVERSAL,
                languages=["javascript", "typescript"],
                severity="High",
                description="文件读取",
                cwe="CWE-22",
            ),
            SinkPattern(
                name="fs_write",
                pattern=r"(writeFile|writeFileSync|createWriteStream)\(",
                is_regex=True,
                category=VulnCategory.PATH_TRAVERSAL,
                languages=["javascript", "typescript"],
                severity="High",
                description="文件写入",
                cwe="CWE-22",
            ),
            
            # SSRF
            SinkPattern(
                name="http_request",
                pattern=r"(fetch|axios|request|http\.get|https\.get)\(",
                is_regex=True,
                category=VulnCategory.SSRF,
                languages=["javascript", "typescript"],
                severity="High",
                description="HTTP 请求",
                cwe="CWE-918",
            ),
            
            # Open Redirect
            SinkPattern(
                name="redirect",
                pattern=r"(redirect|location\.href|location\.assign)\(",
                is_regex=True,
                category=VulnCategory.OPEN_REDIRECT,
                languages=["javascript", "typescript"],
                severity="Medium",
                description="重定向",
                cwe="CWE-601",
            ),
        ]
        
        for sink in js_sinks:
            self.register_sink(sink)
    
    def _load_python_sinks(self) -> None:
        """加载 Python 的 Sink 模式"""
        py_sinks = [
            # RCE
            SinkPattern(
                name="eval",
                pattern="eval(",
                category=VulnCategory.RCE,
                languages=["python"],
                severity="Critical",
                description="代码执行",
                cwe="CWE-94",
            ),
            SinkPattern(
                name="exec",
                pattern="exec(",
                category=VulnCategory.RCE,
                languages=["python"],
                severity="Critical",
                description="代码执行",
                cwe="CWE-94",
            ),
            SinkPattern(
                name="os_system",
                pattern="os.system(",
                category=VulnCategory.RCE,
                languages=["python"],
                severity="Critical",
                description="命令执行",
                cwe="CWE-78",
            ),
            SinkPattern(
                name="os_popen",
                pattern="os.popen(",
                category=VulnCategory.RCE,
                languages=["python"],
                severity="Critical",
                description="命令执行",
                cwe="CWE-78",
            ),
            SinkPattern(
                name="subprocess",
                pattern=r"subprocess\.(call|run|Popen|check_output)\(",
                is_regex=True,
                category=VulnCategory.RCE,
                languages=["python"],
                severity="Critical",
                description="子进程执行",
                cwe="CWE-78",
            ),
            
            # Deserialization
            SinkPattern(
                name="pickle_loads",
                pattern="pickle.loads(",
                category=VulnCategory.DESERIALIZATION,
                languages=["python"],
                severity="Critical",
                description="Pickle 反序列化",
                cwe="CWE-502",
            ),
            SinkPattern(
                name="yaml_load",
                pattern="yaml.load(",
                category=VulnCategory.DESERIALIZATION,
                languages=["python"],
                severity="High",
                description="YAML 反序列化",
                cwe="CWE-502",
            ),
            
            # SQL Injection
            # 用 \w+ 匹配任意变量名（cur / cursor / conn / db_cursor 等），
            # 避免只匹配字面量 "cursor" 而漏掉 cur.execute / db.execute 等常见写法。
            SinkPattern(
                name="cursor_execute",
                pattern=r"\w+\.(execute|executemany)\(",
                is_regex=True,
                category=VulnCategory.SQL_INJECTION,
                languages=["python"],
                severity="High",
                description="SQL 执行",
                cwe="CWE-89",
            ),
            
            # Path Traversal
            SinkPattern(
                name="open_file",
                pattern="open(",
                category=VulnCategory.PATH_TRAVERSAL,
                languages=["python"],
                severity="Medium",
                description="文件操作",
                cwe="CWE-22",
            ),
            SinkPattern(
                name="os_path",
                pattern=r"os\.path\.(join|abspath)\(",
                is_regex=True,
                category=VulnCategory.PATH_TRAVERSAL,
                languages=["python"],
                severity="Medium",
                description="路径操作",
                cwe="CWE-22",
            ),
            
            # XSS (模板)
            SinkPattern(
                name="render_template_string",
                pattern="render_template_string(",
                category=VulnCategory.XSS,
                languages=["python"],
                severity="High",
                description="模板注入",
                cwe="CWE-79",
            ),
            
            # SSRF
            SinkPattern(
                name="requests",
                pattern=r"requests\.(get|post|put|delete|head)\(",
                is_regex=True,
                category=VulnCategory.SSRF,
                languages=["python"],
                severity="High",
                description="HTTP 请求",
                cwe="CWE-918",
            ),
            SinkPattern(
                name="urllib",
                pattern=r"urllib\.(request\.urlopen|urlopen)\(",
                is_regex=True,
                category=VulnCategory.SSRF,
                languages=["python"],
                severity="High",
                description="URL 请求",
                cwe="CWE-918",
            ),
        ]
        
        for sink in py_sinks:
            self.register_sink(sink)

    def _load_php_sinks(self) -> None:
        """加载 PHP 的 Sink 模式"""
        php_sinks = [
            # SQL Injection
            SinkPattern(
                name="php_mysql_query",
                pattern=r"\b(?:mysql_query|mysqli_query|pg_query)\s*\(",
                is_regex=True,
                category=VulnCategory.SQL_INJECTION,
                languages=["php"],
                severity="High",
                description="PHP SQL 查询",
                cwe="CWE-89",
            ),
            SinkPattern(
                name="php_stmt_execute",
                pattern=r"\$\w+\s*->\s*(?:query|execute)\s*\(",
                is_regex=True,
                category=VulnCategory.SQL_INJECTION,
                languages=["php"],
                severity="High",
                description="PHP 语句执行",
                cwe="CWE-89",
            ),
            # RCE
            SinkPattern(
                name="php_system",
                pattern=r"\bsystem\s*\(",
                is_regex=True,
                category=VulnCategory.RCE,
                languages=["php"],
                severity="Critical",
                description="PHP system()",
                cwe="CWE-78",
            ),
            SinkPattern(
                name="php_exec",
                pattern=r"\bexec\s*\(",
                is_regex=True,
                category=VulnCategory.RCE,
                languages=["php"],
                severity="Critical",
                description="PHP exec()",
                cwe="CWE-78",
            ),
            SinkPattern(
                name="php_shell_exec",
                pattern=r"\bshell_exec\s*\(",
                is_regex=True,
                category=VulnCategory.RCE,
                languages=["php"],
                severity="Critical",
                description="PHP shell_exec()",
                cwe="CWE-78",
            ),
            SinkPattern(
                name="php_passthru",
                pattern=r"\bpassthru\s*\(",
                is_regex=True,
                category=VulnCategory.RCE,
                languages=["php"],
                severity="Critical",
                description="PHP passthru()",
                cwe="CWE-78",
            ),
            SinkPattern(
                name="php_popen",
                pattern=r"\bpopen\s*\(",
                is_regex=True,
                category=VulnCategory.RCE,
                languages=["php"],
                severity="Critical",
                description="PHP popen()",
                cwe="CWE-78",
            ),
            SinkPattern(
                name="php_eval",
                pattern=r"\beval\s*\(",
                is_regex=True,
                category=VulnCategory.RCE,
                languages=["php"],
                severity="Critical",
                description="PHP eval()",
                cwe="CWE-94",
            ),
            # XSS
            SinkPattern(
                name="php_echo_print",
                pattern=r"\b(?:echo|print|printf|fprintf)\s+",
                is_regex=True,
                category=VulnCategory.XSS,
                languages=["php"],
                severity="High",
                description="PHP 输出",
                cwe="CWE-79",
            ),
            # Open Redirect
            SinkPattern(
                name="php_header_location",
                pattern=r"header\s*\(\s*['\"]location\s*:",
                is_regex=True,
                category=VulnCategory.OPEN_REDIRECT,
                languages=["php"],
                severity="Medium",
                description="PHP 重定向头",
                cwe="CWE-601",
            ),
            # Path Traversal
            SinkPattern(
                name="php_file_get_contents",
                pattern=r"\bfile_get_contents\s*\(",
                is_regex=True,
                category=VulnCategory.PATH_TRAVERSAL,
                languages=["php"],
                severity="High",
                description="PHP 文件读取",
                cwe="CWE-22",
            ),
            SinkPattern(
                name="php_include_require",
                pattern=r"\b(?:include|require|include_once|require_once)\s*\(",
                is_regex=True,
                category=VulnCategory.PATH_TRAVERSAL,
                languages=["php"],
                severity="High",
                description="PHP 包含",
                cwe="CWE-22",
            ),
            SinkPattern(
                name="php_fopen",
                pattern=r"\bfopen\s*\(",
                is_regex=True,
                category=VulnCategory.PATH_TRAVERSAL,
                languages=["php"],
                severity="High",
                description="PHP 打开文件",
                cwe="CWE-22",
            ),
            SinkPattern(
                name="php_readfile",
                pattern=r"\breadfile\s*\(",
                is_regex=True,
                category=VulnCategory.PATH_TRAVERSAL,
                languages=["php"],
                severity="High",
                description="PHP readfile()",
                cwe="CWE-22",
            ),
            # Deserialization
            SinkPattern(
                name="php_unserialize",
                pattern=r"\bunserialize\s*\(",
                is_regex=True,
                category=VulnCategory.DESERIALIZATION,
                languages=["php"],
                severity="High",
                description="PHP 反序列化",
                cwe="CWE-502",
            ),
        ]
        for sink in php_sinks:
            self.register_sink(sink)

    def _load_java_sinks(self) -> None:
        """加载 Java 的 Sink 模式"""
        java_sinks = [
            # SQL Injection
            SinkPattern(
                name="java_statement_execute",
                pattern=r"\bStatement\b.*\.execute(?:Query|Update)?\s*\(",
                is_regex=True,
                category=VulnCategory.SQL_INJECTION,
                languages=["java"],
                severity="High",
                description="JDBC Statement 执行 SQL",
                cwe="CWE-89",
            ),
            SinkPattern(
                name="java_connection_create_statement",
                pattern=r"\bcreateStatement\s*\(",
                is_regex=True,
                category=VulnCategory.SQL_INJECTION,
                languages=["java"],
                severity="High",
                description="创建非参数化 Statement",
                cwe="CWE-89",
            ),

            # RCE / 命令执行
            SinkPattern(
                name="java_runtime_exec",
                pattern=r"Runtime\.getRuntime\(\)\.exec\s*\(",
                is_regex=True,
                category=VulnCategory.RCE,
                languages=["java"],
                severity="Critical",
                description="Runtime.exec 命令执行",
                cwe="CWE-78",
            ),
            SinkPattern(
                name="java_process_builder_start",
                pattern=r"ProcessBuilder\s*\(",
                is_regex=True,
                category=VulnCategory.RCE,
                languages=["java"],
                severity="Critical",
                description="ProcessBuilder.start 命令执行",
                cwe="CWE-78",
            ),

            # XSS
            SinkPattern(
                name="java_response_writer_write",
                pattern=r"\.getWriter\(\)\.write\s*\(",
                is_regex=True,
                category=VulnCategory.XSS,
                languages=["java"],
                severity="High",
                description="Servlet 响应直接写入",
                cwe="CWE-79",
            ),

            # Open Redirect
            SinkPattern(
                name="java_response_send_redirect",
                pattern=r"\.sendRedirect\s*\(",
                is_regex=True,
                category=VulnCategory.OPEN_REDIRECT,
                languages=["java"],
                severity="Medium",
                description="Servlet 重定向",
                cwe="CWE-601",
            ),

            # Deserialization
            SinkPattern(
                name="java_object_input_stream_read_object",
                pattern=r"\.readObject\s*\(",
                is_regex=True,
                category=VulnCategory.DESERIALIZATION,
                languages=["java"],
                severity="High",
                description="ObjectInputStream.readObject 反序列化",
                cwe="CWE-502",
            ),

            # Path Traversal
            SinkPattern(
                name="java_file_new",
                pattern=r"new\s+File\s*\(",
                is_regex=True,
                category=VulnCategory.PATH_TRAVERSAL,
                languages=["java"],
                severity="High",
                description="File 对象路径访问",
                cwe="CWE-22",
            ),
            SinkPattern(
                name="java_file_input_stream",
                pattern=r"new\s+FileInputStream\s*\(",
                is_regex=True,
                category=VulnCategory.PATH_TRAVERSAL,
                languages=["java"],
                severity="High",
                description="FileInputStream 文件读取",
                cwe="CWE-22",
            ),
        ]
        for sink in java_sinks:
            self.register_sink(sink)

    def _load_go_sinks(self) -> None:
        """加载 Go 的 Sink 模式"""
        go_sinks = [
            # SQL Injection
            SinkPattern(
                name="go_db_query_exec",
                pattern=r"\.(Query|QueryContext|QueryRow|Exec|ExecContext)\s*\(",
                is_regex=True,
                category=VulnCategory.SQL_INJECTION,
                languages=["go"],
                severity="High",
                description="database/sql 查询 / 执行",
                cwe="CWE-89",
            ),

            # RCE / 命令执行
            SinkPattern(
                name="go_exec_command",
                pattern=r"\bexec\.Command\s*\(",
                is_regex=True,
                category=VulnCategory.RCE,
                languages=["go"],
                severity="Critical",
                description="os/exec.Command 命令执行",
                cwe="CWE-78",
            ),

            # XSS（HTTP 响应输出）
            SinkPattern(
                name="go_fmt_fprintf",
                pattern=r"\bfmt\.Fprintf\s*\(",
                is_regex=True,
                category=VulnCategory.XSS,
                languages=["go"],
                severity="High",
                description="fmt.Fprintf 向 ResponseWriter 输出",
                cwe="CWE-79",
            ),

            # Open Redirect
            SinkPattern(
                name="go_http_redirect",
                pattern=r"\bhttp\.Redirect\s*\(",
                is_regex=True,
                category=VulnCategory.OPEN_REDIRECT,
                languages=["go"],
                severity="Medium",
                description="net/http Redirect 重定向",
                cwe="CWE-601",
            ),

            # Path Traversal
            SinkPattern(
                name="go_os_open",
                pattern=r"\bos\.Open\s*\(",
                is_regex=True,
                category=VulnCategory.PATH_TRAVERSAL,
                languages=["go"],
                severity="High",
                description="os.Open 文件读取",
                cwe="CWE-22",
            ),
            SinkPattern(
                name="go_os_openfile",
                pattern=r"\bos\.OpenFile\s*\(",
                is_regex=True,
                category=VulnCategory.PATH_TRAVERSAL,
                languages=["go"],
                severity="High",
                description="os.OpenFile 文件访问",
                cwe="CWE-22",
            ),

            # Deserialization
            SinkPattern(
                name="go_json_unmarshal",
                pattern=r"\bjson\.Unmarshal\s*\(",
                is_regex=True,
                category=VulnCategory.DESERIALIZATION,
                languages=["go"],
                severity="High",
                description="json.Unmarshal 反序列化",
                cwe="CWE-502",
            ),
        ]
        for sink in go_sinks:
            self.register_sink(sink)
    
    def _load_sanitizers(self) -> None:
        """
        加载 Sanitizer 模式。

        注意：阶段二优化后，匹配模式改为精确前缀匹配或严格正则，
        避免 ``encodeURIComponent``（不防 XSS）/ ``escape_velocity``（物理变量）
        之类的误判。
        """
        sanitizers = [
            # ── JavaScript / TypeScript ──

            # XSS Sanitizer
            SanitizerPattern(
                name="escape_html_func",
                pattern=r"\bescapeHtml\s*\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.XSS],
                languages=["javascript", "typescript"],
                description="escapeHtml() 函数",
            ),
            SanitizerPattern(
                name="dompurify",
                pattern="DOMPurify.sanitize(",
                sanitizes_categories=[VulnCategory.XSS],
                languages=["javascript", "typescript"],
                description="DOMPurify 净化",
            ),
            SanitizerPattern(
                name="xss_filter",
                pattern=r"\bxss\s*\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.XSS],
                languages=["javascript", "typescript"],
                description="xss() 过滤函数",
            ),
            SanitizerPattern(
                name="validator_escape",
                pattern="validator.escape(",
                sanitizes_categories=[VulnCategory.XSS],
                languages=["javascript", "typescript"],
                description="validator.escape() 转义",
            ),

            # 数值转换 Sanitizer（净化 SQLi / NoSQLi）
            SanitizerPattern(
                name="parse_int",
                pattern="parseInt(",
                sanitizes_categories=[
                    VulnCategory.SQL_INJECTION,
                    VulnCategory.NOSQL_INJECTION,
                ],
                languages=["javascript", "typescript"],
                description="parseInt() 整数解析",
            ),
            SanitizerPattern(
                name="parse_float",
                pattern="parseFloat(",
                sanitizes_categories=[
                    VulnCategory.SQL_INJECTION,
                    VulnCategory.NOSQL_INJECTION,
                ],
                languages=["javascript", "typescript"],
                description="parseFloat() 浮点解析",
            ),
            SanitizerPattern(
                name="number_cast",
                pattern="Number(",
                sanitizes_categories=[
                    VulnCategory.SQL_INJECTION,
                    VulnCategory.NOSQL_INJECTION,
                ],
                languages=["javascript", "typescript"],
                description="Number() 数值转换",
            ),

            # MongoDB Sanitizer
            SanitizerPattern(
                name="mongo_sanitize",
                pattern="mongoSanitize(",
                sanitizes_categories=[VulnCategory.NOSQL_INJECTION],
                languages=["javascript", "typescript"],
                description="mongo-sanitize 净化",
            ),

            # 路径 Sanitizer（path.basename / normalize / resolve 作为净化感知，降低告警或跳过）
            SanitizerPattern(
                name="path_basename",
                pattern=r"path\.basename\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.PATH_TRAVERSAL],
                languages=["javascript", "typescript"],
                description="path.basename() 限制为文件名（需配合目录白名单）",
            ),
            SanitizerPattern(
                name="path_normalize",
                pattern=r"path\.normalize\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.PATH_TRAVERSAL],
                languages=["javascript", "typescript"],
                description="path.normalize() 路径规范化",
            ),
            SanitizerPattern(
                name="path_resolve",
                pattern=r"path\.resolve\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.PATH_TRAVERSAL],
                languages=["javascript", "typescript"],
                description="path.resolve() 解析为绝对路径",
            ),

            # ── Python ──

            # XSS Sanitizer
            SanitizerPattern(
                name="html_escape_py",
                pattern=r"html\.escape\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.XSS],
                languages=["python"],
                description="html.escape() 转义",
            ),
            SanitizerPattern(
                name="markupsafe_escape",
                pattern=r"markupsafe\.escape\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.XSS],
                languages=["python"],
                description="markupsafe.escape() 转义",
            ),
            SanitizerPattern(
                name="bleach_clean",
                pattern="bleach.clean(",
                sanitizes_categories=[VulnCategory.XSS],
                languages=["python"],
                description="bleach.clean() 净化",
            ),

            # 数值转换 Sanitizer
            SanitizerPattern(
                name="int_cast_py",
                pattern="int(",
                sanitizes_categories=[
                    VulnCategory.SQL_INJECTION,
                    VulnCategory.NOSQL_INJECTION,
                ],
                languages=["python"],
                description="int() 整数转换",
            ),

            # RCE Sanitizer
            SanitizerPattern(
                name="shlex_quote",
                pattern="shlex.quote(",
                sanitizes_categories=[VulnCategory.RCE],
                languages=["python"],
                description="shlex.quote() Shell 转义",
            ),

            # 路径 Sanitizer
            SanitizerPattern(
                name="os_path_basename_py",
                pattern="os.path.basename(",
                sanitizes_categories=[VulnCategory.PATH_TRAVERSAL],
                languages=["python"],
                description="os.path.basename() 路径基名",
            ),
            SanitizerPattern(
                name="os_path_normpath_py",
                pattern="os.path.normpath(",
                sanitizes_categories=[VulnCategory.PATH_TRAVERSAL],
                languages=["python"],
                description="os.path.normpath() 路径规范化",
            ),
        ]

        for sanitizer in sanitizers:
            self.register_sanitizer(sanitizer)

    def _load_php_sanitizers(self) -> None:
        """加载 PHP 的 Sanitizer 模式"""
        php_sanitizers = [
            SanitizerPattern(
                name="php_htmlspecialchars",
                pattern=r"\bhtmlspecialchars\s*\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.XSS],
                languages=["php"],
                description="htmlspecialchars() 转义",
            ),
            SanitizerPattern(
                name="php_htmlentities",
                pattern=r"\bhtmlentities\s*\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.XSS],
                languages=["php"],
                description="htmlentities() 转义",
            ),
            SanitizerPattern(
                name="php_intval",
                pattern=r"\bintval\s*\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.SQL_INJECTION],
                languages=["php"],
                description="intval() 整数转换",
            ),
            SanitizerPattern(
                name="php_floatval",
                pattern=r"\bfloatval\s*\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.SQL_INJECTION],
                languages=["php"],
                description="floatval() 浮点转换",
            ),
            SanitizerPattern(
                name="php_mysqli_real_escape_string",
                pattern=r"\bmysqli_real_escape_string\s*\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.SQL_INJECTION],
                languages=["php"],
                description="mysqli_real_escape_string()",
            ),
            SanitizerPattern(
                name="php_addslashes",
                pattern=r"\baddslashes\s*\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.SQL_INJECTION],
                languages=["php"],
                description="addslashes()",
            ),
            SanitizerPattern(
                name="php_basename",
                pattern=r"\bbasename\s*\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.PATH_TRAVERSAL],
                languages=["php"],
                description="basename() 路径基名",
            ),
            SanitizerPattern(
                name="php_realpath",
                pattern=r"\brealpath\s*\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.PATH_TRAVERSAL],
                languages=["php"],
                description="realpath() 规范路径",
            ),
            SanitizerPattern(
                name="php_escapeshellarg",
                pattern=r"\bescapeshellarg\s*\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.RCE],
                languages=["php"],
                description="escapeshellarg() Shell 转义",
            ),
            SanitizerPattern(
                name="php_escapeshellcmd",
                pattern=r"\bescapeshellcmd\s*\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.RCE],
                languages=["php"],
                description="escapeshellcmd() Shell 转义",
            ),
        ]
        for sanitizer in php_sanitizers:
            self.register_sanitizer(sanitizer)

    def _load_java_sanitizers(self) -> None:
        """加载 Java 的 Sanitizer 模式"""
        java_sanitizers = [
            # SQLI - 参数化查询 / PreparedStatement
            SanitizerPattern(
                name="java_prepared_statement",
                pattern=r"\bprepareStatement\s*\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.SQL_INJECTION],
                languages=["java"],
                description="JDBC PreparedStatement 参数化查询",
            ),

            # XSS
            SanitizerPattern(
                name="java_html_utils_html_escape",
                pattern=r"HtmlUtils\.htmlEscape\s*\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.XSS],
                languages=["java"],
                description="Spring HtmlUtils.htmlEscape XSS 转义",
            ),
            SanitizerPattern(
                name="java_esapi_encoder",
                pattern=r"ESAPI\.encoder\(\)\.encode",
                is_regex=True,
                sanitizes_categories=[VulnCategory.XSS],
                languages=["java"],
                description="OWASP ESAPI encoder 编码输出",
            ),

            # 数值转换
            SanitizerPattern(
                name="java_integer_parse_int",
                pattern=r"Integer\.parseInt\s*\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.SQL_INJECTION],
                languages=["java"],
                description="Integer.parseInt 数值转换",
            ),

            # 路径规范化
            SanitizerPattern(
                name="java_paths_get_normalize",
                pattern=r"Paths\.get\s*\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.PATH_TRAVERSAL],
                languages=["java"],
                description="Paths.get(...).normalize() 路径规范化（部分识别）",
            ),
        ]
        for sanitizer in java_sanitizers:
            self.register_sanitizer(sanitizer)

    def _load_go_sanitizers(self) -> None:
        """加载 Go 的 Sanitizer 模式"""
        go_sanitizers = [
            # XSS Sanitizer
            SanitizerPattern(
                name="go_template_html_escape_string",
                pattern=r"template\.HTMLEscapeString\s*\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.XSS],
                languages=["go"],
                description="html/template.HTMLEscapeString XSS 转义",
            ),

            # 路径规范化
            SanitizerPattern(
                name="go_filepath_clean",
                pattern=r"filepath\.Clean\s*\(",
                is_regex=True,
                sanitizes_categories=[VulnCategory.PATH_TRAVERSAL],
                languages=["go"],
                description="filepath.Clean() 路径规范化",
            ),

            # 数值转换（端口/ID 等）
            SanitizerPattern(
                name="go_strconv_atoi",
                pattern=r"strconv\.Atoi\s*\(",
                is_regex=True,
                sanitizes_categories=[
                    VulnCategory.SQL_INJECTION,
                    VulnCategory.NOSQL_INJECTION,
                ],
                languages=["go"],
                description="strconv.Atoi() 整数解析",
            ),
        ]
        for sanitizer in go_sanitizers:
            self.register_sanitizer(sanitizer)
    
    def get_stats(self) -> Dict[str, int]:
        """获取统计信息"""
        return {
            "sources": len(self._sources),
            "sinks": len(self._sinks),
            "sanitizers": len(self._sanitizers),
        }


# 全局注册表实例
_default_registry: Optional[SourceSinkRegistry] = None


def get_default_registry() -> SourceSinkRegistry:
    """获取默认的全局注册表"""
    global _default_registry
    if _default_registry is None:
        _default_registry = SourceSinkRegistry()
        _default_registry.load_defaults()
    return _default_registry


__all__ = [
    "VulnCategory",
    "TaintLevel",
    "SourcePattern",
    "SinkPattern",
    "SanitizerPattern",
    "SourceSinkRegistry",
    "get_default_registry",
]
