# aegis_server.py - Aegis 工业级 API 服务端
import os
import sys
import certifi

# =================================================================
# 0. 📁 添加项目根目录到 Python 路径（支持新的目录结构）
# =================================================================
# 获取当前文件所在目录的父目录（aegis-ai-core）
_current_file = os.path.abspath(__file__)
_current_dir = os.path.dirname(_current_file)  # src/server
_project_root = os.path.dirname(os.path.dirname(_current_dir))  # aegis-ai-core (向上两级)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# =================================================================
# 1. 🛡️ 环境净化与证书修复 (保留昨晚的成果)
# =================================================================
valid_cert_path = certifi.where()
os.environ['REQUESTS_CA_BUNDLE'] = valid_cert_path
os.environ['SSL_CERT_FILE'] = valid_cert_path

# =================================================================
# 2. 🔑 加载环境变量（支持 .env 文件）
# =================================================================
try:
    from dotenv import load_dotenv
    # 尝试从当前目录或父目录加载 .env 文件
    load_dotenv()
    load_dotenv(os.path.join(_project_root, '.env'))
except ImportError:
    # 如果没有安装 python-dotenv，只使用系统环境变量
    pass

import requests
import chromadb
import urllib3
import logging
import time
import hashlib
from collections import OrderedDict, defaultdict, deque
from datetime import datetime
from typing import Optional, Dict, Any
from src.analysis.ast_analyzer import analyze_code_ast
from src.analysis.security_rules import scan_code_locally
from src.analysis.rule_based_audit import audit_code_with_rules_only, merge_findings
from src.rag.rag_optimizer import optimized_rag_retrieval
from fastapi import FastAPI, HTTPException, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =================================================================
# 3. 📊 结构化日志系统
# =================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("aegis")

# 尝试使用 JSON 格式日志（如果安装了 python-json-logger）
try:
    from pythonjsonlogger import jsonlogger
    logHandler = logging.StreamHandler()
    formatter = jsonlogger.JsonFormatter(
        '%(asctime)s %(name)s %(levelname)s %(message)s'
    )
    logHandler.setFormatter(formatter)
    logger.addHandler(logHandler)
    logger.setLevel(logging.INFO)
except ImportError:
    # 如果没有安装 python-json-logger，使用标准格式
    logger.info("python-json-logger 未安装，使用标准日志格式。安装命令: pip install python-json-logger")

# =================================================================
# 4. 🔄 错误重试机制
# =================================================================
try:
    from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
    RETRY_AVAILABLE = True
except ImportError:
    RETRY_AVAILABLE = False
    logger.warning("tenacity 未安装，将使用简单重试机制。安装命令: pip install tenacity")

# =================================================================
# 🔑 配置区（API Key 必须通过环境变量或 .env 文件设置，禁止硬编码）
# =================================================================
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
API_URL = os.getenv("DEEPSEEK_API_URL", "https://api.deepseek.com/chat/completions")

# =================================================================
# 4.5 💾 缓存 & 限流配置（第二阶段）
# =================================================================
# DeepSeek 响应缓存（减少重复调用，节省成本）
DEEPSEEK_CACHE_TTL_SECONDS = int(os.getenv("DEEPSEEK_CACHE_TTL_SECONDS", "300"))
DEEPSEEK_CACHE_MAX_ITEMS = int(os.getenv("DEEPSEEK_CACHE_MAX_ITEMS", "128"))

# 简单限流（按 IP / 路由）
RATE_LIMIT_CHAT_PER_MIN = int(os.getenv("RATE_LIMIT_CHAT_PER_MIN", "30"))
RATE_LIMIT_AUDIT_PER_MIN = int(os.getenv("RATE_LIMIT_AUDIT_PER_MIN", "10"))

# CORS origins（开发默认 *，生产建议配置具体域名）
CORS_ALLOW_ORIGINS_RAW = os.getenv("CORS_ALLOW_ORIGINS", "*")

# 数据库连接
print("🔌 [System] 正在挂载本地向量数据库...")
client = chromadb.PersistentClient(path="./aegis_db")
collection = client.get_collection(name="cve_core")


class SimpleTTLCache:
    """
    一个非常轻量的 TTL + LRU 缓存：
    - TTL：到期自动失效
    - LRU：超过容量淘汰最旧的

    说明：为了保持依赖简单，这里不引入第三方缓存库。
    """

    def __init__(self, max_items: int, ttl_seconds: int):
        self._max_items = max_items
        self._ttl_seconds = ttl_seconds
        self._store: "OrderedDict[str, tuple[float, str]]" = OrderedDict()

    def get(self, key: str) -> Optional[str]:
        now = time.time()
        item = self._store.get(key)
        if not item:
            return None
        expires_at, value = item
        if expires_at <= now:
            # 过期
            try:999
                del self._store[key]
            except KeyError:
                pass
            return None
        # LRU：命中则移动到末尾
        self._store.move_to_end(key)
        return value

    def set(self, key: str, value: str) -> None:
        if self._ttl_seconds <= 0 or self._max_items <= 0:
            return
        now = time.time()
        expires_at = now + self._ttl_seconds
        self._store[key] = (expires_at, value)
        self._store.move_to_end(key)
        # 超出容量：淘汰最旧的
        while len(self._store) > self._max_items:
            self._store.popitem(last=False)


deepseek_cache = SimpleTTLCache(
    max_items=DEEPSEEK_CACHE_MAX_ITEMS,
    ttl_seconds=DEEPSEEK_CACHE_TTL_SECONDS,
)

# =================================================================
# 🧠 AI 核心逻辑函数 (封装好的 DeepSeek 调用，带重试和日志)
# =================================================================
def _call_deepseek_once(system_prompt: str, user_message: str) -> requests.Response:
    """单次 API 调用（内部函数，用于重试）"""
    with requests.Session() as session:
        session.trust_env = False  # 强制直连，不走代理
        resp = session.post(
            API_URL,
            json={
                "model": "deepseek-chat",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message}
                ],
                "stream": False
            },
            headers={"Authorization": f"Bearer {DEEPSEEK_API_KEY}"},
            timeout=120,
            verify=valid_cert_path
        )
        resp.raise_for_status()  # 抛出 HTTP 错误
        return resp

def call_deepseek(system_prompt: str, user_message: str) -> str:
    """
    调用 DeepSeek 聊天接口（带重试机制和日志）。
    
    Args:
        system_prompt: 系统提示词
        user_message: 用户消息
        
    Returns:
        AI 回复内容，或错误信息字符串
    """
    if not DEEPSEEK_API_KEY:
        error_msg = "未配置 DEEPSEEK_API_KEY，请在环境变量中设置"
        logger.error(error_msg)
        return f"❌ {error_msg}"
    
    # 缓存 key：对输入做哈希，避免存储超长 key
    cache_key_src = f"{system_prompt}\0{user_message}".encode("utf-8", errors="ignore")
    cache_key = hashlib.sha256(cache_key_src).hexdigest()
    cached = deepseek_cache.get(cache_key)
    if cached is not None:
        logger.info("DeepSeek 命中缓存", extra={"cache": "hit"})
        return cached

    start_time = time.time()
    
    # 使用 tenacity 重试机制（如果可用）
    if RETRY_AVAILABLE:
        @retry(
            stop=stop_after_attempt(3),
            wait=wait_exponential(multiplier=1, min=2, max=10),
            retry=retry_if_exception_type((requests.Timeout, requests.ConnectionError, requests.HTTPError))
        )
        def _retryable_call():
            return _call_deepseek_once(system_prompt, user_message)
        
        try:
            resp = _retryable_call()
        except requests.Timeout:
            elapsed = (time.time() - start_time) * 1000
            error_msg = f"API 请求超时（已重试3次），耗时 {elapsed:.0f}ms"
            logger.error(error_msg, extra={"elapsed_ms": elapsed, "retries": 3})
            return f"❌ {error_msg}"
        except requests.ConnectionError as e:
            elapsed = (time.time() - start_time) * 1000
            error_msg = f"网络连接失败: {str(e)}"
            logger.error(error_msg, extra={"elapsed_ms": elapsed, "error": str(e)})
            return f"❌ {error_msg}"
        except requests.HTTPError as e:
            elapsed = (time.time() - start_time) * 1000
            error_msg = f"API 返回错误: {resp.status_code if 'resp' in locals() else 'Unknown'}"
            logger.error(error_msg, extra={"elapsed_ms": elapsed, "status_code": resp.status_code if 'resp' in locals() else None})
            return f"❌ {error_msg}"
        except Exception as e:
            elapsed = (time.time() - start_time) * 1000
            error_msg = f"未知错误: {str(e)}"
            logger.error(error_msg, extra={"elapsed_ms": elapsed, "error": str(e)})
            return f"❌ {error_msg}"
    else:
        # 简单重试机制（如果没有 tenacity）
        max_attempts = 3
        last_exception = None
        for attempt in range(1, max_attempts + 1):
            try:
                resp = _call_deepseek_once(system_prompt, user_message)
                break
            except (requests.Timeout, requests.ConnectionError, requests.HTTPError) as e:
                last_exception = e
                if attempt < max_attempts:
                    wait_time = 2 ** attempt
                    logger.warning(f"API 调用失败，{wait_time}秒后重试 (尝试 {attempt}/{max_attempts})", 
                                 extra={"attempt": attempt, "error": str(e)})
                    time.sleep(wait_time)
                else:
                    elapsed = (time.time() - start_time) * 1000
                    error_msg = f"API 调用失败（已重试{max_attempts}次）: {str(e)}"
                    logger.error(error_msg, extra={"elapsed_ms": elapsed, "retries": max_attempts, "error": str(e)})
                    return f"❌ {error_msg}"
            except Exception as e:
                elapsed = (time.time() - start_time) * 1000
                error_msg = f"未知错误: {str(e)}"
                logger.error(error_msg, extra={"elapsed_ms": elapsed, "error": str(e)})
                return f"❌ {error_msg}"
    
    # 成功响应
    elapsed = (time.time() - start_time) * 1000
    try:
        content = resp.json()['choices'][0]['message']['content']
        logger.info("API 调用成功", extra={
            "elapsed_ms": elapsed,
            "response_length": len(content)
        })
        # 仅缓存成功结果（避免把错误信息缓存进去）
        deepseek_cache.set(cache_key, content)
        return content
    except (KeyError, ValueError) as e:
        error_msg = f"响应解析失败: {str(e)}"
        logger.error(error_msg, extra={"elapsed_ms": elapsed, "error": str(e)})
        return f"❌ {error_msg}"

# =================================================================
# 🌐 FastAPI 服务配置
# =================================================================
app = FastAPI(title="Aegis-AI Backend", version="1.0")

# =================================================================
# 6. 🚦 简单限流（按 IP / 路由）
# =================================================================
# 说明：不引入第三方依赖，使用内存滑动窗口计数。
rate_limit_windows: "defaultdict[str, deque[float]]" = defaultdict(deque)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    path = request.url.path
    if path not in ("/api/chat", "/api/audit"):
        return await call_next(request)

    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window_seconds = 60.0
    max_calls = RATE_LIMIT_CHAT_PER_MIN if path == "/api/chat" else RATE_LIMIT_AUDIT_PER_MIN

    key = f"{client_ip}:{path}"
    q = rate_limit_windows[key]

    # 清理窗口外的记录
    cutoff = now - window_seconds
    while q and q[0] < cutoff:
        q.popleft()

    if len(q) >= max_calls:
        retry_after = int(max(1.0, (q[0] + window_seconds) - now)) if q else 60
        logger.warning(
            "触发限流",
            extra={
                "client_ip": client_ip,
                "path": path,
                "max_calls_per_min": max_calls,
                "retry_after_seconds": retry_after,
            },
        )
        return JSONResponse(
            status_code=429,
            content={
                "error": "Too Many Requests",
                "detail": f"请求过于频繁，请 {retry_after}s 后重试",
            },
            headers={"Retry-After": str(retry_after)},
        )

    q.append(now)
    return await call_next(request)


# ⚠️ 关键：配置 CORS，允许你的 Angular (localhost:4200) 访问我
cors_origins = ["*"]
if CORS_ALLOW_ORIGINS_RAW.strip() != "*":
    cors_origins = [o.strip() for o in CORS_ALLOW_ORIGINS_RAW.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,  # 生产环境建议配置具体域名
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 定义前端发来的数据格式
class ChatRequest(BaseModel):
    message: str

@app.get("/")
def health_check():
    """健康检查接口"""
    try:
        db_count = collection.count()
        api_key_configured = bool(DEEPSEEK_API_KEY)
        return {
            "status": "healthy",
            "db_count": db_count,
            "api_key_configured": api_key_configured,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error("健康检查失败", extra={"error": str(e)})
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "error": str(e)}
        )

# =================================================================
# 5. 🛡️ 全局异常处理
# =================================================================
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """全局异常处理器"""
    logger.error("未处理的异常", extra={
        "path": request.url.path,
        "method": request.method,
        "error": str(exc),
        "error_type": type(exc).__name__
    }, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "内部服务器错误",
            "detail": str(exc) if os.getenv("DEBUG", "false").lower() == "true" else "请联系管理员"
        }
    )

@app.post("/api/chat")
async def chat_endpoint(req: ChatRequest, request: Request):
    """
    这是前端真正调用的接口：
    前端发来 { "message": "Fastjson漏洞" }
    后端返回 { "reply": "...", "mode": "expert/chat" }
    """
    start_time = time.time()
    user_query = req.message.strip()
    
    # 记录请求
    client_ip = request.client.host if request.client else "unknown"
    logger.info("收到聊天请求", extra={
        "query": user_query,
        "client_ip": client_ip,
        "query_length": len(user_query)
    })
    
    if not user_query:
        logger.warning("空查询请求")
        return {"reply": "如果你不说话，我无法帮你。", "mode": "none"}

    try:
        # === 🔥 优化的 RAG 检索流程 ===
        vector_start = time.time()
        rag_result = optimized_rag_retrieval(
            collection=collection,
            query=user_query,
            top_k=5,  # 初始检索 5 条
            return_top_n=3  # 返回前 3 条
        )
        vector_time = (time.time() - vector_start) * 1000
        
        reply = ""
        mode = "chat"  # 默认为闲聊模式
        distance = rag_result['distance']

        logger.info("优化的 RAG 检索完成", extra={
            "distance": distance,
            "has_match": rag_result['has_match'],
            "total_candidates": rag_result['total_candidates'],
            "returned_count": len(rag_result['ranked_results']),
            "vector_time_ms": vector_time
        })

        # 路由判断：是否有有效匹配
        if rag_result['has_match']:
            logger.info("进入专家模式（RAG）", extra={
                "distance": distance,
                "context_length": len(rag_result['context'])
            })
            mode = "expert"
            
            # RAG 模式提示词（使用融合后的上下文）
            sys_prompt = """你是一个高级安全专家。
            请根据【参考资料】回答问题。参考资料可能包含多条相关信息，请综合分析。
            如果资料不相关，请忽略资料并礼貌告知用户。
            """
            user_msg = f"{rag_result['context']}\n\n【用户问题】:\n{user_query}"
            reply = call_deepseek(sys_prompt, user_msg)
            
        else:
            logger.info("进入闲聊模式", extra={"distance": distance})
            mode = "chat"
            # 纯聊模式提示词
            sys_prompt = "你是一个黑客风格的AI助手。用户在跟你闲聊，请用简练、酷酷的语气回应。"
            reply = call_deepseek(sys_prompt, user_query)

        elapsed = (time.time() - start_time) * 1000
        logger.info("请求处理完成", extra={
            "mode": mode,
            "distance": distance,
            "total_time_ms": elapsed,
            "reply_length": len(reply)
        })

        return {
            "reply": reply,
            "mode": mode,
            "distance": distance
        }
    
    except Exception as e:
        elapsed = (time.time() - start_time) * 1000
        logger.error("请求处理失败", extra={
            "error": str(e),
            "error_type": type(e).__name__,
            "elapsed_ms": elapsed
        }, exc_info=True)
        raise HTTPException(status_code=500, detail=f"处理请求时发生错误: {str(e)}")

# 🔥 新增：代码审计专用接口
@app.post("/api/audit")
async def audit_code(file: UploadFile = File(...), request: Request = None):
    """
    代码审计接口：上传代码文件，返回 AST 分析 + AI 审计报告
    """
    start_time = time.time()
    client_ip = request.client.host if request and request.client else "unknown"
    
    logger.info("收到审计请求", extra={
        "file_name": file.filename,
        "content_type": file.content_type,
        "client_ip": client_ip
    })
    
    try:
        # 读取文件内容
        content = await file.read()
        code_text = content.decode("utf-8")
        code_size = len(code_text)
        
        logger.info("文件读取成功", extra={
            "file_name": file.filename,
            "code_size": code_size
        })
        
        # === 🔥 核心升级：双重检测（AST + 正则规则）===
        ast_start = time.time()
        ast_findings = analyze_code_ast(code_text)
        regex_findings = scan_code_locally(code_text, file_path=file.filename)
        merged_findings = merge_findings(ast_findings, regex_findings)
        analysis_time = (time.time() - ast_start) * 1000
        
        logger.info("双重检测完成", extra={
            "ast_count": len(ast_findings),
            "regex_count": len(regex_findings),
            "total_findings": len(merged_findings),
            "analysis_time_ms": analysis_time
        })
        
        local_report_str = ""
        if ast_findings:
            logger.info("AST 分析发现风险点", extra={
                "findings_count": len(ast_findings),
                "analysis_time_ms": analysis_time
            })
            local_report_str = "【AST 静态分析报告】(基于语法树结构分析，置信度高)：\n"
            for f in ast_findings:
                local_report_str += f"- 第 {f['line']} 行 [{f['type']}]: {f['details']}\n"
        else:
            logger.info("AST 分析未发现结构性漏洞", extra={"analysis_time_ms": analysis_time})
            local_report_str = "【AST 静态分析】未发现高危函数调用（但这不代表逻辑绝对安全）。"

        # === 构建 Prompt ===
        # 告诉 DeepSeek：我有 AST 报告，你帮我复查逻辑
        system_prompt = """你是一个高级代码审计专家。
        我们已使用 AST (抽象语法树) 技术对代码进行了预扫描。
        
        请结合【AST 分析报告】和【源代码】：
        1. 重点验证 AST 报告中的风险是否真实存在（上下文是否可控）。
        2. 补充扫描 AST 无法发现的“逻辑漏洞”（如越权访问、硬编码密码等）。
        
        请输出专业的 Markdown 格式审计报告。
        """
        
        # 限制代码长度（避免 token 超限）
        MAX_CODE_LENGTH = 10000
        code_preview = code_text[:MAX_CODE_LENGTH]
        if len(code_text) > MAX_CODE_LENGTH:
            logger.warning("代码过长，已截断", extra={
                "original_length": len(code_text),
                "truncated_length": MAX_CODE_LENGTH
            })
        
        # === 尝试 AI 增强（如果可用）===
        reply = ""
        use_ai = bool(DEEPSEEK_API_KEY)  # 如果配置了 API Key，尝试用 AI
        
        if use_ai:
            try:
                # 限制代码长度（避免 token 超限）
                MAX_CODE_LENGTH = 10000
                code_preview = code_text[:MAX_CODE_LENGTH]
                if len(code_text) > MAX_CODE_LENGTH:
                    logger.warning("代码过长，已截断", extra={
                        "original_length": len(code_text),
                        "truncated_length": MAX_CODE_LENGTH
                    })
                
                user_msg = f"""
                {local_report_str}
                
                --------------------------------------------------
                【源代码】：
                {code_preview} 
                """

                logger.info("提交 AI 增强审计", extra={"code_length": len(code_preview)})
                reply = call_deepseek(system_prompt, user_msg)
                logger.info("AI 增强审计完成")
                
            except Exception as e:
                logger.warning("AI 审计失败，降级到纯规则审计", extra={"error": str(e)})
                use_ai = False
        
        # === 降级策略：如果 AI 不可用，使用纯规则审计 ===
        if not use_ai or not reply or reply.startswith("❌"):
            logger.info("使用纯规则审计引擎")
            rule_result = audit_code_with_rules_only(code_text, file.filename)
            reply = rule_result["report"]
            merged_findings = rule_result["findings"]
        
        elapsed = (time.time() - start_time) * 1000
        
        # 统计严重程度
        severity_count = {
            "Critical": len([f for f in merged_findings if f.get('severity') == 'Critical']),
            "High": len([f for f in merged_findings if f.get('severity') == 'High']),
            "Medium": len([f for f in merged_findings if f.get('severity') == 'Medium']),
            "Low": len([f for f in merged_findings if f.get('severity') == 'Low'])
        }
        
        logger.info("审计完成", extra={
            "file_name": file.filename,
            "total_findings": len(merged_findings),
            "ast_count": len(ast_findings),
            "regex_count": len(regex_findings),
            "severity": severity_count,
            "used_ai": use_ai,
            "total_time_ms": elapsed,
            "reply_length": len(reply)
        })

        return {
            "reply": reply,
            "mode": "audit",
            "filename": file.filename,
            "findings_count": len(merged_findings),
            "ast_findings_count": len(ast_findings),
            "regex_findings_count": len(regex_findings),
            "severity_count": severity_count,
            "used_ai": use_ai
        }
    
    except UnicodeDecodeError as e:
        elapsed = (time.time() - start_time) * 1000
        error_msg = f"文件编码错误，无法解析为 UTF-8: {str(e)}"
        logger.error(error_msg, extra={"file_name": file.filename, "elapsed_ms": elapsed})
        raise HTTPException(status_code=400, detail=error_msg)
    
    except Exception as e:
        elapsed = (time.time() - start_time) * 1000
        logger.error("审计处理失败", extra={
            "file_name": file.filename,
            "error": str(e),
            "error_type": type(e).__name__,
            "elapsed_ms": elapsed
        }, exc_info=True)
        raise HTTPException(status_code=500, detail=f"审计处理时发生错误: {str(e)}")



# 启动提示
logger.info("="*60)
logger.info("🚀 Aegis Server 启动成功")
logger.info(f"📊 数据库记录数: {collection.count()}")
logger.info(f"🔑 API Key 已配置: {'是' if DEEPSEEK_API_KEY else '否'}")
logger.info(f"🔄 重试机制: {'启用 (tenacity)' if RETRY_AVAILABLE else '启用 (简单重试)'}")
logger.info("👉 运行命令: uvicorn src.server.aegis_server:app --reload")
logger.info("="*60)


# =================================================================
# 直接运行脚本时的启动逻辑
# =================================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.server.aegis_server:app", host="0.0.0.0", port=8000, reload=True)