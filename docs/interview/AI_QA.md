# Aegis-AI 问答记录（与 AI 的对话沉淀）

> 用途：把你问我的问题和我的回答长期沉淀在这里，方便回看与复用。  
> 约定：每个问题按时间追加；回答尽量给出可操作的配置/命令。

## 2026-02-02

### Q1：什么是 bypass 配置？

**A：**bypass（绕过）配置的意思是：**哪些域名/IP 不走代理，直接连接（DIRECT）**。  
你开代理后出现的 `SSLEOFError`/`Retrying`，本质上是代理链路在 TLS/SSL 握手阶段把连接“搞断了”。把相关域名加入 bypass，就能让这些请求不经过代理，从而避免握手异常。

常见形式：
- **按域名绕过**：`api.deepseek.com`、`localhost`、`127.0.0.1`
- **按后缀绕过**：`*.deepseek.com`
- **按网段绕过**：`192.168.0.0/16`

你可以把 bypass 理解成：**代理的“白名单直连列表”**。

---

### Q2：前端走代理 vs DeepSeek AI 走代理，有什么区别？

**A：**区别在于“谁的网络请求被代理”以及“影响什么”：

- **前端走代理（通常指 npm / 下载依赖 / 访问外网资源）**
  - 影响：`npm install`、拉包、访问 GitHub、下载二进制依赖等
  - 目标：解决“开发环境拉包慢/被墙/公司网络限制”
  - 风险：一般较低；失败多是下载超时/证书拦截

- **DeepSeek AI 走代理（指后端 Python 调用 `https://api.deepseek.com/...` 也经过代理）**
  - 影响：你服务端的核心能力（聊天/审计）是否稳定
  - 目标：让后端出网（在受限网络里必须经代理才能访问 DeepSeek）
  - 风险：较高；代理若做 HTTPS 解密/证书替换/协议不兼容，容易出现你看到的 `SSLEOFError`、握手失败、随机断连、响应被篡改等问题

**建议：**
- 能稳定直连 DeepSeek：优先 **DeepSeek 直连**（把 `api.deepseek.com` 加入 bypass）
- 必须经代理才能访问 DeepSeek：需要把代理配置成“透明且稳定”的 HTTPS 转发（不要做中间人解密），并确保证书/协议兼容

---

### Q3：为什么我关掉代理就没问题了？

**A：**因为你之前的代理在某些 HTTPS 请求上导致了 **TLS/SSL 握手中断**（对端或代理提前断开连接），触发了 urllib3 的自动重试日志。关掉代理后恢复直连，握手链路正常，所以日志消失。

---

### Q4：我完全不会做软件。你做的这些优化涉及哪些知识点？能通俗讲讲并记录下来吗？

**A：**可以。下面按“你需要掌握的知识点”来拆解（都和你项目现在的代码一一对应）。

#### 1）环境变量 / `.env`（配置与密钥管理）

- **这是什么**：把“会变的配置”放到环境里，而不是写死在代码里。尤其是 API Key，**绝对不能写进仓库**。
- **你项目里对应**：
  - `DEEPSEEK_API_KEY`：DeepSeek 的密钥
  - `DEEPSEEK_API_URL`：接口地址（可选）
  - `.env.example`：给你一个模板（可以复制成 `.env`）
  - `python-dotenv`：让 Python 启动时能自动读 `.env`（不用每次手动 set 环境变量）
- **为什么要这么做**：
  - 安全：避免 Key 泄露
  - 可移植：换电脑/换环境只改 `.env`/环境变量
  - 可运维：生产环境统一用环境变量注入

---

#### 2）HTTPS / SSL 校验（为什么 `verify=False` 很危险）

- **这是什么**：HTTPS 的核心是“加密 + 校验证书”。  
  `verify=False` 等于“我不验证对方是不是正确的服务器”，会被中间人攻击。
- **你项目里对应**：现在请求使用 `certifi` 的证书链（`verify=certifi.where()`）。
- **你看到的现象**：开代理时出现 `SSLEOFError` + `Retrying`，本质是代理/链路在 TLS 握手时断开。

---

#### 3）重试（Retry）+ 指数退避（Exponential Backoff）

- **这是什么**：网络请求会偶发失败（超时、断连、临时 5xx）。正确做法是：**自动重试几次**，并且每次等待时间变长（2s、4s、8s…），避免“越失败越狂轰滥炸”。
- **你项目里对应**：
  - 如果装了 `tenacity`：使用更规范的重试策略
  - 没装也能跑：会用简单重试逻辑兜底
- **你得到的好处**：后端不容易因为一次抖动就“直接挂”，稳定性大幅提升。

---

#### 4）日志（Logging）与可观测性（Observability）

- **这是什么**：程序不是只要能跑就行，还要能“看见它在干嘛”。  
  日志能回答：谁请求了什么？花了多久？失败原因是什么？
- **你项目里对应**：
  - `logging`：基础日志
  - `python-json-logger`（可选）：把日志输出成 JSON（方便后续接 ELK、Grafana、云日志）
  - 在 `/api/chat`、`/api/audit` 里记录：IP、请求耗时、模式、向量距离、返回长度、错误堆栈等
- **你得到的好处**：出问题时不用“猜”，看日志就能定位。

---

#### 5）缓存（Cache）：TTL + LRU（省钱 + 加速）

- **这是什么**：
  - **TTL**（Time To Live）：缓存存一段时间，到期自动失效（例如 300 秒）。
  - **LRU**（Least Recently Used）：缓存满了就淘汰“最久没被用过”的数据。
- **你项目里对应**：
  - 对 DeepSeek 的“成功回复”做了缓存（相同输入直接返回，不再调用外部 API）
  - 用哈希（SHA-256）把 prompt/问题生成一个短 key，避免用超长字符串做 key
  - 可调环境变量：
    - `DEEPSEEK_CACHE_TTL_SECONDS`（默认 300）
    - `DEEPSEEK_CACHE_MAX_ITEMS`（默认 128）
- **你得到的好处**：
  - 更快：重复问同一个问题立即返回
  - 更省钱：减少 DeepSeek 调用次数

---

#### 6）限流（Rate Limit）：防止滥用与“误操作刷爆额度”

- **这是什么**：限制“每个 IP 每分钟最多请求多少次”。  
  例如：`/api/chat` 每分钟 30 次，`/api/audit` 每分钟 10 次。
- **你项目里对应**：
  - FastAPI middleware 做了“滑动窗口计数”（内存里记时间戳）
  - 超限返回 `429 Too Many Requests`，并带 `Retry-After`
  - 可调环境变量：
    - `RATE_LIMIT_CHAT_PER_MIN`
    - `RATE_LIMIT_AUDIT_PER_MIN`
- **你得到的好处**：避免被脚本刷爆、避免自己误操作导致成本暴涨。

---

#### 7）CORS（浏览器跨域规则）与可配置 origins

- **这是什么**：浏览器有安全策略：前端页面（比如 `http://localhost:4200`）去请求后端（比如 `http://127.0.0.1:8000`）属于跨域，后端必须允许才行。
- **你项目里对应**：
  - 开发默认 `*`（允许所有来源，方便调试）
  - 生产建议只允许你的前端域名
  - 环境变量：`CORS_ALLOW_ORIGINS=http://localhost:4200,https://your-domain.com`
- **你得到的好处**：开发方便、生产更安全。

---

#### 8）前端 API 地址配置化（不再硬编码）

- **这是什么**：把前端调用后端的地址做成可配置，否则换电脑/换端口就要改源码。
- **你项目里对应**：
  - 新增 `aegis-frontend/src/app/api.config.ts`
  - `AppComponent` 使用 `API_BASE_URL` 拼接 `/api/chat` 和 `/api/audit`
  - 默认仍是 `http://127.0.0.1:8000`，但可以在 `index.html` 里通过 `window.AEGIS_API_URL` 覆盖
- **你得到的好处**：部署更灵活，后续上服务器也不痛苦。

---

#### 9）为什么“我开代理会报 SSL 错”，但“关掉代理就好了”

- **这是什么**：很多代理会对 HTTPS 做“拦截/重签证书/协议改写”，导致 TLS 握手失败。
- **你项目里对应**：
  - 我们已经把后端请求设为尽量直连（并启用证书校验）
  - 你这边最稳的做法就是：**运行 Aegis 时关代理**，或者给关键域名做 bypass（直连）

---

#### 10）“我现在应该怎么用这些知识点”

- **日常开发**：你关代理 → `uvicorn` 起后端 → `ng serve` 起前端
- **遇到问题**：先看日志（失败原因/耗时/是否限流/是否命中缓存）
- **成本优化**：调大缓存 TTL，减少重复调用；需要时再上 Redis（后续第三阶段）

---

### Q5：前端「不再死写 127.0.0.1:8000，用 API_BASE_URL」和「ChatResponse 类型、减少 any」是什么意思？我还是有点不懂

**A：**分两块说。

---

#### 一、为什么不用死写的地址，而用 API_BASE_URL？

**以前（死写）：**
- 代码里直接写：`this.http.post('http://127.0.0.1:8000/api/chat', ...)`
- 问题：**换环境就要改代码**。例如：
  - 你换一台电脑，后端跑在别的 IP
  - 或者部署到服务器，地址变成 `https://api.xxx.com`
  - 每次都要打开 `app.component.ts` 改这一串地址，容易忘、也容易改错

**现在（用 API_BASE_URL）：**
- 地址只在一个地方定义：`api.config.ts` 里的 `API_BASE_URL`
- 发请求时写成：`this.http.post(\`${this.apiBaseUrl}/api/chat\`, ...)`  
  意思是：**「用配置里的那个基础地址 + /api/chat」**
- 好处：
  - **改一次就行**：以后要换地址，只改 `api.config.ts`（或通过 `window.AEGIS_API_URL` 覆盖），不用在组件里到处找
  - **部署友好**：上线时可以通过配置注入不同地址，不用动业务代码

**一句话**：把「后端地址」当成「可配置的一项」，而不是写死在每一行请求里，这就是用 API_BASE_URL 的意思。

---

#### 二、ChatResponse 类型、减少 any，为什么更安全可维护？

**以前（用 any）：**
- 代码里写：`this.http.post<any>(...)`、`handleResponse(res: any)`
- `any` 的意思：**「随便什么类型都行，编译器不检查」**
- 问题：
  - 后端万一改了一个字段名（比如 `reply` 改成 `content`），前端照样编译通过，但运行时会拿不到数据、界面出错，**要跑起来才发现**
  - 你自己过几个月再看代码，不知道 `res` 里到底有哪些字段，没有提示、没有文档感

**现在（用 ChatResponse）：**
- 在 `api.config.ts` 里定义了一个「形状」：

```ts
export interface ChatResponse {
  reply: string;           // 一定有 reply，且是字符串
  mode: 'chat' | 'expert' | 'audit' | 'error' | 'none';  // mode 只能是这几个之一
  distance?: number;       // distance 可有可无，有的话是数字
}
```

- 请求时写成：`this.http.post<ChatResponse>(...)`，`handleResponse(res: ChatResponse)`
- 好处：
  - **编译器会帮你检查**：如果你写了 `res.reply` 没问题；如果你不小心写成 `res.content`，TypeScript 会报错，**改代码时就能发现**，不用等到运行
  - **可维护**：别人（或你以后）看代码时，一眼就知道「后端返回的就是 reply、mode、distance 这几样」，有自动补全、有类型提示

**一句话**：ChatResponse 就是「和后端约定好的返回格式」；用类型代替 any，等于让编译器帮你盯着「有没有用错字段、有没有拼错字」，所以更安全、更好维护。

---

#### 在你项目里对应到哪？

| 概念 | 文件/位置 |
|------|-----------|
| API_BASE_URL 定义 | `aegis-frontend/src/app/api.config.ts` 第一段 |
| 用 apiBaseUrl 发请求 | `app.component.ts` 里 `this.apiBaseUrl + '/api/chat'`、`'/api/audit'` |
| ChatResponse 定义 | `api.config.ts` 里的 `interface ChatResponse` |
| 使用 ChatResponse | `app.component.ts` 里 `post<ChatResponse>` 和 `handleResponse(res: ChatResponse)` |

---

## 后续问题怎么记录？

你每次直接问我问题就行。我会：
- 先回答你的问题
- 再把“问题 + 答案”追加到这个文件里

