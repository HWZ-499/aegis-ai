# 进程模型与守护进程（TDD 9.1.1）

本文档说明当前实现与 TDD 的对应关系，以及后续 LSP 对接守护进程的方式。

## 当前状态

- **LSP**：仍以**同进程**方式运行（LSP 进程内直接调用 `rule_engine.analyze_*`），适用于单文件、小项目。
- **守护进程**：已提供骨架 `src/worker_daemon.py`，用于验证「单守护进程 + 任务队列 + 内存保护」的可行性，**尚未**与 LSP 对接。

## 守护进程骨架用法

在 **aegis-ai-core** 目录下：

```bash
# 启动守护进程（自动选端口，打印到 stdout）
python -m src.worker_daemon --port 0

# 可选：限制请求次数与内存后优雅退出
python -m src.worker_daemon --port 0 --max-requests 1000 --max-memory-mb 500
```

- 父进程（如扩展或 LSP）读取第一行得到端口，再通过 TCP 发送 JSON 请求：  
  `{"file_path": "...", "content": "源码", "language": "javascript"}\n`  
- 守护进程返回：`{"findings": [...]}\n`
- 达到 `max_requests` 或内存超过 `max_memory_mb` 时进程退出，由父进程重新拉起（Graceful Restart）。

## 后续 LSP 对接要点

1. **启动时机**：扩展激活时先启动 `worker_daemon`（或由 LSP 在首次需要时启动），再启动 LSP；或 LSP 作为 Client 连接已有 daemon。
2. **IPC**：当前骨架使用 **TCP 127.0.0.1**；生产可改为 **Named Pipe**（Windows）或 **Unix Domain Socket**（Linux/macOS）以省端口。
3. **进程生命周期**：  
   - 守护进程崩溃或退出：LSP/扩展检测到连接断开后**重启守护进程**并重连。  
   - 扩展 deactivate：向守护进程发送 shutdown 消息并等待其退出，避免僵尸进程。
4. **内存保护**：已内置于 daemon（请求数/内存上限后退出）；LSP 侧只需在检测到 daemon 退出后重新拉起。

## 参考

- TDD 第 9.1.1 节：性能与进程模型、单守护进程 + 任务队列、进程生命周期、内存保护策略。
