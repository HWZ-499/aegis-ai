# PoC 验证脚本（TDD 12.3）

用于验证「内联坐标映射」与「多进程启动延迟」两项核心风险。

## 运行方式

在 **aegis-ai-core** 目录下执行：

```bash
# PoC 1：内联与坐标地狱
python scripts/poc1_inline_coordinate_hell.py

# PoC 2：多进程启动延迟
python scripts/poc2_multiprocessing_latency.py
```

建议在 VS Code 集成终端中再跑一遍 PoC 2，以更接近插件环境的 Python 启动开销。

## PoC 1 结论

- 内联后，漏洞可能出现在「调用处」或「定义处」的节点；仅用单一行号上报会导致用户看到调用点或定义点，理解不完整。
- **必须**在内联时维护 **虚拟节点 → (CallSite, DefinitionSite)** 映射表，并在上报时提供两处或按策略选主位置。

## PoC 2 结论

- **每次 spawn 新进程**：当前环境约 90–110ms/次；若在插件/CI 下接近或超过 200ms，则「保存后实时 Diagnostic」体验不可接受。
- **常驻子进程**：首次请求有约 90ms 级延迟（进程已起、首次通信），后续单次往返可低至 &lt;1ms。
- 架构建议：采用 **常驻守护进程** 或 **进程池预热**，避免每次分析都冷启动新进程。
