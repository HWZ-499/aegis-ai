#!/usr/bin/env python3
"""
PoC 2: 多进程启动延迟

在“类 LSP 场景”下测量：主进程 spawn 子进程、投递一次任务、收到结果的总耗时。
若单次达 200ms 量级，则「保存后实时出 Diagnostic」的体验会崩，需改为常驻守护进程。

运行: 在 aegis-ai-core 下执行
  python scripts/poc2_multiprocessing_latency.py

可选: 在 VS Code 集成终端中运行，以更接近“插件环境”的 Python 启动开销。
"""

import multiprocessing as mp
import sys
import time
from multiprocessing import Process, Queue


def worker_analyze(task_queue: Queue, result_queue: Queue) -> None:
    """
    子进程：从 task_queue 取任务（一段“源码”），模拟分析，把结果放入 result_queue。
    """
    while True:
        try:
            msg = task_queue.get()
            if msg is None:
                break
            # 模拟一次轻量分析（只做占位计算）
            _ = len(msg) + 1
            result_queue.put(("ok", _))
        except Exception as e:
            result_queue.put(("err", str(e)))


def run_one_shot_spawn(code_snippet: str) -> tuple[float, str]:
    """
    每次“分析”都起一个新子进程：主进程启动子进程 -> 投递任务 -> 收结果 -> 结束子进程。
    返回 (总耗时秒, 结果)。
    """
    task_q: Queue = mp.Queue()
    result_q: Queue = mp.Queue()
    t0 = time.perf_counter()
    p = Process(target=worker_analyze, args=(task_q, result_q))
    p.start()
    task_q.put(code_snippet)
    ok, val = result_q.get()
    p.terminate()
    p.join(timeout=2)
    if p.is_alive():
        p.kill()
        p.join()
    t1 = time.perf_counter()
    return t1 - t0, f"{ok}:{val}"


def run_with_persistent_process(code_snippet: str, task_q: Queue, result_q: Queue) -> float:
    """
    假设子进程已常驻：只测“投递任务 + 收结果”的往返时间（不含进程启动）。
    """
    t0 = time.perf_counter()
    task_q.put(code_snippet)
    result_q.get()
    t1 = time.perf_counter()
    return t1 - t0


def main_poc():
    print("=" * 60)
    print("PoC 2: 多进程启动延迟（模拟 LSP 触发一次分析）")
    print("=" * 60)

    # 模拟一次“扫描”传入的代码片段
    code = "def main():\n    x = input()\n    eval(x)\n" * 10  # 约 40 行

    # 1) 每次起新进程（最坏情况：每次保存都起一个新 worker）
    print("\n【1】每次分析都 spawn 新子进程（冷启动）")
    times_one_shot = []
    for i in range(5):
        elapsed, res = run_one_shot_spawn(code)
        times_one_shot.append(elapsed)
        print(f"     第 {i+1} 次: {elapsed*1000:.0f} ms  result={res}")
    avg_one_shot = sum(times_one_shot) / len(times_one_shot) * 1000
    print(f"     平均: {avg_one_shot:.0f} ms")

    # 2) 常驻进程：先起一个进程，再多次只测“投递+返回”
    print("\n【2】常驻子进程：仅测量「投递任务 + 收结果」往返（无进程启动）")
    task_q: Queue = mp.Queue()
    result_q: Queue = mp.Queue()
    p = Process(target=worker_analyze, args=(task_q, result_q))
    p.start()
    try:
        times_persistent = []
        for i in range(5):
            elapsed = run_with_persistent_process(code, task_q, result_q)
            times_persistent.append(elapsed)
            print(f"     第 {i+1} 次: {elapsed*1000:.0f} ms")
        avg_persistent = sum(times_persistent) / len(times_persistent) * 1000
        print(f"     平均: {avg_persistent:.0f} ms")
    finally:
        task_q.put(None)
        p.join(timeout=2)
        if p.is_alive():
            p.kill()
            p.join()

    # 3) 结论
    print("\n【3】结论")
    print(f"     - 每次 spawn 新进程平均: {avg_one_shot:.0f} ms")
    print(f"     - 常驻进程单次往返平均:  {avg_persistent:.0f} ms")
    if avg_one_shot >= 200:
        print("     - 若「实时检测」要求保存后 <200ms 出结果，当前「每次起新进程」不达标，应改为常驻守护进程。")
    else:
        print("     - 当前环境下单次 spawn 低于 200ms，但仍建议实测 VS Code 插件内 Python 启动后再定架构。")
    print("\n" + "=" * 60)
    print("PoC 2 结论: 用 9.1.1 的「常驻守护进程」或「进程池预热」可避免每次 200ms+ 的冷启动。")
    print("=" * 60)


if __name__ == "__main__":
    # Windows 上 spawn 需要 guard
    mp.freeze_support()
    main_poc()
