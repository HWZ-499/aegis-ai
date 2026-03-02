"""
analysis.cfg - 控制流图（CFG）与支配树模块

提供 SAST 引擎所需的基础 CFG 构建和支配关系计算能力。

核心概念：
- BasicBlock: 基础块（一段连续无分支的代码序列）
- CFG: 控制流图（基础块 + 有向边）
- DominatorTree: 支配树（节点 d 支配节点 n ⟺ 所有从 Entry 到 n 的路径都经过 d）

应用场景：
- Guard Clause 净化传播：if (!valid) return; 后的代码受到守护
- 循环不变量分析
- 死代码检测
"""

from .dominator_tree import BasicBlock, CFG, DominatorTree, build_cfg_from_taint_graph

__all__ = [
    "BasicBlock",
    "CFG",
    "DominatorTree",
    "build_cfg_from_taint_graph",
]
