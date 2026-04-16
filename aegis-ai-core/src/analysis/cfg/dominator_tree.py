"""
dominator_tree.py - 控制流图（CFG）与支配树实现

面向 SAST 引擎的轻量级 CFG + Dominator Tree，专注于：
1. 从 Tree-sitter AST 构建函数级基础块
2. 使用 Cooper et al. (2001) 的简单高效算法计算支配关系
3. 识别 Guard Clause（早返回）的支配范围

参考文献：
    Cooper, Keith D., Timothy J. Harvey, and Ken Kennedy.
    "A simple, fast dominance algorithm." (2001)
    Software Engineering Research 4 (2001): 1-10.

设计原则：
- 轻量级：不依赖外部图算法库，纯 Python 实现
- 精确性：基础块级别的支配关系（不是行级）
- 可查询：外部代码通过 `dominates(a, b)` 查询 a 是否支配 b
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BasicBlock:
    """
    基础块。

    一段连续、无内部分支的代码序列。
    进入点只能是块头，退出点只能是块尾（跳转/返回/抛出）。
    """

    block_id: int
    """块唯一 ID（0 为 Entry，负数为 Exit）"""

    start_line: int = 0
    """块起始行号（1-based）"""

    end_line: int = 0
    """块结束行号（1-based，含）"""

    # 节点引用（可选，用于调试）
    ast_nodes: list[Any] = field(default_factory=list)

    # 后继和前驱
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)

    # 是否是退出块（含 return / throw / raise / die）
    is_exit: bool = False

    # Guard Clause 标记：此块包含早返回检查（if (!x) return;）
    is_guard: bool = False

    # 被此块守护的变量（经过验证后续代码中认为已净化）
    guarded_vars: set[str] = field(default_factory=set)

    def __repr__(self) -> str:
        return f"BB{self.block_id}[{self.start_line}-{self.end_line}]"


# Entry / Exit 块的预定义 ID
ENTRY_ID = 0
EXIT_ID = -1


class CFG:
    """
    函数级控制流图。

    节点：BasicBlock
    边：后继关系（有向）

    构建完成后用于：
    1. 计算支配树（DominatorTree）
    2. 识别 Guard Clause 的支配范围
    3. 死代码路径识别（支配但无后继）
    """

    def __init__(self) -> None:
        self._blocks: dict[int, BasicBlock] = {}
        self._entry: BasicBlock | None = None
        self._exit: BasicBlock | None = None
        self._next_id: int = 1

    def add_block(
        self,
        start_line: int = 0,
        end_line: int = 0,
        is_exit: bool = False,
        is_guard: bool = False,
        guarded_vars: set[str] | None = None,
    ) -> BasicBlock:
        """创建并注册一个新基础块。"""
        block_id = EXIT_ID if is_exit else self._next_id
        if not is_exit:
            self._next_id += 1

        block = BasicBlock(
            block_id=block_id,
            start_line=start_line,
            end_line=end_line,
            is_exit=is_exit,
            is_guard=is_guard,
            guarded_vars=guarded_vars or set(),
        )
        self._blocks[block_id] = block
        return block

    def set_entry(self, block: BasicBlock) -> None:
        """设置入口块。"""
        self._entry = block

    def set_exit(self, block: BasicBlock) -> None:
        """设置出口块。"""
        self._exit = block

    def add_edge(self, from_id: int, to_id: int) -> None:
        """添加有向边（from → to）。"""
        src = self._blocks.get(from_id)
        dst = self._blocks.get(to_id)
        if src is None or dst is None:
            return
        if to_id not in src.successors:
            src.successors.append(to_id)
        if from_id not in dst.predecessors:
            dst.predecessors.append(from_id)

    def get_block(self, block_id: int) -> BasicBlock | None:
        """按 ID 获取基础块。"""
        return self._blocks.get(block_id)

    @property
    def entry(self) -> BasicBlock | None:
        return self._entry

    @property
    def exit(self) -> BasicBlock | None:
        return self._exit

    @property
    def blocks(self) -> list[BasicBlock]:
        """返回所有基础块（按 ID 排序）。"""
        return sorted(self._blocks.values(), key=lambda b: b.block_id)

    def get_all_block_ids(self) -> list[int]:
        """返回所有块 ID（按后序 RPO 顺序，用于支配树算法）。"""
        if self._entry is None:
            return list(self._blocks.keys())
        # BFS 从 entry 出发，收集可达块
        visited: list[int] = []
        queue: list[int] = [self._entry.block_id]
        seen: set[int] = set()
        while queue:
            bid = queue.pop(0)
            if bid in seen:
                continue
            seen.add(bid)
            visited.append(bid)
            block = self._blocks.get(bid)
            if block:
                for succ in block.successors:
                    if succ not in seen:
                        queue.append(succ)
        return visited


class DominatorTree:
    """
    支配树（Dominator Tree）。

    使用 Cooper et al. (2001) 的简单迭代算法：
    1. 以 RPO（逆后序）编号各基础块
    2. 反复用 intersect 操作更新每个块的直接支配者（idom）
    3. 直到不动点

    时间复杂度：O(N²) 最坏，实践中接近 O(N log N)。
    对于单函数级 CFG（通常 < 50 个基础块），完全足够。

    查询接口：
    - `dominates(a_id, b_id)` → a 是否支配 b
    - `get_dominance_frontier(block_id)` → 支配边界
    - `get_dominated_blocks(block_id)` → a 严格支配的所有块
    """

    def __init__(self, cfg: CFG) -> None:
        self._cfg = cfg
        # idom[b] = b 的直接支配者 ID（Entry 的 idom 是自己）
        self._idom: dict[int, int] = {}
        # RPO 编号：rpo_order[i] = 第 i 个块的 ID（按逆后序）
        self._rpo_order: list[int] = []
        # 块 ID → RPO 编号
        self._rpo_num: dict[int, int] = {}

        self._compute()

    def _compute(self) -> None:
        """计算支配树（Cooper et al. 2001 算法）。"""
        entry = self._cfg.entry
        if entry is None:
            return

        # 1. 计算 RPO（逆后序）
        self._rpo_order = self._compute_rpo(entry.block_id)
        for i, bid in enumerate(self._rpo_order):
            self._rpo_num[bid] = i

        # 2. 初始化：Entry 的 idom 是自己，其余未定义
        entry_id = entry.block_id
        self._idom = {entry_id: entry_id}

        # 3. 迭代至不动点
        changed = True
        while changed:
            changed = False
            for bid in self._rpo_order:
                if bid == entry_id:
                    continue
                block = self._cfg.get_block(bid)
                if block is None:
                    continue
                # 从已定义 idom 的前驱中选择第一个
                defined_preds = [p for p in block.predecessors if p in self._idom]
                if not defined_preds:
                    continue
                new_idom = defined_preds[0]
                for pred in defined_preds[1:]:
                    new_idom = self._intersect(pred, new_idom)
                if self._idom.get(bid) != new_idom:
                    self._idom[bid] = new_idom
                    changed = True

        logger.debug(
            "支配树计算完成: %d 个块, %d 个 idom 条目",
            len(self._rpo_order),
            len(self._idom),
        )

    def _compute_rpo(self, entry_id: int) -> list[int]:
        """
        计算从 entry_id 出发的逆后序（RPO）。

        RPO = 后序的逆序，保证支配者总在被支配者之前处理。
        """
        post_order: list[int] = []
        visited: set[int] = set()

        def dfs(bid: int) -> None:
            if bid in visited:
                return
            visited.add(bid)
            block = self._cfg.get_block(bid)
            if block:
                for succ in block.successors:
                    dfs(succ)
            post_order.append(bid)

        dfs(entry_id)
        return list(reversed(post_order))

    def _intersect(self, b1: int, b2: int) -> int:
        """
        找到 b1 和 b2 在支配树中的最近公共祖先（LCA）。

        Cooper et al. 的 intersect 函数，沿 idom 链向上直到相遇。
        """
        finger1, finger2 = b1, b2
        while finger1 != finger2:
            rpo1 = self._rpo_num.get(finger1, -1)
            rpo2 = self._rpo_num.get(finger2, -1)
            while rpo1 > rpo2:
                finger1 = self._idom.get(finger1, finger1)
                rpo1 = self._rpo_num.get(finger1, -1)
            while rpo2 > rpo1:
                finger2 = self._idom.get(finger2, finger2)
                rpo2 = self._rpo_num.get(finger2, -1)
        return finger1

    def dominates(self, a_id: int, b_id: int) -> bool:
        """
        判断基础块 a 是否支配基础块 b。

        a 支配 b ⟺ 所有从 Entry 到 b 的路径都经过 a。

        Args:
            a_id: 候选支配者的块 ID
            b_id: 被支配块的 ID

        Returns:
            True 如果 a 支配 b（含 a == b 的自支配情况）
        """
        if a_id == b_id:
            return True
        # 沿 b 的 idom 链向上查找，看是否经过 a
        current = b_id
        visited: set[int] = set()
        while current != a_id:
            if current in visited:
                return False  # 防止环路
            visited.add(current)
            parent = self._idom.get(current)
            if parent is None or parent == current:
                return False  # 到达 Entry 或无法上溯
            current = parent
        return True

    def strictly_dominates(self, a_id: int, b_id: int) -> bool:
        """
        a 严格支配 b（a ≠ b 且 a 支配 b）。
        """
        return a_id != b_id and self.dominates(a_id, b_id)

    def get_dominated_blocks(self, block_id: int) -> list[int]:
        """
        获取被 block_id 严格支配的所有块 ID。

        用于确定 Guard Clause 的有效守护范围：
        Guard 块严格支配的所有后继块都受到其净化保护。

        Args:
            block_id: Guard 块 ID

        Returns:
            严格被支配的块 ID 列表
        """
        return [bid for bid in self._rpo_order if self.strictly_dominates(block_id, bid)]

    def get_idom(self, block_id: int) -> int | None:
        """获取块的直接支配者 ID。"""
        idom = self._idom.get(block_id)
        return idom if idom != block_id else None

    def get_dominance_frontier(self, block_id: int) -> list[int]:
        """
        计算 block_id 的支配边界（Dominance Frontier）。

        DF(n) = { y | (x → y) ∈ E, n 支配 x 但 n 不严格支配 y }

        Args:
            block_id: 目标块 ID

        Returns:
            支配边界块 ID 列表
        """
        df: list[int] = []
        dominated = set(self.get_dominated_blocks(block_id)) | {block_id}
        for bid in dominated:
            block = self._cfg.get_block(bid)
            if block is None:
                continue
            for succ in block.successors:
                if succ not in dominated or succ == block_id:
                    if succ not in df:
                        df.append(succ)
        return df

    def get_guard_protected_range(self, guard_block_id: int) -> list[int]:
        """
        获取 Guard Clause 块保护的基础块范围。

        定义：Guard 块退出到 Exit 的路径（早返回），
        而另一条路径上被 Guard 严格支配的所有块都处于"已验证"状态。

        Args:
            guard_block_id: 含早返回检查的基础块 ID

        Returns:
            受保护的基础块 ID 列表（Guard 验证通过后执行的块）
        """
        guard_block = self._cfg.get_block(guard_block_id)
        if guard_block is None or not guard_block.is_guard:
            return []

        # Guard 块的后继分为两类：
        # 1. 早返回分支（指向 Exit）
        # 2. 正常继续分支（指向下一个块）
        normal_successors = [
            s
            for s in guard_block.successors
            if s != EXIT_ID and (succ_block := self._cfg.get_block(s)) is not None and not succ_block.is_exit
        ]

        protected: list[int] = []
        for succ_id in normal_successors:
            # 正常分支后的所有被支配块都处于 Guard 保护范围内
            protected.append(succ_id)
            protected.extend(self.get_dominated_blocks(succ_id))

        return list(set(protected))


def build_cfg_from_taint_graph(taint_graph: Any) -> CFG | None:
    """
    从 TaintGraph 构建轻量级 CFG（用于已有污点图的场景）。

    将 TaintGraph 中的 Source/Sink/SANITIZER 节点映射为基础块，
    用于在污点路径上做支配关系查询（判断净化节点是否支配 Sink 节点）。

    Args:
        taint_graph: TaintGraph 实例

    Returns:
        构建的 CFG，失败时返回 None
    """
    try:
        if taint_graph is None:
            return None

        cfg = CFG()
        entry_block = cfg.add_block(start_line=0, end_line=0)
        entry_block.block_id = ENTRY_ID
        cfg._blocks[ENTRY_ID] = entry_block
        cfg.set_entry(entry_block)

        exit_block = cfg.add_block(start_line=0, end_line=0, is_exit=True)
        cfg.set_exit(exit_block)

        # 将污点图节点按行号映射到基础块
        nodes_by_line: dict[int, list[Any]] = {}
        for node_id, node in getattr(taint_graph, "_nodes", {}).items():
            line = getattr(node, "line", 0) or 0
            if line not in nodes_by_line:
                nodes_by_line[line] = []
            nodes_by_line[line].append(node)

        if not nodes_by_line:
            return None

        # 为每行创建一个基础块
        prev_block_id: int | None = ENTRY_ID
        block_by_line: dict[int, int] = {}

        for line in sorted(nodes_by_line.keys()):
            block = cfg.add_block(start_line=line, end_line=line)
            block_by_line[line] = block.block_id
            if prev_block_id is not None:
                cfg.add_edge(prev_block_id, block.block_id)
            prev_block_id = block.block_id

        # 最后一个块连接到 Exit
        if prev_block_id is not None and prev_block_id != ENTRY_ID:
            cfg.add_edge(prev_block_id, EXIT_ID)

        return cfg

    except (RuntimeError, ValueError) as e:
        logger.debug("build_cfg_from_taint_graph 失败: %s", e)
        return None


def build_cfg_from_ast_if_statements(
    if_nodes: list[Any],
    line_range: tuple | None = None,
) -> CFG | None:
    """
    从 if 语句节点列表构建轻量级 CFG，专用于 Guard Clause 分析。

    每个 if 语句被建模为：
        prev_block → guard_block → [exit_branch, normal_branch]

    Args:
        if_nodes: Tree-sitter if_statement 节点列表
        line_range: 函数的行范围 (start, end)，用于构建全局 entry/exit

    Returns:
        构建的 CFG，失败时返回 None
    """
    try:
        cfg = CFG()
        entry_block = cfg.add_block(start_line=0, end_line=0)
        entry_block.block_id = ENTRY_ID
        cfg._blocks[ENTRY_ID] = entry_block
        cfg.set_entry(entry_block)

        exit_block = cfg.add_block(start_line=0, end_line=0, is_exit=True)
        cfg.set_exit(exit_block)

        if not if_nodes:
            cfg.add_edge(ENTRY_ID, EXIT_ID)
            return cfg

        prev_id = ENTRY_ID

        for if_node in if_nodes:
            start_line = if_node.start_point[0] + 1 if hasattr(if_node, "start_point") else 0
            end_line = if_node.end_point[0] + 1 if hasattr(if_node, "end_point") else start_line

            # 创建 Guard 块
            guard_block = cfg.add_block(
                start_line=start_line,
                end_line=end_line,
                is_guard=True,
            )
            cfg.add_edge(prev_id, guard_block.block_id)

            # Guard 的"早返回"分支
            cfg.add_edge(guard_block.block_id, EXIT_ID)

            # Guard 的"正常继续"分支将连接到下一个块
            prev_id = guard_block.block_id

        # 最终正常分支连接 Exit
        # (实际使用时这里应该连接到函数 Sink 所在块)
        cfg.add_edge(prev_id, EXIT_ID)

        return cfg

    except (RuntimeError, ValueError) as e:
        logger.debug("build_cfg_from_ast_if_statements 失败: %s", e)
        return None


__all__ = [
    "BasicBlock",
    "CFG",
    "DominatorTree",
    "ENTRY_ID",
    "EXIT_ID",
    "build_cfg_from_taint_graph",
    "build_cfg_from_ast_if_statements",
]
