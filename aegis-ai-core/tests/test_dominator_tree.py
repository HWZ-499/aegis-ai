from src.analysis.cfg.dominator_tree import (
    CFG,
    ENTRY_ID,
    EXIT_ID,
    DominatorTree,
    build_cfg_from_ast_if_statements,
)


class FakeIfNode:
    def __init__(self, start_line: int, end_line: int) -> None:
        self.start_point = (start_line - 1, 0)
        self.end_point = (end_line - 1, 0)


def test_guard_protected_range_ignores_exit_and_missing_successors() -> None:
    cfg = CFG()
    entry = cfg.add_block()
    entry.block_id = ENTRY_ID
    cfg._blocks[ENTRY_ID] = entry
    cfg.set_entry(entry)

    guard = cfg.add_block(is_guard=True)
    normal = cfg.add_block()
    nested = cfg.add_block()
    exit_block = cfg.add_block(is_exit=True)
    cfg.set_exit(exit_block)

    cfg.add_edge(ENTRY_ID, guard.block_id)
    cfg.add_edge(guard.block_id, normal.block_id)
    cfg.add_edge(guard.block_id, EXIT_ID)
    guard.successors.append(999)  # simulate a stale successor id
    cfg.add_edge(normal.block_id, nested.block_id)
    cfg.add_edge(nested.block_id, EXIT_ID)

    tree = DominatorTree(cfg)

    protected = tree.get_guard_protected_range(guard.block_id)
    assert normal.block_id in protected
    assert nested.block_id in protected
    assert EXIT_ID not in protected
    assert 999 not in protected


def test_ast_guard_cfg_builder_creates_normal_post_guard_branch() -> None:
    cfg = build_cfg_from_ast_if_statements([FakeIfNode(2, 2)], line_range=(1, 5))
    assert cfg is not None

    guard = next(block for block in cfg.blocks if block.is_guard)
    normal_successors = [
        succ
        for succ in guard.successors
        if succ != EXIT_ID and (succ_block := cfg.get_block(succ)) is not None and not succ_block.is_exit
    ]

    assert len(normal_successors) == 1

    tree = DominatorTree(cfg)
    protected = tree.get_guard_protected_range(guard.block_id)
    assert protected == normal_successors
