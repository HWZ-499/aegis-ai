from src.analysis.cfg.dominator_tree import (
    CFG,
    ENTRY_ID,
    EXIT_ID,
    DominatorTree,
)


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
