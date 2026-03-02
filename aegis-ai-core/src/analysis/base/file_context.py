"""
file_context.py - 文件角色辅助（降低误报）

提供基于路径的启发式判断，供 SQL/NoSQL 等规则统一使用，
用于抑制或降级种子/迁移/建表类文件中的误报。
"""

from __future__ import annotations

from pathlib import Path

# 路径或文件名包含以下片段（大小写不敏感）时，视为疑似种子/迁移/建表
SEED_OR_MIGRATION_PARTS = (
    "datacreator",
    "db-reset",
    "db_reset",
    "seed",
    "migration",
    "migrations",
    "schema",
    "fixture",
    "fixtures",
    "artifacts",
)

# 白名单收窄：仅当路径匹配以下片段时才视为种子/迁移（降低误伤含 seed 的业务文件）
STRICT_SEED_PATH_PARTS = (
    "datacreator",
    "db-reset",
    "db_reset",
    "artifacts/db-reset",
    "data/datacreator",
    "/seeds/",
    "/seed/",
    "/migrations/",
    "/migration/",
    "/fixtures/",
    "/fixture/",
)


def is_likely_seed_or_migration(file_path: Path, strict: bool = False) -> bool:
    """
    判断当前文件是否疑似种子数据/迁移/建表脚本。

    用于在 SQL 模板字符串、NoSQL insertMany/insertOne 等场景中
    抑制或降级误报（种子数据中的 SQL/插入不应按用户输入处理）。

    Args:
        file_path: 当前分析文件的路径。
        strict: 若 True，则使用白名单收窄：仅当路径匹配 STRICT_SEED_PATH_PARTS 时才返回 True，
                可降低误伤名称含 seed 的业务文件；默认 False 保持原有关键词匹配。

    Returns:
        True 若路径或文件名符合种子/迁移启发式，否则 False。
    """
    path_str = str(file_path).replace("\\", "/").lower()
    if strict:
        for part in STRICT_SEED_PATH_PARTS:
            if part in path_str:
                return True
        return False
    name = file_path.name.lower()
    for part in SEED_OR_MIGRATION_PARTS:
        if part in path_str or part in name:
            return True
    return False
