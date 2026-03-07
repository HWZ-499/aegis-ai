# test_custom_rules.py - 自定义规则加载（P3-3）
"""测试从 extra_dirs 加载 DSL 规则及路径安全校验。"""

from pathlib import Path

import pytest

from src.analysis.dsl.dsl_adapter import load_dsl_rules_for_language


def test_load_without_extra_dirs() -> None:
    """无 extra_dirs 时仅加载内置规则。"""
    rules = load_dsl_rules_for_language("python")
    ids = {r.rule_id for r in rules}
    assert any("dsl" in rid for rid in ids)


def test_load_with_extra_dir(tmp_path: Path) -> None:
    """extra_dirs 中的 YAML 被加载。"""
    yaml_file = tmp_path / "custom.yaml"
    yaml_file.write_text(
        """
id: dsl.test.custom
language: python
severity: MEDIUM
message: "Custom rule"
vuln_type: CUSTOM
patterns:
  - pattern: dangerous_call($X)
""",
        encoding="utf-8",
    )
    rules = load_dsl_rules_for_language(
        "python",
        extra_dirs=[tmp_path],
        allowed_root=tmp_path,
    )
    rule_ids = [r.rule_id for r in rules]
    assert "dsl.test.custom" in rule_ids


def test_extra_dir_outside_allowed_root(tmp_path: Path) -> None:
    """allowed_root 外的目录被跳过。"""
    inside = tmp_path / "inside"
    inside.mkdir()
    (inside / "r.yaml").write_text(
        "id: dsl.inside\nlanguage: python\nseverity: LOW\nmessage: x\nvuln_type: X\npatterns:\n  - pattern: foo($X)\n",
        encoding="utf-8",
    )
    outside = Path(tmp_path).resolve().parent / "outside_rules"
    outside.mkdir(exist_ok=True)
    (outside / "r.yaml").write_text(
        "id: dsl.outside\nlanguage: python\nseverity: LOW\nmessage: x\nvuln_type: X\npatterns:\n  - pattern: bar($X)\n",
        encoding="utf-8",
    )
    rules = load_dsl_rules_for_language(
        "python",
        extra_dirs=[inside, outside],
        allowed_root=tmp_path,
    )
    rule_ids = [r.rule_id for r in rules]
    assert "dsl.inside" in rule_ids
    assert "dsl.outside" not in rule_ids
