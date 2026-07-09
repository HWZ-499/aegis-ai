from pathlib import Path

from scripts.typecheck_gate import TYPECHECK_GROUPS, resolve_typecheck_targets


def test_ci_typecheck_group_covers_all_source_modules() -> None:
    assert resolve_typecheck_targets("ci") == ["src/"]


def test_typecheck_gate_has_no_non_blocking_legacy_group() -> None:
    assert set(TYPECHECK_GROUPS) == {"ci"}


def test_all_typecheck_targets_exist_in_repo() -> None:
    repo_root = Path(__file__).resolve().parents[1]

    for targets in TYPECHECK_GROUPS.values():
        for target in targets:
            assert (repo_root / target).exists(), f"Missing typecheck target: {target}"


def test_unknown_typecheck_group_raises() -> None:
    try:
        resolve_typecheck_targets("unknown")
    except ValueError as exc:
        assert "unknown typecheck group" in str(exc).lower()
    else:
        raise AssertionError("resolve_typecheck_targets should reject unknown groups")


def test_ci_workflow_has_no_legacy_type_debt_escape_hatch() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    workflow = (repo_root / ".github" / "workflows" / "security-scan.yml").read_text(encoding="utf-8")

    assert "python scripts/typecheck_gate.py --group ci" in workflow
    assert "legacy-report" not in workflow
    assert "mypy-legacy-report" not in workflow
