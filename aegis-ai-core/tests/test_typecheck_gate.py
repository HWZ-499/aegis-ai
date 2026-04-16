from pathlib import Path

from scripts.typecheck_gate import TYPECHECK_GROUPS, resolve_typecheck_targets


def test_ci_typecheck_group_covers_release_gate_modules() -> None:
    targets = resolve_typecheck_targets("ci")

    assert "src/lsp/" in targets
    assert "src/scanner/project_scanner.py" in targets
    assert "src/scanner/baseline.py" in targets
    assert "src/scanner/ai_analyzer.py" in targets
    assert "src/analysis/incremental_analyzer.py" in targets
    assert "src/analysis/rule_engine.py" in targets


def test_ci_typecheck_group_covers_cli_and_release_surfaces() -> None:
    targets = resolve_typecheck_targets("ci")

    assert "src/analysis/dependency_tracker.py" in targets
    assert "src/core/models.py" in targets
    assert "src/scanner/cli.py" in targets
    assert "src/scanner/report_generator.py" in targets


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
