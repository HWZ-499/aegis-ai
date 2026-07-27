import hashlib
import subprocess
from pathlib import Path

import pytest

from scripts.benchmark import evaluate_project


def test_default_report_directory_is_versioned_scripts_report_directory() -> None:
    assert evaluate_project.DEFAULT_REPORT_DIR == evaluate_project.PROJECT_ROOT / "scripts" / "reports"


def test_build_provenance_records_reproducible_project_inputs(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "target"
    target.mkdir()
    ground_truth = tmp_path / "ground_truth.json"
    ground_truth.write_text('[{"file": "demo.py", "line": 4}]\n', encoding="utf-8")

    def fake_state(path: Path, *, allow_parent_repository: bool):
        if path == evaluate_project.PROJECT_ROOT:
            return evaluate_project.GitWorktreeState("scanner-revision", True, "scanner-diff")
        assert allow_parent_repository is False
        return evaluate_project.GitWorktreeState("target-revision", False, None)

    monkeypatch.setattr(evaluate_project, "_git_worktree_state", fake_state)

    provenance = evaluate_project.build_provenance(target, ground_truth, "new")

    assert provenance["engine"] == "new"
    assert provenance["reproducible"] is False
    assert provenance["scanner_revision"] == "scanner-revision"
    assert provenance["scanner_dirty"] is True
    assert provenance["scanner_diff_sha256"] == "scanner-diff"
    assert provenance["target_revision"] == "target-revision"
    assert provenance["target_subdir"] == "."
    assert provenance["target_dirty"] is False
    assert provenance["target_diff_sha256"] is None
    assert provenance["ground_truth"] == "ground_truth.json"
    assert provenance["ground_truth_sha256"] == hashlib.sha256(ground_truth.read_bytes()).hexdigest()
    assert provenance["python_version"]
    assert provenance["platform"]


def test_format_provenance_md_marks_unavailable_revisions() -> None:
    report = evaluate_project.format_provenance_md(
        {
            "engine": "new",
            "reproducible": False,
            "scanner_revision": None,
            "scanner_dirty": None,
            "scanner_diff_sha256": None,
            "target_revision": None,
            "target_subdir": None,
            "target_dirty": None,
            "target_diff_sha256": None,
            "ground_truth": "scripts/data/ground_truth.json",
            "ground_truth_sha256": "abc123",
            "python_version": "3.11.0",
            "platform": "test-platform",
            "processor": None,
        }
    )

    assert "Scanner revision: `unavailable`" in report
    assert "Clean release baseline: `no`" in report
    assert "Scanner dirty: `unavailable`" in report
    assert "Target revision: `unavailable`" in report
    assert "Ground truth SHA-256: `abc123`" in report


def test_format_performance_md_records_time_and_memory() -> None:
    report = evaluate_project.format_performance_md(
        {
            "scan_duration_seconds": 1.23456,
            "rss_before_mb": 40.0,
            "rss_after_mb": 48.5,
            "rss_delta_mb": 8.5,
            "process_peak_rss_mb": 52.25,
        }
    )

    assert "Scan duration: `1.235 s`" in report
    assert "RSS delta: `8.500 MiB`" in report
    assert "Process peak RSS: `52.250 MiB`" in report


def test_baseline_gate_reports_quality_performance_and_provenance_regressions() -> None:
    result = evaluate_project.BenchmarkResult(tp=2, fp=4, fn=1, tn=3)
    violations = evaluate_project.baseline_gate_violations(
        result,
        {"scan_duration_seconds": 2.5, "process_peak_rss_mb": None},
        {"target_revision": "wrong", "ground_truth_sha256": "wrong"},
        {
            "target_revision": "expected-revision",
            "ground_truth_sha256": "expected-ground-truth",
            "quality": {"min_tp": 3, "max_fp": 2, "max_fn": 0, "min_tn": 4},
            "performance": {"max_scan_duration_seconds": 2.0, "max_process_peak_rss_mb": 64.0},
        },
    )

    assert violations == [
        "target_revision=wrong must equal expected-revision",
        "ground_truth_sha256=wrong must equal expected-ground-truth",
        "tp=2 must be >= 3",
        "fp=4 must be <= 2",
        "fn=1 must be <= 0",
        "tn=3 must be >= 4",
        "scan_duration_seconds=2.500 must be <= 2.000",
        "process_peak_rss_mb is unavailable but budget 64.0 is required",
    ]


def test_load_target_thresholds_rejects_unknown_target(tmp_path: Path) -> None:
    thresholds = tmp_path / "thresholds.json"
    thresholds.write_text('{"targets": {"known": {"quality": {}}}}\n', encoding="utf-8")

    assert evaluate_project.load_target_thresholds(thresholds, "known") == {"quality": {}}
    with pytest.raises(ValueError, match="No thresholds are defined"):
        evaluate_project.load_target_thresholds(thresholds, "unknown")


def test_git_worktree_state_fingerprints_tracked_and_untracked_changes(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    def git(*args: str) -> None:
        subprocess.run(
            ["git", "-C", str(repository), *args],
            check=True,
            capture_output=True,
            text=True,
        )

    git("init")
    git("config", "user.email", "aegis@example.test")
    git("config", "user.name", "Aegis Test")
    tracked = repository / "tracked.py"
    tracked.write_text("value = 1\n", encoding="utf-8")
    git("add", "tracked.py")
    git("commit", "-m", "initial")

    clean = evaluate_project._git_worktree_state(repository, allow_parent_repository=False)
    assert clean.revision
    assert clean.dirty is False
    assert clean.diff_sha256 is None

    tracked.write_text("value = 2\n", encoding="utf-8")
    untracked = repository / "new.py"
    untracked.write_text("first\n", encoding="utf-8")
    first_dirty = evaluate_project._git_worktree_state(repository, allow_parent_repository=False)
    assert first_dirty.dirty is True
    assert first_dirty.diff_sha256

    untracked.write_text("second\n", encoding="utf-8")
    second_dirty = evaluate_project._git_worktree_state(repository, allow_parent_repository=False)
    assert second_dirty.diff_sha256 != first_dirty.diff_sha256


def test_git_worktree_state_ignores_untracked_scanner_cache(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    def git(*args: str) -> None:
        subprocess.run(
            ["git", "-C", str(repository), *args],
            check=True,
            capture_output=True,
            text=True,
        )

    git("init")
    git("config", "user.email", "aegis@example.test")
    git("config", "user.name", "Aegis Test")
    (repository / "tracked.py").write_text("value = 1\n", encoding="utf-8")
    git("add", "tracked.py")
    git("commit", "-m", "initial")
    cache = repository / "src" / ".aegis-cache"
    cache.mkdir(parents=True)
    (cache / "finding.json").write_text("{}\n", encoding="utf-8")

    state = evaluate_project._git_worktree_state(repository, allow_parent_repository=False)

    assert state.dirty is False
    assert state.diff_sha256 is None


def test_target_state_does_not_borrow_parent_repository_revision(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    target = repository / "target-without-git"
    target.mkdir(parents=True)
    subprocess.run(["git", "-C", str(repository), "init"], check=True, capture_output=True, text=True)

    state = evaluate_project._git_worktree_state(target, allow_parent_repository=False)

    assert state == evaluate_project.GitWorktreeState(None, None, None)


def test_build_provenance_accepts_explicit_repository_root_for_target_subdir(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    target = repository / "demo"
    target.mkdir(parents=True)
    ground_truth = tmp_path / "ground_truth.json"
    ground_truth.write_text("[]\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "init"], check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "aegis@example.test"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repository), "config", "user.name", "Aegis Test"], check=True)
    (target / "demo.py").write_text("value = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repository), "commit", "-m", "initial"], check=True, capture_output=True)

    provenance = evaluate_project.build_provenance(
        target,
        ground_truth,
        "new",
        target_repository_root=repository,
    )

    assert provenance["target_revision"]
    assert provenance["target_dirty"] is False
    assert provenance["target_subdir"] == "demo"


def test_split_ground_truth_scope_excludes_only_explicitly_unsupported_cases() -> None:
    ground_truth = [
        {"file": "routes.js", "line": 12, "type": "OPEN_REDIRECT"},
        {
            "file": "dependency.js",
            "line": 8,
            "type": "PROTOTYPE_POLLUTION",
            "in_scope": False,
            "scope_reason": "The vulnerable code is in a transitive dependency.",
        },
    ]

    evaluated, excluded = evaluate_project.split_ground_truth_scope(ground_truth)

    assert evaluated == [ground_truth[0]]
    assert excluded == [
        {
            "file": "dependency.js",
            "type": "PROTOTYPE_POLLUTION",
            "reason": "The vulnerable code is in a transitive dependency.",
        }
    ]

    all_entries, no_exclusions = evaluate_project.split_ground_truth_scope(
        ground_truth,
        include_out_of_scope=True,
    )
    assert all_entries == ground_truth
    assert no_exclusions == []


def test_format_scope_md_lists_excluded_cases() -> None:
    report = evaluate_project.format_scope_md(
        2,
        1,
        [{"file": "dependency.js", "type": "PROTOTYPE_POLLUTION", "reason": "external dependency"}],
    )

    assert "Entries evaluated: 1" in report
    assert "Explicitly out of scope: 1" in report
    assert "`PROTOTYPE_POLLUTION` in `dependency.js`: external dependency" in report


def test_validate_ground_truth_locations_excludes_stale_expected_patterns(tmp_path: Path) -> None:
    project = tmp_path / "project"
    source_dir = project / "lib"
    source_dir.mkdir(parents=True)
    (source_dir / "routes.js").write_text(
        "const path = '/home';\nres.redirect(path);\n",
        encoding="utf-8",
    )
    ground_truth = [
        {"file": "lib/routes.js", "line": 2, "type": "OPEN_REDIRECT", "expected_pattern": "res.redirect"},
        {"file": "lib/routes.js", "line": 2, "type": "OPEN_REDIRECT", "expected_pattern": "location.assign"},
        {"file": "missing.js", "line": 1, "type": "XSS_RISK"},
    ]

    valid, invalid = evaluate_project.validate_ground_truth_locations(project, ground_truth)

    assert valid == [ground_truth[0]]
    assert invalid == [
        {
            "file": "lib/routes.js",
            "type": "OPEN_REDIRECT",
            "reason": "Expected pattern 'location.assign' is absent within 3 lines of the annotated line.",
        },
        {
            "file": "missing.js",
            "type": "XSS_RISK",
            "reason": "No matching project file exists at this target revision.",
        },
    ]
