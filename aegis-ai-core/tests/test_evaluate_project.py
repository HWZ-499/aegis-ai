import hashlib
from pathlib import Path

from scripts.benchmark import evaluate_project


def test_build_provenance_records_reproducible_project_inputs(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "target"
    target.mkdir()
    ground_truth = tmp_path / "ground_truth.json"
    ground_truth.write_text('[{"file": "demo.py", "line": 4}]\n', encoding="utf-8")

    monkeypatch.setattr(
        evaluate_project,
        "_git_revision",
        lambda path: "scanner-revision" if path == evaluate_project.PROJECT_ROOT else "target-revision",
    )

    provenance = evaluate_project.build_provenance(target, ground_truth, "new")

    assert provenance["engine"] == "new"
    assert provenance["scanner_revision"] == "scanner-revision"
    assert provenance["target_revision"] == "target-revision"
    assert provenance["ground_truth"] == "ground_truth.json"
    assert provenance["ground_truth_sha256"] == hashlib.sha256(ground_truth.read_bytes()).hexdigest()


def test_format_provenance_md_marks_unavailable_revisions() -> None:
    report = evaluate_project.format_provenance_md(
        {
            "engine": "new",
            "scanner_revision": None,
            "target_revision": None,
            "ground_truth": "scripts/data/ground_truth.json",
            "ground_truth_sha256": "abc123",
        }
    )

    assert "Scanner revision: `unavailable`" in report
    assert "Target revision: `unavailable`" in report
    assert "Ground truth SHA-256: `abc123`" in report


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
