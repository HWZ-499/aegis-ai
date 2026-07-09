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
