from pathlib import Path

from src.scanner.cli import _build_ai_code_contexts


def test_build_ai_code_contexts_prefers_absolute_finding_path(tmp_path: Path) -> None:
    project_path = tmp_path / "project"
    project_path.mkdir()
    rel_file = project_path / "src" / "app.js"
    rel_file.parent.mkdir(parents=True)
    rel_file.write_text("console.log('relative');", encoding="utf-8")

    absolute_file = tmp_path / "outside.js"
    absolute_file.write_text("console.log('absolute');", encoding="utf-8")

    results = {
        "src/app.js": [
            {"file_path": str(absolute_file)},
        ]
    }

    contexts = _build_ai_code_contexts(results, project_path)

    assert contexts["src/app.js"] == "console.log('absolute');"


def test_build_ai_code_contexts_falls_back_to_project_relative_path(tmp_path: Path) -> None:
    project_path = tmp_path / "project"
    project_path.mkdir()
    rel_file = project_path / "src" / "app.js"
    rel_file.parent.mkdir(parents=True)
    rel_file.write_text("console.log('relative');", encoding="utf-8")

    results = {
        "src/app.js": [
            {"line": 1},
        ]
    }

    contexts = _build_ai_code_contexts(results, project_path)

    assert contexts["src/app.js"] == "console.log('relative');"
