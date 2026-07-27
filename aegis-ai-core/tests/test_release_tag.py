from __future__ import annotations

import json
from pathlib import Path

from scripts.check_release_tag import expected_release_tag, validate_release_tag


def _write_versions(repo: Path, core: str = "1.5.0", vscode: str = "0.6.7") -> None:
    (repo / "aegis-ai-core").mkdir(parents=True)
    (repo / "aegis-ai-core" / "pyproject.toml").write_text(
        f'[project]\nname = "aegis-ai-core"\nversion = "{core}"\n',
        encoding="utf-8",
    )
    (repo / "aegis-vscode").mkdir()
    (repo / "aegis-vscode" / "package.json").write_text(
        json.dumps({"name": "aegis-ai-security", "version": vscode}),
        encoding="utf-8",
    )


def test_component_tags_are_namespaced_and_versioned(tmp_path: Path) -> None:
    _write_versions(tmp_path)

    assert expected_release_tag(tmp_path, "core") == "core-v1.5.0"
    assert expected_release_tag(tmp_path, "vscode") == "vscode-v0.6.7"


def test_release_tag_rejects_cross_component_and_mismatched_versions(tmp_path: Path) -> None:
    _write_versions(tmp_path)

    assert validate_release_tag(tmp_path, "core", "vscode-v0.6.7")
    assert validate_release_tag(tmp_path, "core", "core-v1.5.1")
    assert validate_release_tag(tmp_path, "vscode", "core-v1.5.0")


def test_release_tag_rejects_prerelease_package_metadata(tmp_path: Path) -> None:
    _write_versions(tmp_path, core="1.6.0.dev0")

    errors = validate_release_tag(tmp_path, "core", "core-v1.6.0.dev0")

    assert errors == ["core release version must be stable X.Y.Z, got '1.6.0.dev0'"]
