"""Validate that a component release tag exactly matches package metadata."""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

_STABLE_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def _core_version(repo_root: Path) -> str:
    pyproject = (repo_root / "aegis-ai-core" / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r"(?m)^version\s*=\s*[\"']([^\"']+)[\"']", pyproject)
    if match is None:
        raise ValueError("core version is missing from pyproject.toml")
    return match.group(1)


def _extension_version(repo_root: Path) -> str:
    package = json.loads((repo_root / "aegis-vscode" / "package.json").read_text(encoding="utf-8"))
    version = package.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("extension version is missing from package.json")
    return version


def expected_release_tag(repo_root: Path, component: str) -> str:
    """Return the only tag allowed to publish the selected component."""
    if component == "core":
        version = _core_version(repo_root)
        prefix = "core-v"
    elif component == "vscode":
        version = _extension_version(repo_root)
        prefix = "vscode-v"
    else:
        raise ValueError(f"unsupported component: {component}")
    if not _STABLE_VERSION_RE.fullmatch(version):
        raise ValueError(f"{component} release version must be stable X.Y.Z, got {version!r}")
    return f"{prefix}{version}"


def validate_release_tag(repo_root: Path, component: str, tag: str) -> list[str]:
    try:
        expected = expected_release_tag(repo_root, component)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [str(exc)]
    if tag != expected:
        return [f"{component} release tag must be {expected!r}, got {tag!r}"]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", choices=("core", "vscode"))
    parser.add_argument("tag", nargs="?", default=os.getenv("GITHUB_REF_NAME", ""))
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[2]
    errors = validate_release_tag(repo_root, args.component, args.tag)
    if errors:
        for error in errors:
            print(f"[release-tag] {error}")
        return 1
    print(f"[release-tag] OK {args.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
