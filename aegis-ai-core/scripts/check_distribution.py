"""Validate release artifact contents, identity, and bundled-backend integrity."""

from __future__ import annotations

import argparse
import configparser
import glob
import hashlib
import io
import json
import re
import tarfile
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import default
from pathlib import Path
from typing import Any

_RETIRED_FILES = (
    "src/analysis/ast_analyzer.py",
    "src/analysis/security_rules.py",
    "src/analysis/rule_based_audit.py",
    "src/analysis/rules/php/__init__.py",
    "src/analysis/rules/php/php_taint_rules.py",
    "src/scanner/rule_config.py",
)
_FORBIDDEN_CACHE_MARKERS = (
    "/.mypy_cache/",
    "/.pytest_cache/",
    "/.ruff_cache/",
    "/__pycache__/",
)
_FORBIDDEN_VSIX_MARKERS = (
    "/extension/.vscode-test/",
    "/extension/node_modules/",
    "/extension/scripts/",
    "/extension/src/",
    "/extension/resources/aegis-ai-core/real_world_targets/",
    "/extension/resources/aegis-ai-core/tests/",
)
_REQUIRED_CORE_SOURCES = (
    "src/__init__.py",
    "src/analysis/rule_engine.py",
    "src/lsp/__main__.py",
    "src/scanner/cli.py",
)
_REQUIRED_WHEEL_SUFFIXES = (
    *_REQUIRED_CORE_SOURCES,
    ".dist-info/METADATA",
    ".dist-info/WHEEL",
    ".dist-info/entry_points.txt",
)
_REQUIRED_SDIST_SUFFIXES = (
    *_REQUIRED_CORE_SOURCES,
    "PKG-INFO",
    "README.md",
    "pyproject.toml",
)
_REQUIRED_VSIX_SUFFIXES = (
    "extension/CHANGELOG.md",
    "extension/out/extension.js",
    "extension/package.json",
    "extension/resources/aegis-ai-core/README.md",
    "extension/resources/aegis-ai-core/backend-manifest.json",
    "extension/resources/aegis-ai-core/pyproject.toml",
    "extension/resources/aegis-ai-core/src/analysis/rule_engine.py",
    "extension/resources/aegis-ai-core/src/lsp/__main__.py",
    "extension/resources/aegis-ai-core/src/scanner/cli.py",
)
_REQUIRED_CONSOLE_SCRIPTS = {
    "aegis": "src.scanner.cli:main",
    "aegis-lsp": "src.lsp.__main__:main",
    "aegis-scan": "src.scanner.cli:main",
}
_WHEEL_FILENAME_RE = re.compile(r"^aegis_ai_core-(?P<version>\d+\.\d+\.\d+)-.+\.whl$", re.IGNORECASE)
_SDIST_FILENAME_RE = re.compile(r"^aegis_ai_core-(?P<version>\d+\.\d+\.\d+)\.tar\.(?:gz|bz2|xz)$", re.IGNORECASE)
_VSIX_FILENAME_RE = re.compile(r"^aegis-ai-security-(?P<version>\d+\.\d+\.\d+)\.vsix$", re.IGNORECASE)


@dataclass(frozen=True)
class _ArchiveEntry:
    raw_name: str
    name: str
    data: bytes


@dataclass(frozen=True)
class ReleaseMetadata:
    core_version: str
    extension_version: str
    python_requirement: str


def _normalize_archive_name(name: str) -> str:
    return name.replace("\\", "/").lstrip("./")


def _read_archive(path: Path) -> list[_ArchiveEntry]:
    entries: list[_ArchiveEntry] = []
    if path.suffix.lower() in {".whl", ".vsix"} or zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if not info.is_dir():
                    entries.append(
                        _ArchiveEntry(info.filename, _normalize_archive_name(info.filename), archive.read(info))
                    )
        return entries
    if path.name.lower().endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        with tarfile.open(path, mode="r:*") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                extracted = archive.extractfile(member)
                if extracted is not None:
                    entries.append(_ArchiveEntry(member.name, _normalize_archive_name(member.name), extracted.read()))
        return entries
    raise ValueError(f"unsupported distribution format: {path}")


def _archive_kind(path: Path) -> str:
    if path.suffix.lower() == ".whl":
        return "wheel"
    if path.suffix.lower() == ".vsix":
        return "VSIX"
    if path.name.lower().endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        return "sdist"
    return "archive"


def _matches_suffix(name: str, suffix: str) -> bool:
    lowered_name = name.lower()
    lowered_suffix = suffix.lower().lstrip("/")
    if lowered_suffix.startswith(".dist-info/"):
        return lowered_name.endswith(lowered_suffix)
    return lowered_name == lowered_suffix or lowered_name.endswith(f"/{lowered_suffix}")


def _matching_entries(entries: list[_ArchiveEntry], suffix: str) -> list[_ArchiveEntry]:
    return [entry for entry in entries if _matches_suffix(entry.name, suffix)]


def _required_file_violations(entries: list[_ArchiveEntry], required: tuple[str, ...], kind: str) -> list[str]:
    return [f"missing required {kind} file: {suffix}" for suffix in required if not _matching_entries(entries, suffix)]


def _single_entry(entries: list[_ArchiveEntry], suffix: str, violations: list[str], kind: str) -> _ArchiveEntry | None:
    matches = _matching_entries(entries, suffix)
    if not matches:
        return None
    if len(matches) > 1 and "/" not in suffix:
        shallowest_depth = min(entry.name.count("/") for entry in matches)
        shallowest = [entry for entry in matches if entry.name.count("/") == shallowest_depth]
        if len(shallowest) == 1:
            return shallowest[0]
    if len(matches) > 1:
        violations.append(f"multiple {kind} files match {suffix}: {', '.join(entry.raw_name for entry in matches)}")
        return None
    return matches[0]


def _canonical_project_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _normalize_requirement(requirement: str) -> tuple[str, ...]:
    return tuple(sorted(part.strip().replace(" ", "") for part in requirement.split(",") if part.strip()))


def _parse_package_metadata(entry: _ArchiveEntry, violations: list[str], kind: str) -> dict[str, str] | None:
    try:
        message = BytesParser(policy=default).parsebytes(entry.data)
    except (TypeError, ValueError) as exc:
        violations.append(f"invalid {kind} package metadata: {exc}")
        return None
    return {
        "name": str(message.get("Name", "")),
        "version": str(message.get("Version", "")),
        "requires_python": str(message.get("Requires-Python", "")),
    }


def _extract_pyproject_field(text: str, field: str) -> str:
    match = re.search(rf"(?m)^{re.escape(field)}\s*=\s*[\"']([^\"']+)[\"']", text)
    return match.group(1) if match else ""


def _parse_pyproject(entry: _ArchiveEntry, violations: list[str], kind: str) -> dict[str, str] | None:
    try:
        text = entry.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        violations.append(f"invalid {kind} pyproject.toml encoding: {exc}")
        return None
    metadata = {
        "name": _extract_pyproject_field(text, "name"),
        "version": _extract_pyproject_field(text, "version"),
        "requires_python": _extract_pyproject_field(text, "requires-python"),
    }
    if not all(metadata.values()):
        violations.append(f"invalid {kind} pyproject.toml: project name, version, and requires-python are required")
        return None
    return metadata


def _validate_core_identity(
    metadata: dict[str, str],
    *,
    artifact_version: str,
    expected_version: str | None,
    expected_python_requirement: str | None,
    kind: str,
    violations: list[str],
) -> None:
    if _canonical_project_name(metadata["name"]) != "aegis-ai-core":
        violations.append(f"{kind} project name must be 'aegis-ai-core', got {metadata['name']!r}")
    if metadata["version"] != artifact_version:
        violations.append(
            f"{kind} metadata version {metadata['version']!r} does not match artifact filename version {artifact_version!r}"
        )
    if expected_version is not None and metadata["version"] != expected_version:
        violations.append(f"{kind} version must match source version {expected_version!r}, got {metadata['version']!r}")
    if not metadata["requires_python"]:
        violations.append(f"{kind} metadata must declare Requires-Python")
    elif expected_python_requirement is not None and _normalize_requirement(
        metadata["requires_python"]
    ) != _normalize_requirement(expected_python_requirement):
        violations.append(
            f"{kind} Requires-Python must match source requirement {expected_python_requirement!r}, "
            f"got {metadata['requires_python']!r}"
        )


def _validate_console_scripts(entry: _ArchiveEntry, violations: list[str]) -> None:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_file(io.StringIO(entry.data.decode("utf-8")))
    except (UnicodeDecodeError, configparser.Error) as exc:
        violations.append(f"invalid wheel entry_points.txt: {exc}")
        return
    scripts = dict(parser.items("console_scripts")) if parser.has_section("console_scripts") else {}
    for command, target in _REQUIRED_CONSOLE_SCRIPTS.items():
        if scripts.get(command) != target:
            violations.append(f"wheel console script {command!r} must target {target!r}")


def _filename_version(path: Path, pattern: re.Pattern[str], kind: str, violations: list[str]) -> str | None:
    match = pattern.fullmatch(path.name)
    if match is None:
        violations.append(f"{kind} filename must contain a stable Aegis X.Y.Z version: {path.name}")
        return None
    return match.group("version")


def _validate_wheel(
    path: Path,
    entries: list[_ArchiveEntry],
    *,
    expected_core_version: str | None,
    expected_python_requirement: str | None,
) -> list[str]:
    violations = _required_file_violations(entries, _REQUIRED_WHEEL_SUFFIXES, "wheel")
    version = _filename_version(path, _WHEEL_FILENAME_RE, "wheel", violations)
    metadata_entry = _single_entry(entries, ".dist-info/METADATA", violations, "wheel metadata")
    if version is not None and metadata_entry is not None:
        metadata = _parse_package_metadata(metadata_entry, violations, "wheel")
        if metadata is not None:
            _validate_core_identity(
                metadata,
                artifact_version=version,
                expected_version=expected_core_version,
                expected_python_requirement=expected_python_requirement,
                kind="wheel",
                violations=violations,
            )
    entry_points = _single_entry(entries, ".dist-info/entry_points.txt", violations, "wheel entry point")
    if entry_points is not None:
        _validate_console_scripts(entry_points, violations)
    return violations


def _validate_sdist(
    path: Path,
    entries: list[_ArchiveEntry],
    *,
    expected_core_version: str | None,
    expected_python_requirement: str | None,
) -> list[str]:
    violations = _required_file_violations(entries, _REQUIRED_SDIST_SUFFIXES, "sdist")
    version = _filename_version(path, _SDIST_FILENAME_RE, "sdist", violations)
    metadata_entry = _single_entry(entries, "PKG-INFO", violations, "sdist metadata")
    pyproject_entry = _single_entry(entries, "pyproject.toml", violations, "sdist pyproject")
    parsed_metadata: dict[str, str] | None = None
    parsed_pyproject: dict[str, str] | None = None
    if metadata_entry is not None:
        parsed_metadata = _parse_package_metadata(metadata_entry, violations, "sdist")
    if pyproject_entry is not None:
        parsed_pyproject = _parse_pyproject(pyproject_entry, violations, "sdist")
    if version is not None:
        for kind, metadata in (("sdist", parsed_metadata), ("sdist pyproject", parsed_pyproject)):
            if metadata is not None:
                _validate_core_identity(
                    metadata,
                    artifact_version=version,
                    expected_version=expected_core_version,
                    expected_python_requirement=expected_python_requirement,
                    kind=kind,
                    violations=violations,
                )
    return violations


def _parse_json(entry: _ArchiveEntry, violations: list[str], kind: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(entry.data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        violations.append(f"invalid {kind} JSON: {exc}")
        return None
    if not isinstance(payload, dict):
        violations.append(f"invalid {kind} JSON: expected an object")
        return None
    return payload


def _validate_backend_manifest(entries: list[_ArchiveEntry], violations: list[str]) -> None:
    manifest_entry = _single_entry(
        entries,
        "extension/resources/aegis-ai-core/backend-manifest.json",
        violations,
        "VSIX backend manifest",
    )
    if manifest_entry is None:
        return
    manifest = _parse_json(manifest_entry, violations, "VSIX backend manifest")
    if manifest is None:
        return

    prefix = "extension/resources/aegis-ai-core/"
    backend_files = [
        (entry.name[len(prefix) :], entry.data)
        for entry in entries
        if entry.name.startswith(prefix) and entry.name != f"{prefix}backend-manifest.json"
    ]
    backend_files.sort(key=lambda item: item[0])
    digest = hashlib.sha256()
    for relative_path, data in backend_files:
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")

    if manifest.get("manifestVersion") != 1:
        violations.append(f"VSIX backend manifestVersion must be 1, got {manifest.get('manifestVersion')!r}")
    if manifest.get("files") != len(backend_files):
        violations.append(
            f"VSIX backend manifest file count must be {len(backend_files)}, got {manifest.get('files')!r}"
        )
    actual_fingerprint = digest.hexdigest()
    if manifest.get("fingerprint") != actual_fingerprint:
        violations.append("VSIX backend manifest fingerprint does not match packaged backend files")


def _validate_vsix(
    path: Path,
    entries: list[_ArchiveEntry],
    *,
    expected_core_version: str | None,
    expected_extension_version: str | None,
    expected_python_requirement: str | None,
) -> list[str]:
    violations = _required_file_violations(entries, _REQUIRED_VSIX_SUFFIXES, "VSIX")
    version = _filename_version(path, _VSIX_FILENAME_RE, "VSIX", violations)

    package_entry = _single_entry(entries, "extension/package.json", violations, "VSIX package manifest")
    package = _parse_json(package_entry, violations, "VSIX package manifest") if package_entry is not None else None
    if package is not None and version is not None:
        if package.get("name") != "aegis-ai-security":
            violations.append(f"VSIX extension name must be 'aegis-ai-security', got {package.get('name')!r}")
        if package.get("version") != version:
            violations.append(
                f"VSIX package version {package.get('version')!r} does not match artifact filename version {version!r}"
            )
        if expected_extension_version is not None and package.get("version") != expected_extension_version:
            violations.append(
                f"VSIX version must match source version {expected_extension_version!r}, got {package.get('version')!r}"
            )
        if package.get("preview") is not False:
            violations.append("stable VSIX package must set preview to false")

    pyproject_entry = _single_entry(
        entries,
        "extension/resources/aegis-ai-core/pyproject.toml",
        violations,
        "VSIX bundled pyproject",
    )
    if pyproject_entry is not None:
        metadata = _parse_pyproject(pyproject_entry, violations, "VSIX bundled backend")
        if metadata is not None:
            bundled_version = metadata["version"]
            _validate_core_identity(
                metadata,
                artifact_version=bundled_version,
                expected_version=expected_core_version,
                expected_python_requirement=expected_python_requirement,
                kind="VSIX bundled backend",
                violations=violations,
            )
    _validate_backend_manifest(entries, violations)
    return violations


def _generic_content_violations(entries: list[_ArchiveEntry], kind: str) -> list[str]:
    violations: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        lowered_name = entry.name.lower()
        duplicate_key = lowered_name.rstrip("/")
        if duplicate_key in seen:
            violations.append(f"duplicate archive path: {entry.raw_name}")
        seen.add(duplicate_key)

        normalized = f"/{lowered_name.strip('/')}"
        if any(lowered_name == retired or lowered_name.endswith(f"/{retired}") for retired in _RETIRED_FILES) or any(
            marker in f"{normalized}/" for marker in _FORBIDDEN_CACHE_MARKERS
        ):
            violations.append(entry.raw_name)
        if kind == "VSIX" and (
            any(marker in f"{normalized}/" for marker in _FORBIDDEN_VSIX_MARKERS)
            or lowered_name.endswith((".map", ".pyc", ".pyd", ".pyo"))
        ):
            violations.append(entry.raw_name)
    return violations


def validate_distribution(
    path: Path,
    *,
    expected_core_version: str | None = None,
    expected_extension_version: str | None = None,
    expected_python_requirement: str | None = None,
) -> list[str]:
    """Return content, identity, and integrity violations for one release artifact."""
    entries = _read_archive(path)
    kind = _archive_kind(path)
    violations = _generic_content_violations(entries, kind)
    if kind == "wheel":
        violations.extend(
            _validate_wheel(
                path,
                entries,
                expected_core_version=expected_core_version,
                expected_python_requirement=expected_python_requirement,
            )
        )
    elif kind == "sdist":
        violations.extend(
            _validate_sdist(
                path,
                entries,
                expected_core_version=expected_core_version,
                expected_python_requirement=expected_python_requirement,
            )
        )
    elif kind == "VSIX":
        violations.extend(
            _validate_vsix(
                path,
                entries,
                expected_core_version=expected_core_version,
                expected_extension_version=expected_extension_version,
                expected_python_requirement=expected_python_requirement,
            )
        )
    return list(dict.fromkeys(violations))


def _expand_distribution_paths(paths: list[Path]) -> list[Path]:
    """Expand shell-style globs even when the caller shell does not."""
    expanded: list[Path] = []
    for path in paths:
        matches = [Path(match) for match in glob.glob(str(path))]
        expanded.extend(matches or [path])
    return expanded


def _load_release_metadata(repo_root: Path) -> ReleaseMetadata:
    core_text = (repo_root / "aegis-ai-core" / "pyproject.toml").read_text(encoding="utf-8")
    package = json.loads((repo_root / "aegis-vscode" / "package.json").read_text(encoding="utf-8"))
    core_version = _extract_pyproject_field(core_text, "version")
    python_requirement = _extract_pyproject_field(core_text, "requires-python")
    extension_version = package.get("version")
    if not core_version or not python_requirement:
        raise ValueError("source pyproject.toml must declare project version and requires-python")
    if not isinstance(extension_version, str) or not extension_version:
        raise ValueError("source package.json must declare the extension version")
    return ReleaseMetadata(core_version, extension_version, python_requirement)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("distributions", nargs="+", type=Path)
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[2]
    try:
        expected = _load_release_metadata(repo_root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[distribution] ERROR source release metadata: {exc}")
        return 1

    failed = False
    for distribution in _expand_distribution_paths(args.distributions):
        try:
            violations = validate_distribution(
                distribution,
                expected_core_version=expected.core_version,
                expected_extension_version=expected.extension_version,
                expected_python_requirement=expected.python_requirement,
            )
        except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
            print(f"[distribution] ERROR {distribution}: {exc}")
            failed = True
            continue
        if violations:
            failed = True
            print(f"[distribution] FAIL {distribution}")
            for violation in violations:
                print(f"  violation: {violation}")
        else:
            print(f"[distribution] OK {distribution}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
