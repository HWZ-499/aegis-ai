from __future__ import annotations

import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path

from scripts.check_distribution import _expand_distribution_paths, validate_distribution

CORE_VERSION = "1.5.0"
EXTENSION_VERSION = "0.6.7"
PYTHON_REQUIREMENT = ">=3.10,<3.13"


def _core_metadata(version: str = CORE_VERSION) -> str:
    return f"Metadata-Version: 2.3\nName: aegis-ai-core\nVersion: {version}\nRequires-Python: {PYTHON_REQUIREMENT}\n"


def _core_pyproject(version: str = CORE_VERSION) -> str:
    return f'[project]\nname = "aegis-ai-core"\nversion = "{version}"\nrequires-python = "{PYTHON_REQUIREMENT}"\n'


def _entry_points(*, include_lsp: bool = True) -> str:
    lines = ["[console_scripts]", "aegis = src.scanner.cli:main", "aegis-scan = src.scanner.cli:main"]
    if include_lsp:
        lines.append("aegis-lsp = src.lsp.__main__:main")
    return "\n".join(lines) + "\n"


def _write_valid_wheel(
    path: Path,
    *,
    metadata_version: str = CORE_VERSION,
    include_lsp_entry_point: bool = True,
    extra_files: dict[str, str] | None = None,
) -> None:
    dist_info = f"aegis_ai_core-{CORE_VERSION}.dist-info"
    files = {
        "src/__init__.py": "",
        "src/analysis/rule_engine.py": "",
        "src/lsp/__main__.py": "",
        "src/scanner/cli.py": "",
        f"{dist_info}/METADATA": _core_metadata(metadata_version),
        f"{dist_info}/WHEEL": "Wheel-Version: 1.0\nTag: py3-none-any\n",
        f"{dist_info}/entry_points.txt": _entry_points(include_lsp=include_lsp_entry_point),
    }
    files.update(extra_files or {})
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)


def _add_tar_text(archive: tarfile.TarFile, name: str, content: str) -> None:
    data = content.encode("utf-8")
    info = tarfile.TarInfo(name)
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))


def _write_valid_sdist(path: Path, *, extra_files: dict[str, str] | None = None) -> None:
    root = f"aegis_ai_core-{CORE_VERSION}"
    files = {
        "PKG-INFO": _core_metadata(),
        "README.md": "# Aegis AI Core\n",
        "aegis_ai_core.egg-info/PKG-INFO": _core_metadata(),
        "pyproject.toml": _core_pyproject(),
        "src/__init__.py": "",
        "src/analysis/rule_engine.py": "",
        "src/lsp/__main__.py": "",
        "src/scanner/cli.py": "",
    }
    files.update(extra_files or {})
    with tarfile.open(path, "w:gz") as archive:
        for name, content in files.items():
            _add_tar_text(archive, f"{root}/{name}", content)


def _backend_manifest(files: dict[str, bytes], *, valid_fingerprint: bool = True) -> bytes:
    prefix = "extension/resources/aegis-ai-core/"
    backend_files = sorted(
        (name.removeprefix(prefix), data)
        for name, data in files.items()
        if name.startswith(prefix) and name != f"{prefix}backend-manifest.json"
    )
    digest = hashlib.sha256()
    for relative_path, data in backend_files:
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    fingerprint = digest.hexdigest() if valid_fingerprint else "0" * 64
    return json.dumps({"manifestVersion": 1, "fingerprint": fingerprint, "files": len(backend_files)}).encode()


def _write_valid_vsix(
    path: Path,
    *,
    extension_version: str = EXTENSION_VERSION,
    include_core_readme: bool = True,
    valid_fingerprint: bool = True,
    extra_files: dict[str, str] | None = None,
) -> None:
    prefix = "extension/resources/aegis-ai-core/"
    files: dict[str, bytes] = {
        "extension/CHANGELOG.md": b"# Changelog\n",
        "extension/out/extension.js": b"module.exports = {};\n",
        "extension/package.json": json.dumps(
            {"name": "aegis-ai-security", "version": extension_version, "preview": False}
        ).encode(),
        f"{prefix}pyproject.toml": _core_pyproject().encode(),
        f"{prefix}src/analysis/rule_engine.py": b"",
        f"{prefix}src/lsp/__main__.py": b"",
        f"{prefix}src/scanner/cli.py": b"",
    }
    if include_core_readme:
        files[f"{prefix}README.md"] = b"# Aegis AI Core\n"
    for name, content in (extra_files or {}).items():
        files[name] = content.encode()
    files[f"{prefix}backend-manifest.json"] = _backend_manifest(files, valid_fingerprint=valid_fingerprint)
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)


def test_distribution_gate_accepts_complete_release_artifacts(tmp_path: Path) -> None:
    wheel = tmp_path / f"aegis_ai_core-{CORE_VERSION}-py3-none-any.whl"
    sdist = tmp_path / f"aegis_ai_core-{CORE_VERSION}.tar.gz"
    vsix = tmp_path / f"aegis-ai-security-{EXTENSION_VERSION}.vsix"
    _write_valid_wheel(wheel)
    _write_valid_sdist(sdist)
    _write_valid_vsix(vsix)

    expected = {
        "expected_core_version": CORE_VERSION,
        "expected_extension_version": EXTENSION_VERSION,
        "expected_python_requirement": PYTHON_REQUIREMENT,
    }
    assert validate_distribution(wheel, **expected) == []
    assert validate_distribution(sdist, **expected) == []
    assert validate_distribution(vsix, **expected) == []


def test_distribution_gate_rejects_retired_module_in_wheel(tmp_path: Path) -> None:
    wheel = tmp_path / f"aegis_ai_core-{CORE_VERSION}-py3-none-any.whl"
    _write_valid_wheel(wheel, extra_files={"src/analysis/security_rules.py": ""})

    assert validate_distribution(wheel) == ["src/analysis/security_rules.py"]


def test_distribution_gate_rejects_retired_module_in_sdist(tmp_path: Path) -> None:
    archive_path = tmp_path / f"aegis_ai_core-{CORE_VERSION}.tar.gz"
    _write_valid_sdist(archive_path, extra_files={"src/scanner/rule_config.py": ""})

    assert validate_distribution(archive_path) == [f"aegis_ai_core-{CORE_VERSION}/src/scanner/rule_config.py"]


def test_distribution_gate_rejects_local_cache_in_vsix(tmp_path: Path) -> None:
    vsix = tmp_path / f"aegis-ai-security-{EXTENSION_VERSION}.vsix"
    _write_valid_vsix(vsix, extra_files={"extension/.pytest_cache/v/cache/nodeids": "[]"})

    assert validate_distribution(vsix) == ["extension/.pytest_cache/v/cache/nodeids"]


def test_distribution_gate_rejects_vsix_missing_core_package_readme(tmp_path: Path) -> None:
    vsix = tmp_path / f"aegis-ai-security-{EXTENSION_VERSION}.vsix"
    _write_valid_vsix(vsix, include_core_readme=False)

    assert validate_distribution(vsix) == ["missing required VSIX file: extension/resources/aegis-ai-core/README.md"]


def test_distribution_gate_rejects_wheel_metadata_version_mismatch(tmp_path: Path) -> None:
    wheel = tmp_path / f"aegis_ai_core-{CORE_VERSION}-py3-none-any.whl"
    _write_valid_wheel(wheel, metadata_version="1.4.0")

    assert validate_distribution(wheel) == [
        "wheel metadata version '1.4.0' does not match artifact filename version '1.5.0'"
    ]


def test_distribution_gate_rejects_missing_console_entry_point(tmp_path: Path) -> None:
    wheel = tmp_path / f"aegis_ai_core-{CORE_VERSION}-py3-none-any.whl"
    _write_valid_wheel(wheel, include_lsp_entry_point=False)

    assert validate_distribution(wheel) == ["wheel console script 'aegis-lsp' must target 'src.lsp.__main__:main'"]


def test_distribution_gate_rejects_stale_vsix_version(tmp_path: Path) -> None:
    old_version = "0.6.6"
    vsix = tmp_path / f"aegis-ai-security-{old_version}.vsix"
    _write_valid_vsix(vsix, extension_version=old_version)

    assert validate_distribution(vsix, expected_extension_version=EXTENSION_VERSION) == [
        "VSIX version must match source version '0.6.7', got '0.6.6'"
    ]


def test_distribution_gate_rejects_modified_bundled_backend(tmp_path: Path) -> None:
    vsix = tmp_path / f"aegis-ai-security-{EXTENSION_VERSION}.vsix"
    _write_valid_vsix(vsix, valid_fingerprint=False)

    assert validate_distribution(vsix) == ["VSIX backend manifest fingerprint does not match packaged backend files"]


def test_distribution_gate_expands_globs_for_powershell_callers(tmp_path: Path) -> None:
    first = tmp_path / f"aegis-ai-core-{CORE_VERSION}.whl"
    second = tmp_path / f"aegis-ai-core-{CORE_VERSION}.tar.gz"
    first.touch()
    second.touch()

    expanded = _expand_distribution_paths([tmp_path / f"aegis-ai-core-{CORE_VERSION}*"])

    assert set(expanded) == {first, second}
