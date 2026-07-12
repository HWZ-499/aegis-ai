from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

from scripts.check_distribution import _expand_distribution_paths, validate_distribution


def test_distribution_gate_accepts_current_package_layout(tmp_path: Path) -> None:
    wheel = tmp_path / "aegis_ai_core-1.5.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("src/analysis/rule_engine.py", "")
        archive.writestr("src/analysis/multi_language_ast.py", "")

    assert validate_distribution(wheel) == []


def test_distribution_gate_rejects_retired_module_in_wheel(tmp_path: Path) -> None:
    wheel = tmp_path / "aegis_ai_core-1.5.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("src/analysis/security_rules.py", "")

    assert validate_distribution(wheel) == ["src/analysis/security_rules.py"]


def test_distribution_gate_rejects_retired_module_in_sdist(tmp_path: Path) -> None:
    source_file = tmp_path / "rule_config.py"
    source_file.write_text("", encoding="utf-8")
    archive_path = tmp_path / "aegis_ai_core-1.5.0.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(source_file, arcname="aegis_ai_core-1.5.0/src/scanner/rule_config.py")

    assert validate_distribution(archive_path) == [
        "aegis_ai_core-1.5.0/src/scanner/rule_config.py"
    ]


def test_distribution_gate_rejects_local_cache_in_vsix(tmp_path: Path) -> None:
    vsix = tmp_path / "aegis-ai-security-0.6.7.vsix"
    with zipfile.ZipFile(vsix, "w") as archive:
        archive.writestr("extension/CHANGELOG.md", "")
        archive.writestr("extension/resources/aegis-ai-core/pyproject.toml", "")
        archive.writestr("extension/resources/aegis-ai-core/README.md", "")
        archive.writestr("extension/.pytest_cache/v/cache/nodeids", "[]")

    assert validate_distribution(vsix) == ["extension/.pytest_cache/v/cache/nodeids"]


def test_distribution_gate_rejects_vsix_missing_core_package_readme(tmp_path: Path) -> None:
    vsix = tmp_path / "aegis-ai-security-0.6.7.vsix"
    with zipfile.ZipFile(vsix, "w") as archive:
        archive.writestr("extension/CHANGELOG.md", "")
        archive.writestr("extension/resources/aegis-ai-core/pyproject.toml", "")

    assert validate_distribution(vsix) == [
        "missing required VSIX file: extension/resources/aegis-ai-core/readme.md"
    ]


def test_distribution_gate_expands_globs_for_powershell_callers(tmp_path: Path) -> None:
    first = tmp_path / "aegis-ai-core-1.5.0.whl"
    second = tmp_path / "aegis-ai-core-1.5.0.tar.gz"
    first.touch()
    second.touch()

    expanded = _expand_distribution_paths([tmp_path / "aegis-ai-core-1.5.0*"])

    assert set(expanded) == {first, second}
