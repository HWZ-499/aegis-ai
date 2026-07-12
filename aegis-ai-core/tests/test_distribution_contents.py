from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

from scripts.check_distribution import validate_distribution


def test_distribution_gate_accepts_current_package_layout(tmp_path: Path) -> None:
    wheel = tmp_path / "aegis_ai_core-1.5.0.dev0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("src/analysis/rule_engine.py", "")
        archive.writestr("src/analysis/multi_language_ast.py", "")

    assert validate_distribution(wheel) == []


def test_distribution_gate_rejects_retired_module_in_wheel(tmp_path: Path) -> None:
    wheel = tmp_path / "aegis_ai_core-1.5.0.dev0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("src/analysis/security_rules.py", "")

    assert validate_distribution(wheel) == ["src/analysis/security_rules.py"]


def test_distribution_gate_rejects_retired_module_in_sdist(tmp_path: Path) -> None:
    source_file = tmp_path / "rule_config.py"
    source_file.write_text("", encoding="utf-8")
    archive_path = tmp_path / "aegis_ai_core-1.5.0.dev0.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(source_file, arcname="aegis_ai_core-1.5.0.dev0/src/scanner/rule_config.py")

    assert validate_distribution(archive_path) == [
        "aegis_ai_core-1.5.0.dev0/src/scanner/rule_config.py"
    ]
