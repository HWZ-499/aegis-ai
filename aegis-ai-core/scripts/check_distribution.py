"""Reject built distributions that contain retired modules or local caches."""

from __future__ import annotations

import argparse
import tarfile
import zipfile
from pathlib import Path

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


def _archive_names(path: Path) -> list[str]:
    if path.suffix == ".whl" or zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            return archive.namelist()
    if path.name.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        with tarfile.open(path) as archive:
            return archive.getnames()
    raise ValueError(f"unsupported distribution format: {path}")


def validate_distribution(path: Path) -> list[str]:
    """Return forbidden paths found in a wheel, source archive, or VSIX."""
    violations: list[str] = []
    for raw_name in _archive_names(path):
        name = raw_name.replace("\\", "/").lstrip("./")
        normalized = f"/{name.strip('/')}"
        if any(name == retired or name.endswith(f"/{retired}") for retired in _RETIRED_FILES) or any(
            marker in f"{normalized}/" for marker in _FORBIDDEN_CACHE_MARKERS
        ):
            violations.append(raw_name)
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("distributions", nargs="+", type=Path)
    args = parser.parse_args(argv)

    failed = False
    for distribution in args.distributions:
        try:
            violations = validate_distribution(distribution)
        except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
            print(f"[distribution] ERROR {distribution}: {exc}")
            failed = True
            continue
        if violations:
            failed = True
            print(f"[distribution] FAIL {distribution}")
            for violation in violations:
                print(f"  forbidden content: {violation}")
        else:
            print(f"[distribution] OK {distribution}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
