from pathlib import Path

from src.analysis.dependency_tracker import DependencyTracker


def _write(path: Path, content: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_dependency_tracker_resolves_python_package_relative_imports(tmp_path: Path) -> None:
    root = tmp_path
    importer = root / "app" / "services" / "handler.py"
    helper = root / "app" / "services" / "helper.py"
    model = root / "app" / "models.py"
    utils = root / "app" / "utils.py"

    _write(root / "app" / "__init__.py")
    _write(root / "app" / "services" / "__init__.py")
    _write(helper, "def render():\n    return 'ok'\n")
    _write(model, "class User:\n    pass\n")
    _write(utils, "def sanitize(value):\n    return value\n")
    _write(
        importer,
        "\n".join(
            [
                "from . import helper",
                "from ..models import User",
                "from ..utils import sanitize",
                "",
            ]
        ),
    )

    tracker = DependencyTracker()
    tracker.update_imports(str(importer), importer.read_text(encoding="utf-8"), "python", str(root))

    assert str(importer) in tracker.get_affected_files(str(helper.resolve()))
    assert str(importer) in tracker.get_affected_files(str(model.resolve()))
    assert str(importer) in tracker.get_affected_files(str(utils.resolve()))


def test_dependency_tracker_resolves_python_absolute_imports_from_project_root(tmp_path: Path) -> None:
    root = tmp_path
    importer = root / "app" / "views.py"
    utils = root / "app" / "utils.py"

    _write(root / "app" / "__init__.py")
    _write(utils, "def sanitize(value):\n    return value\n")
    _write(importer, "from app.utils import sanitize\n")

    tracker = DependencyTracker()
    tracker.update_imports(str(importer), importer.read_text(encoding="utf-8"), "python", str(root))

    assert str(importer) in tracker.get_affected_files(str(utils.resolve()))


def test_dependency_tracker_regex_fallback_resolves_relative_imports_in_incomplete_python(
    tmp_path: Path,
) -> None:
    root = tmp_path
    importer = root / "app" / "views.py"
    helpers = root / "app" / "helpers.py"

    _write(root / "app" / "__init__.py")
    _write(helpers, "def normalize(value):\n    return value\n")
    _write(importer, "from . import helpers\nif broken:\n")

    tracker = DependencyTracker()
    tracker.update_imports(str(importer), importer.read_text(encoding="utf-8"), "python", str(root))

    assert str(importer) in tracker.get_affected_files(str(helpers.resolve()))


def test_export_hash_tracks_signatures_after_first_200_lines(tmp_path: Path) -> None:
    target = tmp_path / "late_api.py"
    tracker = DependencyTracker()
    base_code = "\n".join(["# filler"] * 220 + ["def late_api(value):", "    return value"])
    changed_code = "\n".join(["# filler"] * 220 + ["def late_api(value, default=None):", "    return value"])

    assert tracker.update_export_hash(str(target), base_code) is True
    assert tracker.update_export_hash(str(target), base_code) is False
    assert tracker.update_export_hash(str(target), changed_code) is True
