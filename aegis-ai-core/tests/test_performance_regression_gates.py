from pathlib import Path

import pytest

from src.analysis.dsl import load_dsl_rule_definitions
from src.analysis.rule_engine import get_default_rules_for_language
from src.analysis.taint.cross_file_analyzer import CrossFileAnalyzer


def test_repeated_module_resolution_has_bounded_candidate_checks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repeated imports must hit the module cache instead of probing every candidate."""
    module = tmp_path / "shared.py"
    module.write_text("value = 1\n", encoding="utf-8")
    analyzer = CrossFileAnalyzer(tmp_path)
    analyzer._project_source_files = {analyzer._path_index_key(module)}

    candidate_checks = 0
    original_exists = analyzer._source_file_exists

    def counted_exists(candidate: Path | str) -> bool:
        nonlocal candidate_checks
        candidate_checks += 1
        return original_exists(candidate)

    monkeypatch.setattr(analyzer, "_source_file_exists", counted_exists)

    for _ in range(200):
        assert analyzer._find_module_in_project("shared") == module

    assert candidate_checks <= 10


def test_preloaded_dsl_rules_never_reload_directories_per_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Project-preloaded definitions must remove filesystem loading from per-file setup."""
    definitions = load_dsl_rule_definitions()

    def fail_reload(*args, **kwargs):
        raise AssertionError("preloaded DSL definitions should avoid directory reloads")

    monkeypatch.setattr("src.analysis.dsl.dsl_adapter.load_dsl_rule_definitions", fail_reload)

    for _ in range(200):
        rules = get_default_rules_for_language(
            "python",
            dsl_rule_definitions=definitions,
        )
        assert rules
