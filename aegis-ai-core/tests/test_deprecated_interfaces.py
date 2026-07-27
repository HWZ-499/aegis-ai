"""Prevent removed pre-1.5 analysis engines from returning to the package."""

from pathlib import Path

import src.analysis.rule_engine as rule_engine
import src.analysis.rules as rules


def test_removed_analysis_modules_are_absent() -> None:
    analysis_root = Path(rule_engine.__file__).parent

    assert not (analysis_root / "ast_analyzer.py").exists()
    assert not (analysis_root / "security_rules.py").exists()
    assert not (analysis_root / "rule_based_audit.py").exists()
    assert not (analysis_root / "rules" / "php" / "__init__.py").exists()
    assert not (analysis_root / "rules" / "php" / "php_taint_rules.py").exists()
    assert not (analysis_root.parent / "scanner" / "rule_config.py").exists()


def test_removed_compatibility_exports_are_absent() -> None:
    removed_engine_exports = {
        "analyze_code_ast",
        "scan_code_locally",
        "VULN_SIGNATURES",
        "VULN_SEVERITY",
        "PhpSQLInjectionRule",
        "PhpRCERule",
        "PhpXSSRule",
        "PhpOpenRedirectRule",
    }
    removed_rule_exports = {
        "PhpSQLInjectionRule",
        "PhpRCERule",
        "PhpXSSRule",
        "PhpOpenRedirectRule",
        "PhpPathTraversalRule",
        "PhpDeserializationRule",
        "PhpNoSQLInjectionRule",
        "PhpHardcodedCredentialsRule",
    }

    assert removed_engine_exports.isdisjoint(rule_engine.__all__)
    assert all(not hasattr(rule_engine, name) for name in removed_engine_exports)
    assert removed_rule_exports.isdisjoint(rules.__all__)
    assert all(not hasattr(rules, name) for name in removed_rule_exports)


def test_compatibility_adapter_depends_only_on_canonical_entry() -> None:
    adapter_source = (Path(rule_engine.__file__).parent / "multi_language_ast.py").read_text(encoding="utf-8")

    assert "analyze_source" in adapter_source
    assert "scan_code_locally" not in adapter_source
    assert "analyze_code_ast" not in adapter_source
