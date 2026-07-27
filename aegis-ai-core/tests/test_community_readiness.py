from __future__ import annotations

from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[1]
_REPO_ROOT = _CORE_ROOT.parent


def test_community_entry_points_are_documented() -> None:
    root_readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
    docs_index = (_REPO_ROOT / "docs" / "README.md").read_text(encoding="utf-8")

    assert "CONTRIBUTING.md" in root_readme
    assert "SECURITY.md" in root_readme
    assert "DSL_RULE_AUTHORING.md" in root_readme
    assert "community-rule.yaml" in root_readme
    assert "DSL_RULE_AUTHORING.md" in docs_index


def test_rule_authoring_guide_describes_executable_contract() -> None:
    guide = (_REPO_ROOT / "docs" / "technical" / "DSL_RULE_AUTHORING.md").read_text(encoding="utf-8")

    required_markers = {
        "aegis rules init",
        "aegis rules test",
        ".aegis/rules",
        "expect_findings",
        "metavariables",
        "line-oriented",
        "true-positive",
        "true-negative",
    }
    assert all(marker in guide for marker in required_markers)


def test_contribution_and_security_policies_have_safe_routing() -> None:
    contributing = (_REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    security = (_REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")

    assert "python -m pytest" in contributing
    assert "npm test" in contributing
    assert "SECURITY.md" in contributing
    assert "Do not include vulnerability details" in security
    assert "Report a vulnerability" in security
    assert "90 days" in security


def test_issue_template_links_current_repository_policies() -> None:
    config = (_REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml").read_text(encoding="utf-8")

    assert "github.com/HWZ-499/aegis-ai" in config
    assert "github.com/aegis-ai/aegis-ai" not in config
    assert "/security/policy" in config
