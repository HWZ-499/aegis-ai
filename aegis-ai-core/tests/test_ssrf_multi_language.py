from pathlib import Path

import pytest

from src.analysis.rule_engine import (
    analyze_go,
    analyze_java,
    analyze_php,
    get_default_rules_for_language,
)
from src.analysis.rules.ssrf import (
    GoSSRFAstRule,
    JavaScriptSSRFAstRule,
    JavaSSRFAstRule,
    PhpSSRFAstRule,
    PythonSSRFAstRule,
)
from src.lsp.server import scan_document
from src.scanner.project_scanner import ProjectScanner


def _identity(findings: list[dict]) -> list[tuple[object, ...]]:
    return sorted(
        (
            finding.get("type"),
            finding.get("rule_id"),
            finding.get("line"),
            finding.get("severity"),
        )
        for finding in findings
        if finding.get("type") == "SSRF"
    )


@pytest.mark.parametrize(
    ("language", "suffix", "source", "analyze", "rule_id"),
    [
        (
            "php",
            ".php",
            "<?php $url = $_GET['url']; file_get_contents($url);",
            analyze_php,
            "SSRF_PHP_AST",
        ),
        (
            "java",
            ".java",
            (
                "class FetchController {"
                " void fetch(HttpServletRequest request) {"
                ' String url = request.getParameter("url");'
                " new RestTemplate().getForObject(url, String.class);"
                " }"
                "}"
            ),
            analyze_java,
            "SSRF_JAVA_AST",
        ),
        (
            "go",
            ".go",
            (
                "package samples\n"
                'import "net/http"\n'
                "func fetch(r *http.Request) {\n"
                ' target := r.FormValue("url")\n'
                " http.Get(target)\n"
                "}\n"
            ),
            analyze_go,
            "SSRF_GO_AST",
        ),
    ],
)
def test_ssrf_is_consistent_across_lsp_public_api_and_project_scan(
    tmp_path: Path,
    language: str,
    suffix: str,
    source: str,
    analyze,
    rule_id: str,
) -> None:
    source_file = tmp_path / f"sample{suffix}"
    source_file.write_text(source, encoding="utf-8")

    lsp_findings = scan_document(source, str(source_file))
    public_findings = analyze(source, str(source_file))
    project_findings = ProjectScanner(
        str(tmp_path),
        use_cache=False,
        use_parallel=False,
    ).scan_file(source_file)

    expected = _identity(public_findings)
    assert _identity(lsp_findings) == expected
    assert _identity(project_findings) == expected
    assert expected
    assert {finding[1] for finding in expected} == {rule_id}


def test_java_ssrf_does_not_treat_unrelated_execute_as_http_request() -> None:
    source = """
class RepositoryController {
    void run(HttpServletRequest request) {
        String url = request.getParameter("url");
        repository.execute(url);
    }
}
"""

    assert not any(finding.get("type") == "SSRF" for finding in analyze_java(source, "RepositoryController.java"))


def test_default_rule_registry_has_ssrf_for_every_primary_language() -> None:
    expected = {
        "python": PythonSSRFAstRule,
        "javascript": JavaScriptSSRFAstRule,
        "php": PhpSSRFAstRule,
        "java": JavaSSRFAstRule,
        "go": GoSSRFAstRule,
    }
    for language, rule_type in expected.items():
        rules = get_default_rules_for_language(language, include_dsl=False)
        assert sum(isinstance(rule, rule_type) for rule in rules) == 1
