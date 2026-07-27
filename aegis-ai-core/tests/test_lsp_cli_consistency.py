from pathlib import Path

from src.analysis.incremental_analyzer import IncrementalAnalyzer
from src.analysis.rule_engine import analyze_php
from src.lsp.server import scan_document
from src.scanner.project_scanner import ProjectScanner


def _finding_identity(findings: list[dict]) -> list[tuple[object, ...]]:
    return sorted(
        (
            finding.get("type"),
            finding.get("rule_id"),
            finding.get("line"),
            finding.get("severity"),
        )
        for finding in findings
    )


def test_lsp_incremental_scan_matches_full_lsp_and_cli_scan(tmp_path: Path) -> None:
    source_file = tmp_path / "app.py"
    initial = """import os

def stable():
    password = "supersecretvalue123"
    return password

def changed(cmd):
    return cmd
"""
    updated = """import os

def stable():
    password = "supersecretvalue123"
    return password

def changed(cmd):
    os.system(cmd)
"""
    source_file.write_text(initial, encoding="utf-8")

    incremental = IncrementalAnalyzer()
    initial_findings = scan_document(initial, str(source_file))
    incremental.update_cache(
        str(source_file),
        initial,
        "python",
        initial_findings,
    )

    changed_functions, full_rescan = incremental.get_changed_functions(
        str(source_file),
        updated,
        "python",
    )
    assert changed_functions == ["changed"]
    assert full_rescan is False

    partial_source = incremental.build_partial_source(
        str(source_file),
        updated,
        "python",
        changed_functions,
    )
    assert partial_source is not None
    partial_findings = scan_document(partial_source, str(source_file))
    partial_findings = incremental.filter_findings_for_functions(
        str(source_file),
        updated,
        "python",
        changed_functions,
        partial_findings,
    )
    incremental_findings = incremental.merge_partial_findings(
        str(source_file),
        changed_functions,
        partial_findings,
        code=updated,
        language="python",
    )

    full_lsp_findings = scan_document(updated, str(source_file))
    source_file.write_text(updated, encoding="utf-8")
    cli_findings = ProjectScanner(
        str(tmp_path),
        use_cache=False,
        use_parallel=False,
    ).scan_file(source_file)

    expected = _finding_identity(full_lsp_findings)
    assert _finding_identity(incremental_findings) == expected
    assert _finding_identity(cli_findings) == expected


def test_php_lsp_public_api_and_project_scan_are_consistent(tmp_path: Path) -> None:
    source_file = tmp_path / "index.php"
    source = """<?php
$command = $_GET['command'];
call_user_func('system', $command);
print $_POST['message'];
"""
    source_file.write_text(source, encoding="utf-8")

    lsp_findings = scan_document(source, str(source_file))
    public_findings = analyze_php(source, str(source_file), include_dsl=False)
    project_findings = ProjectScanner(
        str(tmp_path),
        use_cache=False,
        use_parallel=False,
    ).scan_file(source_file)

    expected = _finding_identity(public_findings)
    assert _finding_identity(lsp_findings) == expected
    assert _finding_identity(project_findings) == expected
    assert {finding.get("rule_id") for finding in public_findings} == {
        "RCE_PHP_AST",
        "XSS_PHP_AST",
    }
