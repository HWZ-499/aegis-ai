from pathlib import Path

import pytest

from src.analysis.analyzers.php_analyzer import PhpAnalyzer
from src.analysis.rule_engine import analyze_php, get_default_rules_for_language
from src.analysis.rules.rce.php_ast_rule import PhpRCEAstRule
from src.analysis.rules.xss.php_ast_rule import PhpXSSAstRule


def _ast_only_findings(code: str) -> list[dict]:
    rules = [PhpRCEAstRule(), PhpXSSAstRule()]
    return PhpAnalyzer(rules).analyze(code, Path("sample.php"))


@pytest.mark.parametrize(
    ("code", "expected_type"),
    [
        (
            "<?php $host = $_GET['host']; $output = `ping -c 1 $host`;",
            "RCE_COMMAND_EXEC",
        ),
        (
            "<?php $command = $_POST['command']; call_user_func('system', $command);",
            "RCE_COMMAND_EXEC",
        ),
        ("<?php print $_GET['name'];", "XSS_RISK"),
        ("<?= $_GET['name'] ?>", "XSS_RISK"),
        ("<?php die($_POST['message']);", "XSS_RISK"),
    ],
)
def test_php_ast_only_detects_rce_and_xss_variants(code: str, expected_type: str) -> None:
    findings = _ast_only_findings(code)

    assert any(finding.get("type") == expected_type for finding in findings)


@pytest.mark.parametrize(
    ("code", "unexpected_type"),
    [
        ("<?php $version = `php -v`;", "RCE_COMMAND_EXEC"),
        (
            "<?php $host = $_GET['host']; system('ping -c 1 ' . escapeshellarg($host));",
            "RCE_COMMAND_EXEC",
        ),
        (
            "<?php echo '<p>' . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . '</p>';",
            "XSS_RISK",
        ),
        ("<?= htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') ?>", "XSS_RISK"),
    ],
)
def test_php_ast_only_respects_rce_and_xss_sanitizers(code: str, unexpected_type: str) -> None:
    findings = _ast_only_findings(code)

    assert not any(finding.get("type") == unexpected_type for finding in findings)


def test_php_ast_rules_run_when_taint_graph_construction_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    class FailingTaintAnalyzer:
        def __init__(self, language: str, initialize_parser: bool = True) -> None:
            pass

        def analyze_tree(self, root: object, file_path: str, code: str) -> None:
            raise RuntimeError("simulated taint failure")

    monkeypatch.setattr("src.analysis.taint.TaintAnalyzer", FailingTaintAnalyzer)
    analyzer = PhpAnalyzer([PhpRCEAstRule(), PhpXSSAstRule()])

    findings = analyzer.analyze(
        "<?php system($_GET['cmd']); echo $_GET['name'];",
        Path("direct.php"),
    )

    assert {finding.get("type") for finding in findings} == {
        "RCE_COMMAND_EXEC",
        "XSS_RISK",
    }


def test_php_public_entry_uses_ast_exclusively_for_rce_and_xss() -> None:
    findings = analyze_php(
        "<?php $cmd = $_GET['cmd']; system($cmd); echo $_GET['name'];",
        "entry.php",
        include_dsl=False,
    )
    relevant = [finding for finding in findings if finding.get("type") in {"RCE_COMMAND_EXEC", "XSS_RISK"}]

    assert {finding.get("rule_id") for finding in relevant} == {
        "RCE_PHP_AST",
        "XSS_PHP_AST",
    }
    assert all(finding.get("source") != "PHP-Regex" for finding in relevant)


def test_php_public_entry_does_not_execute_legacy_regex_supplement(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_legacy_scan(*args, **kwargs):
        raise AssertionError("PHP production entry must not call scan_code_locally")

    monkeypatch.setattr("src.analysis.security_rules.scan_code_locally", fail_legacy_scan)

    findings = analyze_php(
        """<?php
$user = $_POST['username'];
$user = mysqli_real_escape_string($conn, $user);
$pass = $_POST['password'];
$pass = mysqli_real_escape_string($conn, $pass);
$query = "SELECT * FROM users WHERE username='$user' AND password='$pass'";
mysqli_query($conn, $query);
""",
        "ast-only.php",
        include_dsl=False,
    )

    assert any(finding.get("rule_id") == "SQL_INJECTION_PHP_AST" for finding in findings)
    assert all(finding.get("source") != "PHP-Regex" for finding in findings)


def test_php_public_entry_preserves_distinct_ast_sinks_in_nearby_branches() -> None:
    findings = analyze_php(
        """<?php
$target = $_GET['target'];
if (PHP_OS_FAMILY === 'Windows') {
    shell_exec('ping ' . $target);
} else {
    shell_exec('ping -c 1 ' . $target);
}
""",
        "branches.php",
        include_dsl=False,
    )

    rce_lines = [finding.get("line") for finding in findings if finding.get("type") == "RCE_COMMAND_EXEC"]
    assert rce_lines == [4, 6]


def test_php_default_rules_register_one_rce_and_one_xss_rule() -> None:
    rules = get_default_rules_for_language("php", include_dsl=False)

    assert sum(isinstance(rule, PhpRCEAstRule) for rule in rules) == 1
    assert sum(isinstance(rule, PhpXSSAstRule) for rule in rules) == 1
