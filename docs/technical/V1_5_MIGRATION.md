# Aegis 1.5 analysis API migration

Aegis 1.5 removes the analysis interfaces deprecated since 1.2. The package is
marked `1.5.0.dev0` while the stable-version policy and final release checks are
being completed.

## Analysis entry points

Use the canonical dispatcher for new integrations:

```python
from src.analysis.rule_engine import analyze_source

findings = analyze_source(source_code, "app.py")
```

The following pre-1.5 APIs have been removed:

| Removed API | Replacement |
|---|---|
| `ast_analyzer.analyze_code_ast()` | `analyze_source()` or `analyze_python()` |
| `security_rules.scan_code_locally()` | `analyze_source()` |
| `rule_engine.VULN_SIGNATURES` / `VULN_SEVERITY` | Rule objects returned by `get_default_rules_for_language()` |
| `rule_based_audit` | `analyze_source()` plus `ReportGenerator` when a rendered report is needed |
| `rules.php.Php*Rule` | The maintained `Php*AstRule` classes, or preferably `analyze_source()` |

`MultiLanguageASTAnalyzer` and `analyze_code_multi_language()` remain as thin
compatibility adapters, but they no longer run independent parsers or a generic
regex fallback. Unsupported languages return no findings.

## Custom rules

The removed `scanner.rule_config.RuleConfig` edited regex signatures that were
no longer consumed by production scans. Custom rules now use the validated YAML
DSL:

```console
aegis rules init --language python --type sqli
aegis rules test .aegis/rules
aegis . --rules-dir .aegis/rules
```

Project-local `.aegis/rules` directories are loaded automatically. Rule changes
should include embedded DSL tests and focused fixtures under
`aegis-ai-core/tests/rules/`.
