# Aegis AI Core

Local-first static application security testing for Python, JavaScript,
TypeScript, PHP, Java, Go, and basic C/C++ scanning. Aegis combines language
parsers, security rules, taint tracking, suppression workflows, and CI-ready
reports behind one production analysis path.

## Requirements

- Python 3.10, 3.11, or 3.12
- Python 3.13 is not supported by the pinned Tree-sitter dependency stack

## Install

```console
pip install aegis-ai-core
```

For repository development:

```console
pip install -e ".[dev]"
```

## Scan a project

```console
aegis /path/to/project --format json
aegis /path/to/project --format html --output aegis-report.html
aegis /path/to/project --format sarif --output aegis-results.sarif
```

The equivalent module command is:

```console
python -m src.scanner.cli /path/to/project --format json
```

Supported report formats are JSON, HTML, Markdown, and SARIF. Project scans can
also use baselines, incremental mode, custom YAML rules, and optional AI-assisted
remediation.

## Language support

| Level | Languages | Analysis path |
|---|---|---|
| Full | Python, JavaScript/TypeScript, PHP, Java, Go | Language parser plus maintained AST/taint/DSL rules |
| Basic | C/C++ | Lightweight contextual rules for memory, string, pointer, and concurrency risks |

Unsupported languages return no findings rather than falling back to a generic
cross-language regex scanner.

## Custom YAML rules

```console
aegis rules init --language python --type sqli
aegis rules test .aegis/rules
aegis /path/to/project --rules-dir /path/to/project/.aegis/rules
```

See the [rule authoring guide](https://github.com/HWZ-499/aegis-ai/blob/main/docs/technical/DSL_RULE_AUTHORING.md)
for schema, embedded TP/TN tests, loading boundaries, and contribution rules.

## Optional AI providers

The scanner works without an AI provider. Install the optional OpenAI-compatible
client only when generated remediation is needed:

```console
pip install "aegis-ai-core[ai]"
```

Supported provider modes include DeepSeek, OpenAI, Ollama, and custom
OpenAI-compatible endpoints. Source code is sent to a remote provider only after
an explicit AI remediation action; local scans do not require a provider.

## Reproducible quality signals

The 2026-07-12 clean-worktree baselines report:

| Target | Recall | Precision | F1 |
|---|---:|---:|---:|
| DVWA | 100.0% | 44.2% | 0.61 |
| NodeGoat | 100.0% | 85.7% | 0.92 |

Reports record scanner/target revisions, ground-truth hashes, TP/FP/FN/TN,
duration, and peak RSS. These numbers are not generalized claims for every
framework or vulnerability category. See the
[detection quality guide](https://github.com/HWZ-499/aegis-ai/blob/main/docs/technical/DETECTION_QUALITY.md)
and versioned reports in `scripts/reports/` for the exact scope.

## Compatibility and security

- [Aegis 1.5 migration guide](https://github.com/HWZ-499/aegis-ai/blob/main/docs/technical/V1_5_MIGRATION.md)
- [Maintenance policy](https://github.com/HWZ-499/aegis-ai/blob/main/docs/MAINTENANCE.md)
- [Security policy](https://github.com/HWZ-499/aegis-ai/blob/main/SECURITY.md)
- [Changelog](https://github.com/HWZ-499/aegis-ai/blob/main/aegis-ai-core/CHANGELOG.md)

## License

MIT
