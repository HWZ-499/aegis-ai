# Aegis Core changelog

All notable Core changes are recorded here. Releases follow the
[maintenance policy](../docs/MAINTENANCE.md).

## 1.5.0 — prepared for release

### Added

- A canonical `analyze_source()` dispatch path shared by CLI, LSP, project
  scanning, benchmarks, and compatibility adapters.
- Clean-provenance real-project reports and machine-enforced accuracy, duration,
  and peak-memory thresholds.
- Python 3.10–3.12 compatibility gates and wheel/sdist retired-file checks.

### Changed

- Multi-language compatibility calls now delegate to the maintained rule engine;
  unsupported languages return no generic regex findings.
- Core packaging uses stable version 1.5.0 and component tag `core-v1.5.0`.

### Removed

- Deprecated `ast_analyzer`, `security_rules`, `rule_based_audit`, old PHP
  `Php*Rule` exports, and the disconnected regex `RuleConfig` utility.

See the [Aegis 1.5 migration guide](../docs/technical/V1_5_MIGRATION.md) for
replacements. PyPI publication is an O9 distribution step; this entry records
the stable source checkpoint.
