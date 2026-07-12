# Contributing to Aegis AI

Contributions are welcome for detection rules, false-positive fixes, scanners,
the VS Code extension, documentation, and reproducible benchmark data.

## Before opening a change

- Search existing issues and pull requests for overlapping work.
- Keep one change focused on one behavior or rule family.
- Do not include credentials, proprietary source code, generated reports, local
  caches, virtual environments, or third-party target repositories in a commit.
- Report suspected vulnerabilities through `SECURITY.md`, not a public issue.

## Development setup

Core development supports Python 3.10–3.12:

```console
python -m venv .venv
pip install -e "./aegis-ai-core[dev]"
python -m pytest aegis-ai-core/tests
```

Extension development uses a supported Node.js LTS/current line:

```console
cd aegis-vscode
npm ci
npm run check
npm test
```

## Detection-rule changes

- Add a focused true-positive and true-negative fixture under
  `aegis-ai-core/tests/rules/<category>/`.
- Explain the source, sink, sanitizer, and expected finding type in fixture
  comments or the pull request.
- Do not hide false positives with broad directory exclusions.
- Run the controlled rule matrix and relevant language tests.
- For YAML DSL rules, follow
  `docs/technical/DSL_RULE_AUTHORING.md`, include embedded tests, and run:

```console
cd aegis-ai-core
python -m src.scanner.cli rules test path/to/rule-or-directory
python -m pytest tests/test_rules_cli.py tests/rules/test_all_rules.py
```

The community starter is
`aegis-ai-core/templates/rules/community-rule.yaml`.

## Required checks

Run checks in proportion to the change, with the full suites before requesting
merge:

```console
ruff check aegis-ai-core/src aegis-ai-core/tests
python -m mypy aegis-ai-core/src
python -m pytest aegis-ai-core/tests

cd aegis-vscode
npm run check
npm test
```

Changes to package metadata, release workflows, public capabilities, supported
runtimes, or quality numbers must also pass release consistency and update the
relevant changelog/roadmap documentation.

## Pull request checklist

- Describe the user-visible outcome and why the change is needed.
- Link an issue when one exists.
- List the exact validation commands and results.
- Call out compatibility, performance, or finding-count changes.
- Include migration notes for public API, CLI, configuration, or report-schema
  changes.
- Confirm no unrelated generated or vendored files are included.

Maintainers may ask for a smaller patch, more negative cases, real-project
evidence, or a different implementation when a rule is too broad for the DSL.
