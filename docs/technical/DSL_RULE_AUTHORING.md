# Authoring Aegis YAML DSL rules

Aegis YAML rules are intended for small, reviewable, line-oriented security
patterns. They complement the AST and taint analyzers; they are not a substitute
for multi-line control-flow or source-to-sink analysis.

## Quick start

From `aegis-ai-core`, install the development package and create a rule:

```console
pip install -e ".[dev]"
aegis rules init --language python --type sqli
aegis rules test .aegis/rules
aegis . --rules-dir .aegis/rules --format json
```

The module form is equivalent when the console entry point is unavailable:

```console
python -m src.scanner.cli rules init --language python --type sqli
python -m src.scanner.cli rules test .aegis/rules
```

Project-local `.aegis/rules` directories are loaded automatically. An explicit
`--rules-dir` must resolve inside the scanned project root; Aegis ignores rule
directories outside that boundary.

## Generated skeletons

`aegis rules init` accepts `py`, `js`, and `ts` aliases and writes normalized
language names. Built-in specialized skeletons are deliberately limited to
combinations with language-correct examples:

| Template type | Supported generated skeletons |
|---|---|
| `custom` | Python, JavaScript, TypeScript, PHP, Java, Go |
| `sqli` | Python, JavaScript, TypeScript, Go |
| `xss` | Python, JavaScript, TypeScript |
| `rce` | Python, JavaScript, TypeScript |
| `path-traversal` | Python, JavaScript, TypeScript |
| `hardcoded-credentials` | Python, JavaScript, TypeScript, Go |

For other language/category combinations, start with `--type custom` and write
language-specific patterns. The CLI rejects unsupported specialized combinations
instead of generating a misleading skeleton. Existing files are never
overwritten unless `--force` is supplied.

## Rule schema

```yaml
id: community.python.insecure-yaml-load
language: python
severity: HIGH
message: "Untrusted request data is passed to yaml.load."
vuln_type: DESERIALIZATION
patterns:
  - pattern: yaml.load($PAYLOAD)
    metavariables:
      PAYLOAD:
        regex: '(?i)\brequest\.(?:data|json|form)\b'
    where:
      file_not_regex: '(?i)(?:^|[/\\])tests?(?:[/\\]|$)'
tests:
  - name: detects request payload
    code: |
      yaml.load(request.data)
    file_path: app/imports.py
    expect_findings: 1
  - name: skips safe loader
    code: |
      yaml.safe_load(request.data)
    file_path: app/imports.py
    expect_findings: 0
```

| Field | Requirement |
|---|---|
| `id` | Stable, unique identifier. Community rules should use `community.<language>.<name>`. |
| `language` | `python`, `javascript`, `typescript`, `php`, `java`, or `go`. |
| `severity` | `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. |
| `message` | Actionable diagnostic text that explains the risk. |
| `vuln_type` | Existing finding category when possible, such as `SQL_INJECTION` or `XSS_RISK`. |
| `patterns` | One or more line-oriented patterns; any matching pattern can emit a finding. |
| `tests` | Embedded positive and negative examples executed by `aegis rules test`. |

## Pattern behavior

- `$NAME` declares a metavariable. Outside quotes it captures a non-whitespace
  expression; inside matching quotes it captures the quoted content.
- `metavariables.<NAME>.regex` requires the captured text to match a regular
  expression. `not_regex` rejects matching text.
- `where.file_regex` and `where.file_not_regex` filter by file path.
- Matching is line-oriented. A pattern cannot express a multi-line data-flow
  path, sanitizer dominance, or interprocedural behavior; use an AST/taint rule
  for those cases.
- A DSL finding with the same `(line, vuln_type)` as an existing maintained rule
  is deduplicated rather than reported twice.

Avoid broad patterns such as a bare function name without a source constraint.
Do not suppress entire test/vendor paths merely to improve a benchmark; provide
negative cases that demonstrate why the rule is precise.

## Embedded tests

Every contributed rule must include at least:

1. A true-positive example that represents untrusted or dangerous behavior.
2. A true-negative example using the safe API, sanitizer, constant, or unrelated
   data that should not match.

`expect_findings` accepts an exact integer or a boolean. Exact counts are
preferred because they also catch duplicate findings. `file_path` should be set
when a rule uses a `where` clause.

Run one file or a directory recursively:

```console
aegis rules test path/to/rule.yaml
aegis rules test .aegis/rules --quiet
```

Exit code `0` means all embedded cases passed; `1` means a schema/test failure;
`2` is used for invalid authoring arguments or a refused overwrite.

## Community contribution workflow

1. Copy `aegis-ai-core/templates/rules/community-rule.yaml` or run
   `aegis rules init`.
2. Use a namespaced ID and language-specific examples.
3. Run embedded tests and scan a small representative project.
4. Add focused fixtures under `aegis-ai-core/tests/rules/<category>/` when the
   rule is proposed for built-in distribution.
5. Run the checks listed in `CONTRIBUTING.md` and include TP/FP reasoning in the
   pull request.

Rules that need multi-line context, real type information, or source-to-sink
propagation should be proposed as maintained Python AST/taint rules instead.
