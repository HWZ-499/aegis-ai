# Aegis release checklist

Core and the VS Code extension release independently. Preparing artifacts does
not authorize publishing them; a maintainer must intentionally push the exact
component tag after all external credentials are configured.

## One-time external configuration

### PyPI

For the first `aegis-ai-core` release, configure a PyPI pending trusted
publisher with these exact values:

| Field | Value |
|---|---|
| PyPI project | `aegis-ai-core` |
| GitHub owner | `HWZ-499` |
| Repository | `aegis-ai` |
| Workflow | `publish-pypi.yml` |
| Environment | blank unless the workflow is updated to use one |

The workflow uses GitHub OIDC and must not store a long-lived PyPI API token.

### VS Code Marketplace

1. Confirm the releasing account can publish under `wen-zai`.
2. Store a Marketplace token in the repository secret `VSCE_PAT`.
3. Keep the token scoped to Marketplace publishing and rotate it according to
   the publisher account policy.

Never write either credential to a tracked file, workflow argument, test log,
or issue.

## Core preflight

From the repository root:

```console
python aegis-ai-core/scripts/check_release_consistency.py
python aegis-ai-core/scripts/check_release_tag.py core core-v1.5.0
ruff check aegis-ai-core/src aegis-ai-core/tests
python -m mypy aegis-ai-core/src
python -m pytest aegis-ai-core/tests
```

Build in a clean directory and validate both distributions:

```console
cd aegis-ai-core
python -m build
python scripts/check_distribution.py dist/*
python -m twine check dist/*
```

Confirm wheel metadata has version 1.5.0, Python `>=3.10,<3.13`, and the stable
classifier. Install the wheel in a fresh supported Python environment and run
`aegis --help` before tagging. The tag workflow repeats this against the final
wheel in an isolated virtual environment, verifies all three console entry
points, imports the scanner and LSP modules, and only then enters the Trusted
Publisher step.

## Extension preflight

```console
cd aegis-vscode
npm ci
npm audit --audit-level=low
npm run check
npm test
npx vsce package --no-dependencies
cd ..
python aegis-ai-core/scripts/check_distribution.py aegis-vscode/aegis-ai-security-0.6.7.vsix
python aegis-ai-core/scripts/check_release_tag.py vscode vscode-v0.6.7
```

Inspect the VSIX manifest and file list. It must include `CHANGELOG.md`, the
bundled Core 1.5.0 backend, and no cache, test, source-map, or retired backend
files. The distribution gate also checks that the package/file versions match
and recomputes the bundled backend file count and SHA-256 fingerprint. Checking
the exact versioned VSIX avoids mixing retained artifacts from older releases
into the local preflight. The full dependency audit must report zero
vulnerabilities, including development and packaging tools. Do not use
`npm audit fix --force` during release preparation because it may perform
breaking tool downgrades or upgrades.

## Intentional publish actions

Only after review and explicit approval:

```console
git tag core-v1.5.0
git push origin core-v1.5.0

git tag vscode-v0.6.7
git push origin vscode-v0.6.7
```

Each tag triggers only its component workflow. The workflow rechecks that the
tag exactly matches package metadata before publishing.

## Post-release verification

- PyPI: verify metadata, rendered README, files, install command, and console
  entry points on the public project page.
- Marketplace: verify 0.6.7 is no longer marked Preview, the current README and
  changelog render correctly, and a clean VS Code profile can install/activate.
- Record the published URLs and workflow runs in the roadmap/changelog.
- Do not move or reuse a published tag.

PyPI files are immutable. If a release is defective, publish a new patch version
rather than replacing artifacts. Use Marketplace unpublish only for a severe
security or data-loss incident; otherwise publish a corrected extension version.
