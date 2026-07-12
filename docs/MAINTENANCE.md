# Maintenance and release policy

This policy applies from Aegis Core 1.5.0 onward. Core and the VS Code
extension are versioned and released independently.

## Versioning

- Aegis Core follows [Semantic Versioning](https://semver.org/). Public CLI,
  configuration, report schema, and documented Python API compatibility are
  preserved within a major version.
- The VS Code extension has its own Semantic Versioning line because editor UI
  changes and bundled-backend updates do not map one-to-one to Core releases.
- Detection improvements may change individual findings in a minor or patch
  release. Such changes must pass the frozen real-project quality budgets and
  be described in the relevant changelog.
- Experimental behavior is explicitly labeled and may evolve before promotion
  to a supported interface.

## Supported versions and runtimes

- The latest stable Core minor receives bug and security fixes.
- The immediately previous Core minor receives critical and security fixes for
  90 days after a successor minor is published. Older minors are end-of-life.
- A supported VS Code extension release is the latest Marketplace version. A
  previous extension version may receive a critical packaging fix when users
  cannot upgrade immediately, but normal fixes ship in the latest version.
- Core 1.5 supports Python 3.10–3.12. The extension build is checked on Node
  20, 22, and 24; the packaged extension remains governed by its declared VS
  Code engine range.
- Runtime support is never inferred from an upstream release. Adding or
  removing a runtime requires metadata, documentation, bootstrap checks, CI,
  and isolated install verification to change together.

## Compatibility and deprecation

- New public interfaces require documentation and focused compatibility tests.
- A public interface may be deprecated in a minor release, but removal after
  1.5 requires the next major release unless security or correctness makes the
  old behavior unsafe.
- Deprecations must identify a replacement and appear in the changelog and a
  migration guide. Silent fallback to a retired analysis engine is prohibited.
- Finding schema removals, CLI option removals, and baseline format changes are
  breaking changes. Additive fields remain permitted within a major version.

## Release gates

Core releases require:

1. Python 3.10, 3.11, and 3.12 test matrices.
2. Ruff and mypy passing on maintained sources.
3. Release consistency, wheel/sdist content, and isolated installation checks.
4. Frozen real-project provenance, accuracy, duration, and peak-RSS budgets.
5. A changelog entry and migration notes for behavior or API changes.

Extension releases require Node 20/22/24 type checks, extension-host tests,
bundled-backend preparation, and successful VSIX packaging.

## Release tags

Component-scoped tags prevent one product from publishing the other:

- Core: `core-vX.Y.Z`, exactly matching `aegis-ai-core/pyproject.toml`.
- VS Code: `vscode-vX.Y.Z`, exactly matching `aegis-vscode/package.json`.

Pre-release package metadata cannot pass the stable tag gate. The PyPI and VS
Code workflows validate the exact tag before building any publishable artifact.
Publication itself remains an O9 distribution action and is not implied by
preparing stable metadata in the repository.

## Operating cadence

- Security and data-loss defects take priority over the normal release cadence.
- Otherwise, fixes are accumulated into reviewed patch releases; detection or
  feature work ships in minor releases after benchmark gates are refreshed.
- Threshold changes require an auditable reason and fresh clean-provenance runs;
  budgets must not be relaxed merely to make a regression pass.
- Each release records supported runtimes, known limitations, and upgrade steps.
