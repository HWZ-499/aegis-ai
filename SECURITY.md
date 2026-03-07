# Security Policy

## Supported Versions

We release security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

- **aegis-ai-core**: Python package (LSP server, scanner, analysis engine)
- **aegis-vscode**: VS Code / Cursor extension (LSP client)

Both components are in scope for vulnerability reports.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

- **Preferred**: Use [GitHub Private Vulnerability Reporting](https://github.com/aegis-ai/aegis-ai/security/advisories/new) for this repository.
- **Alternative**: Email the maintainers with a clear description, steps to reproduce, and impact. Include "Aegis-AI Security" in the subject.

We will respond as follows:

- **48 hours**: Acknowledge receipt of your report.
- **7 days**: Provide an initial assessment (valid/duplicate/out of scope) and severity.
- **30 days**: Aim to ship a fix and release (or a mitigation plan for complex issues).

We will not take legal action against or ask for the same from researchers who report issues in good faith and follow responsible disclosure.

## Acknowledgments

We thank security researchers who report valid vulnerabilities. With your permission, we will acknowledge your contribution in release notes and in this file after the issue is fixed.

## Scope

In scope:

- aegis-ai-core (Python): static analysis engine, LSP server, CLI scanner, RAG/AI components
- aegis-vscode: VS Code extension and its interaction with the LSP server
- Build and CI configuration that could affect supply chain or artifact integrity

Out of scope:

- Third-party dependencies (report to their maintainers; we will still consider dependency upgrade PRs)
- Vulnerabilities in code that is only present in user projects being scanned (our product scans such code; we do not execute it)
