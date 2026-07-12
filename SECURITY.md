# Security policy

## Supported versions

| Component | Supported line |
|---|---|
| Aegis Core | 1.5.x |
| VS Code extension | 0.6.x |

After a new Core minor is published, the immediately previous minor receives
critical and security fixes for 90 days, as defined in
`docs/MAINTENANCE.md`. Development branches and older releases are not supported
security channels.

## Reporting a vulnerability

Do not include vulnerability details, proof-of-concept payloads, credentials, or
affected user data in a public issue.

1. Prefer the repository Security tab and its **Report a vulnerability** action
   when private vulnerability reporting is available.
2. Include the affected component/version, impact, reproduction steps, and a
   minimal proof of concept. State whether the issue is already public or being
   actively exploited.
3. If private reporting is unavailable, open a minimal public issue requesting
   private maintainer coordination. Do not include technical details until a
   private channel is established.

The project aims to acknowledge a report within three business days and provide
an initial triage decision within seven business days. Complex fixes may require
more time; maintainers will coordinate disclosure timing and credit with the
reporter.

## In scope

- Aegis scanner, CLI, LSP, worker process, report generation, and rule loading.
- The published VS Code extension and bundled backend bootstrap/update path.
- Leakage of scanned source through behavior that occurs without an explicit AI
  remediation action.
- Rule or archive loading that permits code execution or workspace escape.

False positives, false negatives without an exploitable product vulnerability,
and normal feature requests should use the public issue tracker. Reports about
third-party vulnerable sample projects belong to those upstream projects unless
Aegis packaging introduced the issue.
