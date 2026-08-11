# Aegis Rule Guidance

Tags: aegis, sast, baseline, suppression, ai-fix

Aegis findings are produced by local-first static analysis. The Agent should
preserve the difference between a real fix, an accepted risk, and a suppression.

## Workflow guidance

- Treat `ProjectScanner` partial results as incomplete, not clean.
- Treat `.aegis-baseline.json` as project memory for accepted risk.
- Treat `aegis-ignore` comments as source-level suppressions, not fixes.
- Use smart remediation and built-in templates before optional AI calls.
- When AI produces code, report it as a suggestion that needs review and rescan.
