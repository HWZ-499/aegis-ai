# OWASP Top 10 Security Risks

Tags: owasp, top10, secure-coding

OWASP Top 10 groups common web application risks that repeatedly appear in
code review and SAST findings. Aegis Agent uses this document as broad context
when a finding maps to injection, broken access control, insecure design,
security misconfiguration, vulnerable components, authentication failures, or
unsafe data handling.

## Agent guidance

- Prefer fixes that remove the unsafe data flow rather than hiding the warning.
- Mention whether the finding maps to an OWASP class such as Injection, SSRF,
  Cryptographic Failures, or Software and Data Integrity Failures.
- Keep recommendations framework-aware and reviewable; do not suggest automatic
  code edits without user approval.
