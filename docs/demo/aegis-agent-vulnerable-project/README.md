# Aegis Agent Vulnerable Demo Project

This intentionally vulnerable mini project is used only for Aegis Agent demos.

It contains examples for:

- SQL injection through dynamic query construction.
- Reflected XSS through `res.send(...)`.
- SSRF through outbound `fetch(...)`.

Run:

```powershell
cd aegis-ai-core
python -m src.agent.cli diagnose ..\docs\demo\aegis-agent-vulnerable-project --format html --output ..\docs\assets\aegis-agent-report.html --no-ai
```

Do not treat this directory as a benchmark target or production sample.
