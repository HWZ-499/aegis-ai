# Aegis Agent

Aegis Agent is the CLI-first AI Agent workflow layer for Aegis code security diagnosis.

It turns existing Aegis security capabilities into OpenAI-style tools and runs them through a controlled LangGraph workflow:

```text
scan -> analyze -> retrieve -> fix -> review -> summarize
```

## What It Shows

- Tool Calling: scanner, finding detail, knowledge retrieval, fix suggestion, project memory, report summary, patch preview, guarded apply.
- Workflow: LangGraph `StateGraph` node order with structured tool trace.
- Automated diagnosis: vulnerability list, severity, CWE, cause, knowledge snippets, fix advice, optional code replacement.
- RAG: package-local Markdown vulnerability knowledge base.
- Memory: baseline and source suppression state as project memory.
- Reports: JSON, Markdown, and escaped self-contained HTML.
- Guarded fixing: `apply-fix` is dry-run by default; `--yes --rescan` writes only after exact preview validation and then verifies with a no-cache scan.

## Install

From `aegis-ai-core`:

```bash
pip install -e .[agent]
```

The `agent` extra installs LangGraph. The offline diagnosis path does not call an AI provider unless `--ai` is explicitly passed.

## CLI

```bash
aegis-agent tools --format json --output aegis-agent-tools.json
aegis-agent workflow --format mermaid --output aegis-agent-workflow.mmd
aegis-agent diagnose <project_path> --format json --output aegis-agent-report.json --no-ai
aegis-agent diagnose <project_path> --format markdown --output aegis-agent-report.md --no-ai
aegis-agent diagnose <project_path> --format html --output aegis-agent-report.html --no-ai
```

Patch preview application is explicit:

```bash
aegis-agent apply-fix aegis-agent-report.json --finding-id <finding_id>
aegis-agent apply-fix aegis-agent-report.json --finding-id <finding_id> --yes --rescan
```

The first command is a dry-run. The second validates the patch preview, writes the replacement, and runs a no-cache verification scan.

## Included Files

- `cli.py`: command-line entrypoint.
- `tools.py`: tool registry, report renderers, patch preview/apply logic.
- `workflow.py`: LangGraph workflow.
- `knowledge_base/`: bundled CWE/OWASP/fix-template Markdown knowledge.
- `tests/test_agent_*.py`: focused Agent tests.
