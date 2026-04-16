FROM python:3.11-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY aegis-ai-core/requirements.txt aegis-ai-core/pyproject.toml ./aegis-ai-core/

RUN pip install --no-cache-dir -r aegis-ai-core/requirements.txt \
    && pip install --no-cache-dir pydantic-settings

COPY aegis-ai-core/ ./aegis-ai-core/

WORKDIR /app/aegis-ai-core

# ── LSP Server (stdio, for IDE integration) ───────────────────
FROM base AS lsp

CMD ["python", "-m", "src.lsp"]

# ── CLI Scanner ───────────────────────────────────────────────
FROM base AS cli

ENTRYPOINT ["python", "-m", "src.scanner.cli"]
CMD ["--help"]
