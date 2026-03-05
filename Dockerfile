FROM python:3.11-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY aegis-ai-core/requirements.txt aegis-ai-core/pyproject.toml ./aegis-ai-core/

RUN pip install --no-cache-dir -r aegis-ai-core/requirements.txt \
    && pip install --no-cache-dir httpx pydantic-settings

COPY aegis-ai-core/ ./aegis-ai-core/

WORKDIR /app/aegis-ai-core

# ── FastAPI HTTP Server ───────────────────────────────────────
FROM base AS server

EXPOSE 8000

CMD ["uvicorn", "src.server.aegis_server:app", "--host", "0.0.0.0", "--port", "8000"]

# ── LSP Server (stdio, for IDE integration) ───────────────────
FROM base AS lsp

CMD ["python", "-m", "src.lsp"]

# ── CLI Scanner ───────────────────────────────────────────────
FROM base AS cli

ENTRYPOINT ["python", "-m", "src.scanner.cli"]
CMD ["--help"]
