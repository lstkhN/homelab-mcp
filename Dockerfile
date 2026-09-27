FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . \
    && addgroup --system --gid 10001 homelab \
    && adduser --system --uid 10001 --ingroup homelab --home /nonexistent homelab

USER homelab
ENTRYPOINT ["homelab-mcp"]
