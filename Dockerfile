FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.11.27 /uv /usr/local/bin/uv
# git is used for optional digest archive sync. kubectl is NOT installed by default:
# if enabling one-click actions, add kubectl to a custom image with least-privilege RBAC.
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 incidentlens \
    && useradd --system --uid 10001 --gid incidentlens --home-dir /app --shell /usr/sbin/nologin incidentlens
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PATH="/app/.venv/bin:$PATH"
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv sync --locked --no-dev --extra postgres --no-editable
COPY config ./config
RUN mkdir -p /app/digests && chown -R incidentlens:incidentlens /app
USER incidentlens
EXPOSE 8000
# Run a single replica: digest and escalation schedules execute in-process without distributed locks.
CMD ["uvicorn", "incidentlens.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
