FROM python:3.12-slim
# git is used for optional digest archive sync. kubectl is NOT installed by default:
# if enabling one-click actions, add kubectl to a custom image with least-privilege RBAC.
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[postgres]"
COPY config ./config
EXPOSE 8000
# Run a single replica: digest and escalation schedules execute in-process without distributed locks.
CMD ["uvicorn", "incidentlens.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
