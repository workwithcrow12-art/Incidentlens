# IncidentLens

IncidentLens receives infrastructure alerts, pages on-call through deterministic YAML routing rules, and investigates in the background. It correlates Prometheus metrics, Loki logs, GitHub deployments, dependency alerts, and past incidents into evidence-linked hypotheses, while batching lower-priority alerts into scheduled Markdown digests.

**Status: prototype verified locally (179 tests, 98% coverage, strict `mypy`); staging validation is required before enabling live actions or production log ingestion.** See [docs/verification-and-repairs.md](docs/verification-and-repairs.md) for the full repair history and verification matrix.

## How it works

```mermaid
flowchart TD
    AM["Alertmanager"] --> API["FastAPI webhook"]
    API --> ROUTE{"YAML routing rules"}
    ROUTE -->|critical| OPEN["Persist incident and configured deliveries"]
    ROUTE -->|action or info| DB[("SQLite or PostgreSQL")]
    OPEN --> PAGE["PagerDuty trigger and Slack alert"]
    PAGE --> INV["Background investigation"]
    OPEN --> DB

    subgraph Evidence["Evidence collection"]
        PROM["Prometheus metrics"]
        LOKI["Loki logs"]
        GH["GitHub deployments"]
        DEP["Dependency alerts"]
        MEM["Similar closed incidents"]
    end
    INV --> Evidence
    DB -.-> DEP
    DB -.-> MEM
    Evidence --> RULES["Rule-based hypotheses"]
    RULES --> REFINE{"LLM enabled?"}
    REFINE -->|yes| LLM["Optional LLM refinement"]
    REFINE -->|no| RESULT["Investigation result"]
    LLM --> RESULT
    RESULT --> DB
    RESULT --> SLACK["Slack investigation card"]

    TIMER["In-process schedules"] --> ESC["Escalation & delivery retries"]
    DB -.-> ESC
    ESC -->|eligible action alert| PAGE
    TIMER --> DIGEST["Digest builder"]
    DB -.-> DIGEST
    DIGEST -->|ongoing action alerts| INV
    DIGEST --> FILES["Markdown archives"]
    DIGEST --> NOTICE["Slack digest notice"]
    TIMER --> MAINT["Retention and monthly ROI"]
    DB -.-> MAINT
    MAINT --> FILES

    API -->|resolved alert| CLOSE["Close incident and resolve PagerDuty"]
    CLOSE --> DB
    CLOSE --> POST["Postmortem draft"]
    POST --> FILES
    FILES -->|optional commit and push| GIT["Git remote"]

    SLACK --> HUMAN["Engineer reviews or approves"]
    HUMAN --> SIGNED["Signed Slack interaction"]
    SIGNED --> FEEDBACK["Hypothesis feedback"]
    FEEDBACK --> DB
    SIGNED --> ACTION["Approver, resolved, lock, and cooldown checks"]
    ACTION -->|enabled and authorized| CMD["Execute allowlisted command"]
    ACTION -->|disabled| DRY["Dry-run preview"]
    CMD --> AUDIT["Action audit record"]
    DRY --> AUDIT
    AUDIT --> DB
```

Routing never depends on the LLM, and the LLM has no path to command execution. Alerts with the same fingerprint are serialized; failed deliveries on configured channels are persisted and retried every `IL_ESCALATION_CHECK_SECONDS` (unconfigured channels log locally without queuing retries).

| Capability | Implementation | Key boundaries |
| --- | --- | --- |
| Alert routing | Three severities (`critical`, `action`, `info`) from YAML; age/repeat escalation | Related warnings do not jointly escalate; single-replica in-process scheduler. |
| Investigation | Pre/during metric & log comparisons, deploy correlation, dependency & memory lookup | Zero hypotheses when evidence is absent; LLM output is validated and confidence is computed in code. |
| Redaction | Emails, phones, Luhn cards, JWTs, Bearer/Basic auth, URL credentials, AWS/GitHub/Slack tokens, key-value secrets | Validate against organization-specific log formats before enabling external LLMs. |
| Human actions | Signed Slack interactions, approver IDs, argument-list execution, per-service lock & cooldown | Disabled by default (`IL_ACTIONS_ENABLED=false`); refused on resolved incidents. |
| Postmortems & ROI | Auto-drafted postmortems, read-only `GET` preview, monthly ROI & MTTR reports | Manual root causes and postmortem file edits are preserved across feedback and `GET` reads. |

## Quickstart

Run commands from the repository root so `config/` and `.env` resolve properly. Requires Python 3.11+ (3.12 in Docker) and Git.

### Install with `uv` (recommended)

```bash
uv sync --locked --extra dev
cp .env.example .env   # PowerShell: Copy-Item .env.example .env
```

### Install with `venv` + `pip`

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
Copy-Item .env.example .env
```

### Run the offline demo and checks

```bash
python -X utf8 scripts/demo.py
python -m pytest --cov=incidentlens --cov-report=term-missing
python -m mypy src scripts
```

`scripts/demo.py` mocks Prometheus, Loki, GitHub, Slack, and PagerDuty at the HTTP transport layer and writes sample digests, postmortems, and ROI reports into `demo-output/`.

### Start the API server

Edit `.env` first: keep `IL_LLM_PROVIDER=none` and `IL_ACTIONS_ENABLED=false` initially, and set `IL_WEBHOOK_TOKEN` to a strong bearer token.

```bash
python -m uvicorn incidentlens.app:create_app --factory --host 127.0.0.1 --port 8000
```

Send the sample payload (`examples/alertmanager_payload.json`) using `bash scripts/send_sample.sh` (with `IL_WEBHOOK_TOKEN` exported) or PowerShell:

```powershell
$headers = @{ Authorization = 'Bearer YOUR_LOCAL_TEST_TOKEN' }
$payload = Get-Content examples/alertmanager_payload.json -Raw -Encoding utf8
Invoke-RestMethod http://localhost:8000/webhooks/alertmanager -Method Post -Headers $headers -ContentType 'application/json' -Body $payload
Invoke-RestMethod http://localhost:8000/incidents -Headers $headers
```

### PostgreSQL and Docker Compose

```bash
docker compose up -d db
docker compose up --build incidentlens
```

For a standalone PostgreSQL instance, install `.[postgres]` and set `IL_DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST:5432/incidentlens`. Tables are created at startup; schema migrations are not yet implemented.

## Staging configuration

| Configuration | Purpose |
| --- | --- |
| `config/routing_rules.yaml` | Alert classification and escalation thresholds. Keep an independent critical route from Alertmanager to PagerDuty during pilot validation. |
| `config/services.yaml` | Service owners, GitHub repositories, dependencies, and runbook URLs. |
| `config/signals.yaml` | PromQL and LogQL templates (`{service}` placeholder) tuned to your metric and label names. |
| `config/actions.yaml`, `IL_ACTIONS_ENABLED` | Allowlisted commands, Slack approver IDs, timeouts, and per-service `cooldown_seconds`. Note: the base Docker image omits `kubectl`. |
| `config/baseline.yaml` | Pre-adoption headcount, interruption rate, and MTTR for ROI comparisons. |
| `IL_WEBHOOK_TOKEN`, `IL_PUBLIC_URL` | Bearer authentication for API/webhook routes and public base URL for evidence links. |
| `IL_PAGERDUTY_ROUTING_KEY` | PagerDuty Events API v2 routing key (unconfigured = local dry-run, not queued). |
| `IL_SLACK_BOT_TOKEN`, `IL_SLACK_CHANNEL`, `IL_SLACK_SIGNING_SECRET` | Slack bot delivery and signed interactivity (`POST /slack/interactions`), or `IL_SLACK_WEBHOOK_URL` for message-only delivery. |
| `IL_PROMETHEUS_URL`, `IL_LOKI_URL`, `IL_GITHUB_TOKEN`, `IL_GRAFANA_URL` | Read-only evidence collectors and Grafana Explore deep links. |
| `IL_LLM_PROVIDER`, `IL_LLM_MODEL`, `IL_LLM_API_KEY`, `IL_LLM_BASE_URL` | Optional hypothesis refinement (`none`, `anthropic`, or `openai-compatible`). |

Run a **single replica**: schedules, alert locks, and service action locks are process-local.

## API reference

All endpoints except `/healthz` and `/slack/interactions` require `Authorization: Bearer <IL_WEBHOOK_TOKEN>` when `IL_WEBHOOK_TOKEN` is set. `/slack/interactions` verifies Slack HMAC signatures.

| Method and path | Purpose |
| --- | --- |
| `GET /healthz` | Basic liveness check |
| `POST /webhooks/alertmanager` | Ingest Alertmanager webhook batch |
| `GET /alerts/{fingerprint}` | Inspect stored alert state |
| `GET /incidents`, `GET /incidents/{id}` | List incidents or inspect an incident with investigations and action audit log |
| `GET /incidents/{id}/postmortem` | Read saved postmortem or render an in-memory draft (read-only) |
| `POST /incidents/{id}/resolution` | Record human-authored root cause and fix |
| `POST /investigations/{id}/feedback` | Confirm a hypothesis (`1..N`) or mark none correct (`0`) |
| `POST /reports/roi?month=YYYY-MM` | Generate a monthly ROI report |
| `POST /digest/run` | Trigger a digest run manually |
| `POST /escalations/check` | Retry failed notifications and check pending escalations |
| `POST /maintenance/run` | Run retention cleanup and previous-month ROI reporting |
| `POST /slack/interactions` | Handle signed Slack button clicks |

## Source map & documentation

- `src/incidentlens/app.py`, `service.py`, `store.py`, `models.py`, `redact.py` — FastAPI routes, orchestration, SQLAlchemy persistence, domain models, and secret redaction
- `src/incidentlens/ingest/`, `routing/` — Alertmanager normalization and YAML rule evaluation
- `src/incidentlens/investigation/`, `changes/`, `memory/` — Prometheus/Loki/GitHub collectors, anomaly detection, incident similarity, and optional LLM synthesis
- `src/incidentlens/actions/`, `digest/`, `reports/`, `outputs/` — Guarded command runner, Markdown digests/postmortems/ROI, Slack cards, PagerDuty, and Git archive sync
- [docs/verification-and-repairs.md](docs/verification-and-repairs.md) — Repair log (R1–R16), verification commands, and staging checklist
- [docs/doi-chieu-yeu-cau.md](docs/doi-chieu-yeu-cau.md) — Requirements traceability matrix
- [LICENSE](LICENSE) — MIT License
