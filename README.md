# IncidentLens

IncidentLens receives infrastructure alerts, pages on-call through fixed routing rules, and investigates in the background. It combines metrics, logs, deployments, dependency alerts, and past incidents into hypotheses with links to evidence. Lower-priority alerts become scheduled Markdown digests.

**Status: reviewed defects repaired and verified locally on 2026-11-16; staging validation is still required.** The core application, regression tests, offline demo, and package builds are complete for the repair scope described below. Proposed integrations and live deployment remain separate roadmap work.

## How it works

### Architecture graph

```mermaid
flowchart TD
    AM[Alertmanager] --> API[FastAPI webhook]
    API --> ROUTE{YAML routing rules}
    ROUTE -->|critical| OPEN[Persist incident and notification deliveries]
    ROUTE -->|action or info| DB[(SQLite or PostgreSQL)]
    OPEN --> PAGE[PagerDuty trigger attempt and Slack notification]
    PAGE --> INV[Background investigation]
    OPEN --> DB

    subgraph Evidence[Evidence collection]
        PROM[Prometheus metrics]
        LOKI[Loki logs]
        GH[GitHub deployments]
        DEP[Dependency alerts]
        MEM[Similar closed incidents]
    end
    INV --> Evidence
    DB -.-> DEP
    DB -.-> MEM
    Evidence --> RULES[Rule-based hypotheses]
    RULES --> REFINE{LLM enabled?}
    REFINE -->|yes| LLM[Optional LLM refinement]
    REFINE -->|no| RESULT[Investigation result]
    LLM --> RESULT
    RESULT --> DB
    RESULT --> SLACK[Slack investigation card]

    TIMER[In-process schedules] --> ESC[Escalation checks]
    DB -.-> ESC
    ESC -->|eligible action alert| PAGE
    TIMER --> DIGEST[Digest builder]
    DB -.-> DIGEST
    DIGEST -->|selected ongoing action alerts| INV
    DIGEST --> FILES[Markdown archives]
    DIGEST --> NOTICE[Slack digest notification]
    TIMER --> MAINT[Retention and monthly ROI]
    DB -.-> MAINT
    MAINT --> FILES

    API -->|resolved alert| CLOSE[Close incident and resolve PagerDuty]
    CLOSE --> DB
    CLOSE --> POST[Postmortem draft]
    POST --> FILES
    FILES -->|optional commit and push| GIT[Git remote]

    SLACK --> HUMAN[Engineer reviews or approves]
    HUMAN --> SIGNED[Signed Slack interaction]
    SIGNED --> FEEDBACK[Hypothesis feedback]
    FEEDBACK --> DB
    SIGNED --> ACTION[Approver and command allowlist checks]
    ACTION -->|enabled and authorized| CMD[Execute configured command]
    ACTION -->|disabled| DRY[Dry-run result]
    CMD --> AUDIT[Action audit record]
    DRY --> AUDIT
    AUDIT --> DB
```

Solid arrows show workflow or output; dotted arrows show stored data used by a job. The graph describes the implemented architecture. Opening and recovery notifications are persisted before delivery and retried by the escalation schedule. Schedules run inside one application process, and the LLM has no connection to command execution.

### Workflow summary

```text
Alertmanager webhook
  -> YAML routing rules
     -> critical: persist incident + deliveries -> PagerDuty attempt + Slack -> background investigation
     -> action: store -> digest; escalate if configured age/repeat limits are reached
     -> info: store -> digest

Investigation
  -> collect Prometheus + Loki + GitHub data in parallel
  -> add dependency alerts and similar closed incidents
  -> generate rule-based hypotheses
  -> optionally refine them through an LLM
  -> save results and send a Slack investigation card

Recovery -> resolve PagerDuty + close incident + draft postmortem
Feedback/actions -> record root cause, fix, and action audit trail
Daily maintenance -> retention cleanup + previous-month ROI report when applicable
```

Routing never depends on the LLM. Investigation normally follows the initial paging attempt. Requests for the same alert fingerprint are serialized; independent alerts can proceed concurrently. Failed opening and recovery notifications are retried per channel, including after restart.

| Capability | Current implementation | Limits |
| --- | --- | --- |
| Alert routing | Three levels from YAML; age/repeat escalation | Related warnings do not jointly trigger escalation. Heavier metric thresholds require separate Prometheus alert rules. |
| Investigation | Before/during comparisons; up to three hypotheses | Zero hypotheses is valid when evidence is insufficient. The default 240-second timeout can end without a saved result; it is not a delivery guarantee. |
| Change correlation | GitHub Deployments API | Config, feature flags, Terraform, GitLab, and ArgoCD are not connected. |
| Incident memory | Service/name similarity plus word overlap | No embeddings or pgvector search; scans a bounded set of recent closed incidents. |
| Human actions | Slack signature, approver list, allowlisted commands, audit records | Disabled by default; identical signed requests are claimed atomically in the database before execution. |
| Reports | Digests, postmortems, monthly ROI, feedback accuracy, MTTR | MTTA is not measured. Time saved is an estimate, not observed savings. |

## Install locally

Run all commands from the project root so the application can find `config/` and `.env`. The package declares Python 3.11 or newer; the Dockerfile uses Python 3.12. Git is needed for archive synchronization and Git-related tests.

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
Copy-Item .env.example .env
```

Using the virtual environment's executable directly avoids changing PowerShell execution policy.

### Linux or macOS

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
cp .env.example .env
```

The remaining examples use `python` after activating the environment (`.venv\Scripts\Activate.ps1` on PowerShell, or `source .venv/bin/activate` on Linux/macOS). Alternatively, keep using its executable directly.

### Offline demonstration

```bash
python -X utf8 scripts/demo.py
```

The demo uses HTTP mocks for the external services and writes digests, postmortems, and ROI examples to `demo-output/`. It recreates that directory on each run. It demonstrates application flow, not compatibility with live services or real incident accuracy.

### Start the API

Edit `.env` before starting. For an initial local run, leave integration credentials empty, keep `IL_LLM_PROVIDER=none` and `IL_ACTIONS_ENABLED=false`, and set `IL_WEBHOOK_TOKEN` to a local test token. Empty paging/notification credentials produce dry-run logs; empty evidence-source URLs skip those collectors. Leaving the webhook token empty disables bearer-token protection.

```bash
python -m uvicorn incidentlens.app:create_app --factory --host 127.0.0.1 --port 8000
```

Open `/healthz` for a basic liveness response or `/docs` for the generated API documentation. Liveness does not verify delivery to Slack/PagerDuty or evidence-source availability.

In a second PowerShell terminal, replace the token below with the value in `.env`:

```powershell
$headers = @{ Authorization = 'Bearer YOUR_LOCAL_TEST_TOKEN' }
$payload = Get-Content examples/alertmanager_payload.json -Raw -Encoding utf8
Invoke-RestMethod http://localhost:8000/webhooks/alertmanager -Method Post -Headers $headers -ContentType 'application/json' -Body $payload
Invoke-RestMethod http://localhost:8000/incidents -Headers $headers
Invoke-RestMethod http://localhost:8000/digest/run -Method Post -Headers $headers
```

On Linux/macOS, the sample script reads the token from the shell environment; it does not load `.env` itself:

```bash
export IL_WEBHOOK_TOKEN='YOUR_LOCAL_TEST_TOKEN'
bash scripts/send_sample.sh
```

SQLite creates `incidentlens.db` locally. Generated artifacts normally go into `digests/`. The default digest interval is four hours, escalation checks run every minute, and maintenance runs every 24 hours. A monthly report is generated by maintenance for the previous month when data exists; it is not guaranteed to run exactly at midnight on the first day.

### PostgreSQL and Docker

For a locally managed PostgreSQL instance, install the driver and configure a dedicated database:

```bash
python -m pip install -e '.[dev,postgres]'
```

Set `IL_DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST:5432/incidentlens` in `.env`. Tables are created at startup; schema migrations are not implemented.

The supplied Compose configuration starts the app and PostgreSQL, overrides the database URL, and persists the database and digest directory. It includes a pgvector-capable image, but the application does not currently use vector search.

```bash
docker compose up -d db
docker compose exec db pg_isready -U incidentlens -d incidentlens
# Wait until the readiness command succeeds before starting the app.
docker compose up --build incidentlens
```

Create `.env` first. The Compose file waits for a successful PostgreSQL health check before starting the application. Its published port and sample database password are development defaults. Docker build/startup was not verified during this review.

## Configure a staging installation

| Configuration | Purpose and required work |
| --- | --- |
| `config/routing_rules.yaml` | Define classification and escalation policies. Keep an independent critical-alert route from Alertmanager to PagerDuty while validating. |
| `config/services.yaml` | Set service owners, repositories, dependencies, and runbook URLs. |
| `config/signals.yaml` | Replace sample PromQL/LogQL queries with queries that match your metrics, labels, and services. Check normal and incident windows manually. |
| `IL_WEBHOOK_TOKEN`, `IL_PUBLIC_URL` | Protect API endpoints and provide a reachable base URL for evidence links. |
| `config/alertmanager.example.yml` | Point Alertmanager at `/webhooks/alertmanager`; match its bearer token to the application token. |
| `IL_PAGERDUTY_ROUTING_KEY` | Configure paging with a staging integration; verify trigger, deduplication, and recovery delivery. |
| `IL_SLACK_BOT_TOKEN`, `IL_SLACK_CHANNEL`, `IL_SLACK_SIGNING_SECRET` | Configure the bot, channel, and signed interactions. Alternatively use `IL_SLACK_WEBHOOK_URL` for notifications. |
| `IL_PROMETHEUS_URL`, `IL_PROMETHEUS_BEARER_TOKEN`, `IL_LOKI_URL`, `IL_GITHUB_TOKEN` | Enable evidence collectors. Provision credentials with read-only scopes; GET-only client code does not restrict a credential's permissions. |
| `IL_GRAFANA_URL`, `IL_GRAFANA_LOKI_DATASOURCE` | Configure log evidence links and verify them against your Grafana version. |
| `IL_LLM_PROVIDER` | Keep `none` initially. Anthropic requires a model and API key; `openai-compatible` requires a model and base URL, plus a key if its server requires one. All outgoing text fields are redacted and malformed responses fall back to rules; validate redaction patterns against your data before sending sensitive evidence. |
| `config/actions.yaml`, `IL_ACTIONS_ENABLED` | Keep actions disabled until staging validation. Configure approvers, service restrictions, installed executables, and limited command permissions. The Docker image does not include kubectl. |
| `config/baseline.yaml` | Enter measured pre-adoption interruption rates, MTTR, and incident counts. Current `before` values are null; measurement is pending. |
| `IL_DIGEST_GIT_PUSH` | Requires the digest directory to be a Git repository with a usable remote and credentials. Commit/push runs in the background; delivery still needs verification. |

For Slack buttons, configure the app's Interactivity URL as `https://YOUR_HOST/slack/interactions`. The bot uses `chat:write` and must have access to the target channel. Validate the full interaction in staging before enabling commands.

Run a single application process/replica: schedules are in-process and have no distributed coordination. Back up the database and archives before upgrades. Do not rely on IncidentLens as the sole critical paging path.

## Completed repairs

README findings R1–R7 and the five additional review defects were repaired on 2026-11-16. Regression cases were first run against the broken behavior, then rerun after the fixes.

| ID | Repaired behavior | Regression coverage |
| --- | --- | --- |
| R1 | Failed incident-opening notifications remain queued independently for PagerDuty and Slack. The escalation schedule retries them after recovery or restart without recreating the incident. | `test_failed_escalation_retries_after_restart`, `test_retries_only_failed_notification_channel` |
| R2 | LLM input redaction covers historical draft hypotheses and alert name/service/summary as well as evidence descriptions. | `test_llm_redacts_historical_root_cause_and_fix`, `test_llm_redacts_every_alert_text_field` |
| R3 | Identical valid signed Slack requests are atomically claimed in persistent storage before background execution. Concurrent retries and restarts execute the command at most once. | `tests/test_slack_replay.py` |
| R4 | Firing and recovery for the same fingerprint are ordered; recovery cannot leave an incident open behind an unfinished paging call. | `test_concurrent_resolution_leaves_closed_incident` |
| R5 | The complete LLM response schema is validated inside the fallback handler. Malformed fields retain rule hypotheses and evidence. | `test_malformed_llm_item_preserves_complete_rule_investigation`, `test_malformed_llm_envelope_falls_back_to_rules` |
| R6 | A previously digested warning becomes pending again when it resolves. Its recovery is published once, including when recovery arrives during digest collection. | `test_digested_warning_publishes_recovery_once`, `test_recovery_during_digest_remains_pending` |
| R7 | ROI path assertions use pathlib and JSON fixtures explicitly use UTF-8. | `tests/test_reports.py`, `tests/test_api.py`, `tests/test_alertmanager.py` |
| R8 | Stale recovery cannot close a newer episode; stale firing cannot reopen an already recovered episode. | `test_stale_recovery_does_not_close_new_episode`, `test_stale_firing_does_not_reopen_resolved_episode` |
| R9 | Failed recovery notifications retry independently. New incidents use distinct PagerDuty keys while older pending resolves remain deliverable. | `test_failed_escalation_resolution_retries`, `test_new_episode_preserves_pending_resolution` |
| R10 | Digest filenames are created exclusively, adding a numeric suffix on collisions. Repeated and concurrent writes preserve every report. | `tests/test_archive_regressions.py` |
| R11 | Only deployments at or before alert onset are considered causal candidates. Later mitigation deployments cannot displace earlier causes. | `test_deploy_after_incident_is_not_blamed` and deployment boundary cases in `tests/test_engine.py` |
| R12 | Git synchronization attempts to push existing local commits even with a clean index; concurrent synchronization is serialized. | `test_clean_sync_retries_failed_push_after_restart`, `test_concurrent_syncs_do_not_mix_staged_changes` |

The database creates two additive tables, `notification_deliveries` and `interaction_claims`, at startup. Existing alert and incident tables are unchanged. Existing incidents without recorded delivery keys retain the legacy PagerDuty fingerprint key; new incidents use an incident-specific key. Back up existing databases before upgrading. Historical delivery failures from versions without delivery tracking cannot be reconstructed automatically.

Notification retries run every `IL_ESCALATION_CHECK_SECONDS` (60 seconds by default), or through `POST /escalations/check` when schedules are disabled. Successful channels are not resent by the retry job. A remote service accepting a message immediately before a process crash can still cause an at-least-once retry; PagerDuty deduplicates its event key. Investigation cards, digest announcements, and report announcements are separate best-effort notifications.

Slack command execution is at most once for an identical signed request. A crash after claiming a request but before execution requires an engineer to inspect the audit trail and submit a fresh action; the system intentionally does not automatically rerun a potentially executed command. Claims and delivery records are retained with incident history. Run one application process/replica; alert ordering and scheduled-job coordination remain process-local.

## Verification and remaining limits

Fresh checks on **2026-11-16**, Windows, Python **3.14.6**, SQLite:

- **160 tests passed**, **99% statement coverage**. The suite also passes with native Windows text encoding. One upstream Starlette/httpx deprecation warning remains.
- The offline demonstration completed and generated a digest, postmortem, and ROI report.
- A real local uvicorn server passed startup, liveness, bearer authentication, webhook ingestion, incident lookup, and graceful shutdown checks with integrations disabled.
- Source and wheel packages built successfully with cached build dependencies. Distribution inputs explicitly exclude local caches, virtual environments, databases, and credentials.
- Compose now has a PostgreSQL readiness health check, and `.dockerignore` excludes local state from the build context. Docker and PostgreSQL executables were unavailable, so live Compose/PostgreSQL execution was not verified.

```bash
python -m pytest -q
python -m pytest --cov=incidentlens --cov-report=term-missing
python -X utf8 scripts/demo.py
uv build
```

For PostgreSQL tests, use a disposable database only: the test helper drops and recreates application tables when `IL_TEST_DATABASE_URL` is set.

```powershell
$env:IL_TEST_DATABASE_URL = 'postgresql+psycopg://USER:PASSWORD@localhost/incidentlens_test'
python -X utf8 -m pytest -q
Remove-Item Env:IL_TEST_DATABASE_URL
```

| Area | Established locally | Remaining validation |
| --- | --- | --- |
| Paging | Rule-based routing, persistent per-channel retries, concurrent recovery, separate episode keys | Live PagerDuty/Slack behavior, rate limits, credentials, and operational recovery |
| Hypotheses | Schema validation, evidence ID checks, deterministic confidence, rule fallback | Real incident accuracy; a valid citation alone does not establish support |
| LLM input | Pattern-based redaction across outgoing free-text fields, including historical drafts | Unrecognized secret formats and adversarial prompt injection |
| Human actions | Signature checks, approvers, command allowlists, durable request claims and action audits | Staging validation of allowed commands and operator permissions |
| Retention | Old episodes and resolved, digested alerts are purged | Policies for incident history, investigations, claims, deliveries, audit logs, archives and Git history |
| ROI | Feedback accuracy, MTTR and estimated hours saved | Measured baselines and real time saved during a pilot |
| Deployment | Local server and distribution builds verified; readiness configuration added | Docker, PostgreSQL, live integrations, backup/restore, future schema migrations and Grafana links |

## Delivery roadmap

1. **Repair correctness and safety — completed locally.** R1–R12 have regression coverage and passing SQLite checks. Keep actions disabled until the configured commands are validated in staging.
2. **Make deployment repeatable.** Database readiness handling is in place. Add schema migration tooling for future schema changes; verify backup/restore, PostgreSQL tests, Docker startup, shutdown, retention boundaries, and delivery failure recovery. Record reproducible test/coverage results.
3. **Validate a limited staging pilot.** Adapt signal queries; connect real read-only evidence sources and staging notification integrations. Exercise firing, duplicate delivery, escalation, recovery, feedback, digest, and report flows. Confirm evidence links and measure investigation latency rather than inferring it from a timeout.
4. **Evaluate usefulness.** Collect pre-adoption baselines and engineer-reviewed hypotheses. The proposed 60% accuracy target and $100 per on-call user/month price are hypotheses to validate; neither is an achieved result. Likewise, the earlier $20–30 digest valuation was an assumption, not established market evidence.
5. **Choose additional scope from pilot evidence.** Candidates include request tracing (Tempo/Jaeger), config/feature-flag/Terraform correlation, related-warning escalation, MTTA via acknowledgement events, additional integrations, and vector search if current memory retrieval proves insufficient.

The referenced original plan, `ke-hoach-du-an-ai-dieu-tra-su-co.md`, was unavailable at its stated location. This roadmap is a consolidation of the available requirements and review findings; it does not certify completion of that missing plan or all three original phases. SSO requires application and identity-provider integration; hosting region and organizational assurance requirements also need explicit deployment decisions.

## API reference

All listed endpoints except `/healthz` and `/slack/interactions` require `Authorization: Bearer TOKEN` when `IL_WEBHOOK_TOKEN` is configured. Slack interactions use signature verification instead.

| Method and path | Purpose |
| --- | --- |
| `GET /healthz` | Basic liveness |
| `POST /webhooks/alertmanager` | Ingest alerts |
| `GET /alerts/{fingerprint}` | Read stored alert state |
| `GET /incidents`, `GET /incidents/{id}` | List incidents or inspect an incident, investigations, and actions |
| `GET /incidents/{id}/postmortem` | Render the postmortem draft |
| `POST /incidents/{id}/resolution` | Record root cause and fix |
| `POST /investigations/{id}/feedback` | Rate a hypothesis |
| `POST /reports/roi?month=YYYY-MM` | Generate a monthly report |
| `POST /digest/run` | Run a digest manually |
| `POST /escalations/check` | Check pending escalations |
| `POST /maintenance/run` | Run cleanup and monthly reporting |
| `POST /slack/interactions` | Process signed Slack interactions |

## Source map

| Location | Responsibility |
| --- | --- |
| `src/incidentlens/app.py` | FastAPI routes, configuration wiring, schedules |
| `src/incidentlens/service.py` | Alert and incident workflow orchestration |
| `src/incidentlens/store.py`, `models.py` | Persistence and shared data models |
| `src/incidentlens/ingest/`, `routing/` | Alertmanager normalization and rules |
| `src/incidentlens/investigation/`, `changes/` | Evidence collection, comparisons, hypotheses, LLM, deployments |
| `src/incidentlens/memory/`, `actions/` | Similarity retrieval and approved commands |
| `src/incidentlens/digest/`, `reports/`, `outputs/` | Markdown, ROI, postmortems, Slack, PagerDuty, Git archives |
| `config/`, `tests/`, `src/incidentlens/testing.py` | Configuration, automated checks, and simulated services |

The two earlier requirements-review copies are historical inputs to this README. Their earlier completion claims are superseded by the repaired behavior and fresh verification results above.
