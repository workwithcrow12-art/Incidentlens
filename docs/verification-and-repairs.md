# Verification Log and Completed Repairs

## Completed repairs

Every defect below was reproduced with a failing regression test first and verified after applying the fix.

### Third review round (2026-11-26)

| ID | Repaired behavior | Regression coverage |
| --- | --- | --- |
| R17 | Postmortem files track the SHA-256 of the last system-generated draft (`postmortem_sha256:{id}`). Adding `root_cause`/`fix`, recording hypothesis feedback, or finishing a late investigation regenerates unedited postmortem files and serves fresh `GET /incidents/{id}/postmortem` content, while manual file edits on disk are never overwritten. | `test_postmortem_regenerates_on_post_recovery_updates_until_manually_edited`, `test_get_postmortem_is_read_only_and_preserves_manual_edits` |
| R18 | Missing `IL_PAGERDUTY_ROUTING_KEY` emits a `WARNING` at application startup, logs dry-run PagerDuty calls at `WARNING`, and appends `⚠️ PagerDuty not configured, nobody was paged` to critical and auto-escalated Slack alerts without queuing false retries. | `test_unconfigured_pagerduty_is_not_treated_as_failure_or_queued`, `test_startup_does_not_warn_when_pagerduty_is_configured`, `test_pagerduty_trigger_resolve_and_dry_run` |
| R19 | Per-service `cooldown_seconds` applies to any attempted execution (`executed` or `failed`, including command timeouts), and repeating an already-attempted action on the same incident requires explicit single-use re-confirmation (`act_confirm_<action>`). | `test_timed_out_action_starts_cooldown_blocking_second_approver`, `test_action_cooldown_and_same_incident_reconfirmation`, `test_fresh_signed_action_respects_cooldown_and_requires_reconfirm` |
| R20 | Redaction covers `DB_PASS=…`, CLI flags (`--password …`, `--token …`), `sk-ant-…` / `sk-proj-…` API keys, URL passwords containing `/` or `@`, and `Authorization: Token …` (keeping `Token` while redacting the secret), while preserving operational counters (`token_count=15`, `max_tokens: 1000`). | `tests/test_redact.py` |
| R21 | Alert batches group by fingerprint to preserve per-alert ordering while delivering distinct fingerprints concurrently (`asyncio.gather`). | `test_alert_batch_delivers_concurrently_across_fingerprints` |
| R22 | Scheduled background jobs run immediately when due and persist `schedule:<name>` timestamps in `kv` so process restarts preserve remaining timer intervals instead of resetting them. | `test_scheduled_jobs_run_immediately_and_preserve_timer_across_restarts` |
| R23 | Empty or unset `IL_WEBHOOK_TOKEN` fails closed (`401`) unless `IL_ALLOW_UNAUTHENTICATED=true` is explicitly set; `docker-compose.yml` binds `127.0.0.1:8000:8000` by default and requires a non-empty `IL_WEBHOOK_TOKEN`. | `test_empty_or_unset_webhook_token_fails_closed`, `test_compose_binds_loopback_and_requires_webhook_token` |
| R24 | Missing Prometheus baseline samples (`[]`) return `None` instead of counting as `0.0`, while measured zero baselines (`[0.0, ...]`) still detect anomalies. | `test_appears_from_zero_requires_measured_baseline`, `test_missing_prometheus_baseline_creates_no_false_evidence` |
| R25 | Pod PromQL templates match controller pod suffixes (`{service}-([a-z0-9]{8,10}-[a-z0-9]{5}|[0-9]+)`) and escape dots inside regex matchers so sibling services (`{service}-worker`, `{service}-service`) cannot match. | `test_shipped_config_is_valid_and_pod_queries_do_not_match_other_services` |
| R26 | `IncidentLens.drain()` prunes already-finished tasks (`t.done()`) before calling `asyncio.gather`, eliminating an infinite non-yielding loop on Python 3.12/Linux when a task finishes right before its `discard` callback runs; PostgreSQL `Store` engines enable `pool_pre_ping=True`. | `test_drain_does_not_spin_when_task_completes_before_discard_callback`, `test_new_episode_preserves_pending_resolution` |
| R27 | `.env.example` keeps all comments on standalone `#` lines rather than inline after `KEY=`, preventing Docker Compose and `--env-file` parsers from treating inline comment text as literal secret/URL values (which previously bypassed `${IL_WEBHOOK_TOKEN:?}` and populated `IL_SLACK_SIGNING_SECRET`); `Settings` normalizes blank/whitespace-only optional strings to `None`. | `test_env_example_has_no_inline_comments_that_break_docker_compose` |

### Second review round (2026-11-26)

| ID | Repaired behavior | Regression coverage |
| --- | --- | --- |
| R13 | One-click actions are refused on resolved incidents, serialized per service with an in-process lock, and gated by a configurable per-service cooldown (`cooldown_seconds`, 300s default) persisted in `action_log`. | `test_two_approvers_clicking_at_once_execute_only_once`, `test_action_cooldown_blocks_repeat_until_expired`, `test_action_refused_on_resolved_incident`, `test_fresh_signed_action_respects_cooldown_then_can_repeat` |
| R14 | Secret redaction covers prefixed/suffixed key-value names (`DB_PASSWORD=…`, `client_secret=…`, `access_token: …`, `SECRET_KEY=…`), URL credentials (`postgres://admin:password@…`, `redis://:secret@…`), GitHub tokens (`ghp_…`, `github_pat_…`), and Slack tokens (`xoxb-…`, `xoxp-…`) without clobbering `host:port` service URLs. | `tests/test_redact.py` |
| R15 | Confirming a hypothesis never overwrites a human-authored root cause; marking "none correct" clears a hypothesis-derived root cause while preserving human entries; `GET /incidents/{id}/postmortem` is strictly read-only and never overwrites manual edits on disk. | `test_human_root_cause_never_overwritten_by_feedback`, `test_negative_feedback_undoes_machine_root_cause`, `test_get_postmortem_is_read_only_and_preserves_manual_edits` |
| R16 | Unconfigured PagerDuty and Slack channels return `DeliveryStatus.NOT_CONFIGURED`, emit an informational dry-run log without queuing retry rows, and do not trigger false `<!channel>` PagerDuty failure alerts. | `test_unconfigured_pagerduty_is_not_treated_as_failure_or_queued`, `tests/test_clients.py` |

### Initial review round (2026-11-16)

| ID | Repaired behavior | Regression coverage |
| --- | --- | --- |
| R1 | Failed incident-opening notifications remain queued independently for PagerDuty and Slack. The escalation schedule retries them after recovery or restart without recreating the incident. | `test_failed_escalation_retries_after_restart`, `test_retries_only_failed_notification_channel` |
| R2 | LLM input redaction covers historical draft hypotheses and alert name/service/summary as well as evidence descriptions. | `test_llm_redacts_historical_root_cause_and_fix`, `test_llm_redacts_every_alert_text_field` |
| R3 | Identical valid signed Slack requests are atomically claimed in persistent storage before background execution. Concurrent retries and restarts execute the command at most once. | `tests/test_slack_replay.py` |
| R4 | Firing and recovery for the same fingerprint are ordered; recovery cannot leave an incident open behind an unfinished paging call. | `test_concurrent_resolution_leaves_closed_incident` |
| R5 | The complete LLM response schema is validated inside the fallback handler. Malformed fields retain rule hypotheses and evidence. | `test_malformed_llm_item_preserves_complete_rule_investigation`, `test_malformed_llm_envelope_falls_back_to_rules` |
| R6 | A previously digested warning becomes pending again when it resolves. Its recovery is published once, including when recovery arrives during digest collection. | `test_digested_warning_publishes_recovery_once`, `test_recovery_during_digest_remains_pending` |
| R7 | ROI path assertions use `pathlib` and JSON fixtures explicitly use UTF-8. | `tests/test_reports.py`, `tests/test_api.py`, `tests/test_alertmanager.py` |
| R8 | Stale recovery cannot close a newer episode; stale firing cannot reopen an already recovered episode. | `test_stale_recovery_does_not_close_new_episode`, `test_stale_firing_does_not_reopen_resolved_episode` |
| R9 | Failed recovery notifications retry independently. New incidents use distinct PagerDuty keys while older pending resolves remain deliverable. | `test_failed_escalation_resolution_retries`, `test_new_episode_preserves_pending_resolution` |
| R10 | Digest filenames are created exclusively, adding a numeric suffix on collisions. Repeated and concurrent writes preserve every report. | `tests/test_archive_regressions.py` |
| R11 | Only deployments at or before alert onset are considered causal candidates. Later mitigation deployments cannot displace earlier causes. | `test_deploy_after_incident_is_not_blamed` and deployment boundary cases in `tests/test_engine.py` |
| R12 | Git synchronization attempts to push existing local commits even with a clean index; concurrent synchronization is serialized. | `test_clean_sync_retries_failed_push_after_restart`, `test_concurrent_syncs_do_not_mix_staged_changes` |

### Operational notes on persistence and retries

- The database creates `notification_deliveries` and `interaction_claims` alongside existing `alerts`, `episodes`, `incidents`, `investigations`, `action_log`, and `kv` tables at startup. Schema migrations are not yet implemented; back up databases before upgrading.
- Notification retries run every `IL_ESCALATION_CHECK_SECONDS` (60 seconds by default), or via `POST /escalations/check` when schedules are disabled. Unconfigured channels (`DeliveryStatus.NOT_CONFIGURED`) are not queued for retries.
- Slack interaction replay deduplication is atomic across store instances. In addition, approved actions acquire a per-service lock, refuse resolved incidents, and enforce `cooldown_seconds` after any executed action on that service.

## Local and Docker verification summary

Verified on **2026-11-26** across local Windows and Linux Docker (`python:3.12-slim` + `pgvector/pgvector:pg16`):

- **214 tests passed** with **98% statement coverage** on both SQLite and live PostgreSQL 16 (`pgvector/pgvector:pg16`).
- **`mypy src scripts` passed** with zero errors across 38 files.
- The offline lifecycle demonstration (`scripts/demo.py`) completed cleanly locally and inside Docker.
- Source (`sdist`) and wheel (`bdist_wheel`) distributions built cleanly (`uv build`).
- Production `Dockerfile` image and live `docker compose` stack (`incidentlens` + `pgvector/pgvector:pg16`) verified end-to-end: empty-token Compose guard, loopback port binding (`127.0.0.1:8000`), `401` bearer-token enforcement, `scripts/send_sample.sh`, postmortem/ROI/digest generation, Slack HMAC signature + replay deduplication, and PostgreSQL persistence across container restarts.

```bash
python -m mypy src scripts
python -m pytest --cov=incidentlens --cov-report=term-missing
python -X utf8 scripts/demo.py
uv build
```

For disposable local PostgreSQL testing (drops and recreates tables when `IL_TEST_DATABASE_URL` is set):

```powershell
$env:IL_TEST_DATABASE_URL = 'postgresql+psycopg://USER:PASSWORD@localhost/incidentlens_test'
python -X utf8 -m pytest -q
Remove-Item Env:IL_TEST_DATABASE_URL
```

## Established guarantees vs. staging validation

| Area | Established locally | Remaining staging validation |
| --- | --- | --- |
| Paging | Rule-based routing, persistent per-channel retries when configured, clean dry-run skip when unconfigured, separate episode keys | Live PagerDuty/Slack rate limits, credentials, and operational recovery |
| Hypotheses | Strict schema validation, evidence ID checks, deterministic confidence, rule fallback | Real-world incident accuracy; valid citations alone do not prove causality |
| Secret redaction | Key-value prefixes/suffixes, URL credentials, JWTs, Bearer/Basic auth, AWS/GitHub/Slack tokens, emails, Luhn cards, phone numbers | Organization-specific proprietary secret formats and adversarial log payloads |
| Human actions | Slack HMAC verification, approver lists, command allowlists, durable replay claims, resolved-incident refusal, per-service lock and cooldown | Staging validation of allowed commands, `kubectl` availability, and RBAC scopes |
| Human authorship | Manual root causes are preserved across hypothesis feedback; `GET /incidents/{id}/postmortem` is read-only | Multi-editor postmortem collaboration workflows |
| Retention & ROI | Old episodes and resolved+digested alerts purged; feedback accuracy, MTTR, and estimated hours saved reported | Measured pre-adoption baselines and observed pilot time savings |
| Deployment | Local server, typechecking, lockfile, CI workflow, and distribution builds verified | Live Docker Compose, backup/restore drills, schema migrations, and Grafana links |
