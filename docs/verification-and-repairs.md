# Verification Log and Completed Repairs

## Completed repairs

Every defect below was reproduced with a failing regression test first and verified after applying the fix.

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

## Local verification summary

Verified on **2026-11-26** (Windows, Python 3.14.6, SQLite):

- **179 tests passed** with **98% statement coverage**.
- **`mypy src scripts` passed** with zero errors across 38 files.
- The offline lifecycle demonstration (`scripts/demo.py`) completed and generated sample digests, postmortems, and ROI reports in English.
- Source (`sdist`) and wheel (`bdist_wheel`) distributions built cleanly.
- Docker and live PostgreSQL were not executed locally on this host; GitHub Actions CI includes a PostgreSQL 16 integration job (`pgvector/pgvector:pg16`).

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
