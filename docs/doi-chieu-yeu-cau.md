# Requirements Traceability

> Historical requirements mapping against the codebase and automated test suite. See [verification-and-repairs.md](verification-and-repairs.md) for current verification results and repair history.

Legend: ✅ implemented and tested · ⚠️ implemented with documented design trade-off · ⬜ outside application scope or roadmap item.

## 1. Core design principles

| Principle | Status | Verification |
| :--- | :-: | :--- |
| Critical alerts never wait on AI | ✅ | `test_critical_pages_first_then_investigates`, `test_broken_investigation_never_blocks_paging`, `test_slow_investigation_is_cut_off` |
| AI suggests, humans decide | ✅ | `test_action_denied_cases`, `test_dry_run_by_default_does_not_execute`, `test_slack_buttons_require_valid_signature` |
| Every claim cites collected evidence | ✅ | `test_full_investigation_finds_deploy`, `test_no_evidence_means_no_hypothesis`, `test_llm_hallucinated_evidence_is_dropped`, `test_investigation_model_caps_hypotheses` |
| Reuse existing infrastructure | ✅ | Initial grouping and repeat intervals handled by Alertmanager (`config/alertmanager.example.yml`) |
| Measurable operational value | ✅ | `test_roi_numbers`, `test_roi_with_measured_baseline` |

## 2. Classification and escalation

| Requirement | Status | Verification |
| :--- | :-: | :--- |
| Three severities (🔴🟡⚪) determined by static rules | ✅ | `tests/test_routing.py` |
| 🔴 pages PagerDuty + Slack immediately | ✅ | `test_critical_pages_first_then_investigates`, `test_pagerduty_trigger_resolve_and_dry_run` |
| Repeat deliveries do not spam or re-investigate | ✅ | `test_resend_does_not_spam_or_reinvestigate` |
| Auto-escalate long-standing warnings | ✅ | `test_warning_is_not_paged_but_escalates_later`, `test_escalation_uses_real_start_time` |
| Auto-escalate high-repeat warnings | ✅ | `test_escalation_after_too_many_repeats` |
| Correlated multi-warning escalation | ⬜ | Dependency alerts are used as investigation evidence, not yet as a joint escalation trigger |

## 3. Core capabilities

| Capability | Status | Verification |
| :--- | :-: | :--- |
| ① Investigation: metrics, logs, deploys, dependencies → 1–3 hypotheses | ✅ | `tests/test_engine.py`, `tests/test_signals.py` |
| ① Bounded investigation runtime | ✅ | Configurable timeout (240s default); elapsed seconds recorded on each investigation |
| ① Distributed trace correlation | ⬜ | Roadmap item (Tempo/Jaeger not yet connected) |
| ② Deployment correlation | ✅ | `test_github_deployments`, `test_deploy_after_incident_is_not_blamed` |
| ② Config, feature flag, and Terraform changes | ⬜ | Roadmap item via `ChangeProvider` protocol |
| ③ Incident memory | ⚠️ | `test_memory_of_past_incident`, `test_memory_prefers_incidents_with_known_cause`. Uses structured + token overlap scoring rather than `pgvector` embeddings |
| ④ Human-approved actions with audit log, lock, and cooldown | ✅ | `tests/test_memory_actions.py`, `tests/test_slack_replay.py` |
| ⑤ Automated monthly ROI report and postmortem drafts | ✅ | `tests/test_reports.py`, `test_get_postmortem_is_read_only_and_preserves_manual_edits` |

## 4. AI safety and security boundaries

| Control | Status | Verification |
| :--- | :-: | :--- |
| LLM never controls paging | ✅ | `routing/rules.py` has no dependency on `investigation/` |
| LLM never executes commands | ✅ | `ActionRunner` is reachable only via verified Slack interactions |
| Deterministic confidence scoring | ✅ | `test_confidence_rules`, `test_llm_rewrites_but_code_sets_confidence` |
| Human root cause preserved over machine feedback | ✅ | `test_human_root_cause_never_overwritten_by_feedback`, `test_negative_feedback_undoes_machine_root_cause` |
| Graceful fallback to rules on LLM failure | ✅ | `test_llm_garbage_or_outage_falls_back_to_rules`, `test_malformed_llm_item_preserves_complete_rule_investigation` |
| Secret and PII redaction | ✅ | `tests/test_redact.py`, `test_llm_never_receives_raw_secrets`, `test_llm_redacts_historical_root_cause_and_fix` |
| Self-hosted / OpenAI-compatible LLM support | ✅ | `OpenAICompatibleLLM`, `test_openai_compatible_client` |
| Data residency, SOC 2, SSO | ⬜ | Deployment and organizational governance |
