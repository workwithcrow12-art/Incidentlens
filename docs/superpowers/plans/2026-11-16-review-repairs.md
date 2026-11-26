# Review repairs implementation plan

**Goal:** Repair README R1–R7 and the five additional reproduced review defects, verify the existing application, and update its documented status.

**Architecture:** Keep FastAPI, SQLAlchemy, and the single-process scheduler. Add durable notification deliveries and Slack interaction claims as new tables so existing databases remain readable. Serialize alert transitions and escalation jobs in the service, reject stale episodes, and mark digest snapshots only when their stored state still matches.

**Scope:** Existing product capabilities and confirmed defects. Live credentials, infrastructure deployment, and proposed roadmap integrations remain deployment work.

## Tasks

- [x] Notifications and lifecycle: regression tests for outage/recovery, restart, concurrent firing/resolution, stale recovery, and digest recovery; implement durable deliveries and ordered transitions in service.py/store.py.
- [x] Slack: signed request replay/concurrency/restart tests; atomically claim requests before executing commands.
- [x] Investigation: historical-secret redaction, malformed schema fallback, and post-onset deployment regression tests; fix llm.py/engine.py.
- [x] Archive: collision and recovered Git push tests; exclusive filenames and serialized synchronization; repair Windows path assertion.
- [x] Verification: full pytest suite with coverage, offline demo and package/startup checks where available; review fixes independently.
- [x] Documentation: replace open-defect claims with fix/test evidence and preserve staging limitations.

## Verification baseline

2026-11-16: 114 passed, 1 failed (Windows path assertion). All six README runtime defects reproduced offline, plus stale recovery, failed resolve retry, archive collision, later deployment attribution, and Git push retry.

No Git metadata exists in the supplied project directory; changes are made in place. Tests require execution outside the filesystem sandbox because its socket restrictions prevent Python from creating an asyncio event loop. External integrations use mock HTTP transports.

## Final verification

160 passed, 99% statement coverage on Windows/Python 3.14.6/SQLite. Offline demo, source/wheel build, and local uvicorn startup/auth/ingestion/shutdown passed. One upstream Starlette/httpx deprecation warning remains. Docker and PostgreSQL are unavailable; live staging validation remains required. Review identified cross-episode PagerDuty deduplication; added a failing regression then fixed independent keys and preservation of old pending resolves.
