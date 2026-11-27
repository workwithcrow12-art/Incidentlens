from datetime import datetime, timedelta, timezone
from pathlib import Path
import re

from conftest import START
from incidentlens.digest.render import render_digest
from incidentlens.models import AlertGroup, Change, Evidence, Hypothesis, Investigation, InvestigationTarget
from incidentlens.reports.roi import Baseline, BaselineBefore, compute_roi, render_roi
from incidentlens.testing import SimulatedWorld, make_alert, simulated_service

NOV = datetime(2026, 11, 1, tzinfo=timezone.utc)


async def month_of_activity(lens, clock):
    """1 critical incident (resolved in 30m, hypothesis confirmed) + 3 warning alerts + 1 info alert."""
    await lens.handle_alerts([make_alert(starts_at=START)])
    await lens.handle_alerts([make_alert(name=f"W{i}", severity="warning", starts_at=START) for i in range(3)])
    await lens.handle_alerts([make_alert(name="Noise", severity="info", starts_at=START)])
    await lens.handle_alerts([make_alert(starts_at=START)])  # Repeat delivery, not a new episode
    await lens.drain()
    lens.record_feedback(1, 1, "alice")
    clock.now = START + timedelta(minutes=30)
    await lens.handle_alerts([make_alert(status="resolved", starts_at=START, ends_at=clock.now)])
    await lens.drain()


async def test_roi_numbers(tmp_path, clock):
    lens = simulated_service(tmp_path, clock, SimulatedWorld(START), baseline=Baseline(oncall_headcount=2))
    await month_of_activity(lens, clock)
    r = compute_roi(lens.store, lens.baseline, NOV, clock.now)

    assert r.days == 11 and r.headcount == 2
    assert r.episodes == 5 and r.interruptions == 1
    assert r.interruptions_now == 1 / 2 / 11
    assert r.interruptions_before is None
    assert r.mttr_now == 30 and r.mttr_before is None
    assert (r.feedback_up, r.feedback_total, r.accuracy) == (1, 1, 1.0)
    assert round(r.hours_saved, 2) == 0.33

    text = render_roi(r)
    assert "5 alert episodes occurred; only 1 paged on-call" in text
    assert "| Interruptions / responder / day | — | 0.05 | — |" in text
    assert "100% (1/1 rated)" in text
    assert "Pre-adoption (estimated)" not in text


async def test_roi_with_measured_baseline(tmp_path, clock):
    baseline = Baseline(
        oncall_headcount=2,
        before=BaselineBefore(
            interruptions_per_person_per_day=1.0, mttr_minutes=60, critical_incidents_per_month=4
        ),
    )
    lens = simulated_service(tmp_path, clock, SimulatedWorld(START), baseline=baseline)
    await month_of_activity(lens, clock)
    text = render_roi(compute_roi(lens.store, baseline, NOV, clock.now))
    assert "| Mean MTTR | 60 min | 30 min | -50% |" in text
    assert "| On-call incidents | 4 | 1 | -75% |" in text
    assert "Pre-adoption (estimated):" not in text


def test_roi_empty_month_does_not_crash(lens, clock):
    r = compute_roi(lens.store, lens.baseline, NOV, clock.now)
    assert r.episodes == 0 and r.accuracy is None and r.interruptions_before is None
    assert "| — |" in render_roi(r)


async def test_maintenance_publishes_last_month_once_and_purges(tmp_path, clock):
    world = SimulatedWorld(START)
    lens = simulated_service(tmp_path, clock, world)
    await month_of_activity(lens, clock)
    await lens.handle_alerts([make_alert(name="Old", severity="info", status="resolved", starts_at=START)])
    await lens.run_digest()

    clock.now = datetime(2026, 12, 1, 6, 0, tzinfo=timezone.utc)
    result = await lens.run_maintenance()
    assert Path(result["roi_report"]) == tmp_path / "reports" / "roi-2026-11.md"
    assert any("Monthly report 11/2026" in m["text"] for m in world.slack)
    assert (await lens.run_maintenance())["roi_report"] is None  # Published once per month

    lens._retention = timedelta(days=10)
    assert lens.store.claim_interaction("old-claim", START) is True
    assert lens.store.claim_interaction("recent-claim", clock.now) is True
    purged = (await lens.run_maintenance())["purged"]
    assert purged == {"alerts": 2, "episodes": 5, "interactions": 1, "deliveries": 4}
    assert lens.store.get("auth-service-Old") is None
    assert lens.store.get("auth-service-HighLatency") is None  # Resolved critical alerts are also purged
    assert lens.store.get("auth-service-W0") is not None  # Ongoing alerts are kept
    incident = lens.store.get_incident(1)
    assert incident is not None  # Incident history is never purged
    assert lens.store.pager_key(incident) == "auth-service-HighLatency:incident:1"  # Preserved after delivery purge
    assert lens.store.get_investigation(1) is not None
    assert lens.store.claim_interaction("recent-claim", clock.now) is False


async def test_purge_keeps_open_or_pending_deliveries_and_undigested_warnings(tmp_path, clock):
    world = SimulatedWorld(START)
    lens = simulated_service(tmp_path, clock, world)
    # 1. Open critical incident: neither its firing alert row nor its open deliveries may be purged.
    await lens.handle_alerts([make_alert(name="OpenCrit", fp="open-crit", starts_at=START)])
    # 2. Resolved warning that has NOT been digested yet: must stay until digested.
    undigested = make_alert(
        name="UndigestedWarn", fp="undigested-warn", severity="warning", status="resolved", starts_at=START
    )
    await lens.handle_alerts([undigested])
    # 3. Closed incident whose PagerDuty resolve failed (done=False): its deliveries must not be purged.
    await lens.handle_alerts([make_alert(name="PendingClose", fp="pending-close", starts_at=START)])
    world.fail_hosts.add("events.pagerduty.com")
    resolved_close = make_alert(
        name="PendingClose",
        fp="pending-close",
        status="resolved",
        starts_at=START,
        ends_at=START + timedelta(minutes=5),
    )
    await lens.handle_alerts([resolved_close])
    await lens.drain()

    purged = lens.store.purge(START + timedelta(days=30))
    assert purged["alerts"] == 1  # Only pending-close's resolved critical AlertRow is purged
    assert purged["deliveries"] == 0
    assert lens.store.get("open-crit") is not None
    assert lens.store.get("undigested-warn") is not None
    open_inc = lens.store.get_incident(1)
    pending_inc = lens.store.get_incident(2)
    assert lens.store.pager_key(open_inc) == "open-crit:incident:1"
    assert lens.store.pager_key(pending_inc) == "pending-close:incident:2"


async def test_markdown_outputs_escape_injected_links_and_unsafe_urls(lens, clock):
    malicious_summary = (
        "Failure [Click here](https://evil.example/phish) "
        "<https://evil.example/auto> ![img](https://evil.example/p.png)"
    )
    alert = make_alert(
        name="Bad[Alert](https://evil.example/name)",
        service="auth-service",
        starts_at=START,
        summary=malicious_summary,
    ).model_copy(update={"source_url": "javascript:alert(1)"})
    await lens.handle_alerts([alert])
    await lens.drain()
    lens.set_resolution(
        1,
        root_cause="Injected [root](https://evil.example/rc)",
        fix="Run [script](https://evil.example/fix)",
    )
    pm = lens.read_postmortem(1)
    assert "[Click here](https://evil.example/phish)" not in pm
    assert r"\[Click here\](https://evil.example/phish)" in pm
    assert "<https://evil.example/auto>" not in pm
    assert "![img](https://evil.example/p.png)" not in pm
    assert "[root](https://evil.example/rc)" not in pm
    assert "[script](https://evil.example/fix)" not in pm

    rec = lens.store.record(
        lens.router.classify(
            make_alert(
                name="Warn[Inject](https://evil.example)",
                severity="warning",
                starts_at=START,
                summary=malicious_summary,
            ).model_copy(update={"source_url": "javascript:alert(1)"})
        ),
        START,
    )
    assert rec is not None
    tgt = InvestigationTarget.from_record(rec)
    inv = Investigation(
        target=tgt,
        evidence=[
            Evidence(
                id="E1",
                kind="log",
                description="log ](https://evil.example/breakout) [x",
                url="http://grafana.test/explore?expr=rate(x[5m])",
            )
        ],
        hypotheses=[
            Hypothesis(statement="See [evil](https://evil.example/h)", confidence="medium", evidence_ids=["E1"])
        ],
    )
    bad_change = Change(
        service="svc",
        kind="deploy",
        ref="a1b2c3d",
        author="[bot](https://evil.example)",
        created_at=START,
        url="javascript:evil()",
    )
    group = AlertGroup(
        service="svc`break",
        name=rec.name,
        team="Team [X](https://evil.example/team)",
        records=[rec],
        changes=[bad_change],
        investigation=inv,
    )
    digest = render_digest([group], START, START + timedelta(hours=1))
    assert "javascript:" not in digest
    assert not re.search(r"(?<!\\)\]\(https://evil\.example", digest)
    assert r"\](https://evil.example/breakout)" in digest
    assert "``svc`break``" in digest
    assert "rate%28x%5B5m%5D%29" in digest


async def test_postmortem_for_unresolved_incident(lens):
    await lens.handle_alerts([make_alert(starts_at=START)])
    await lens.drain()
    text = lens.write_postmortem(1).read_text(encoding="utf-8")
    assert "unresolved" in text and "To be determined" in text
    assert "### System hypotheses" in text


def test_legacy_database_upgrades_missing_columns_on_startup(tmp_path):
    import sqlite3
    from incidentlens.store import Store

    db_file = tmp_path / "legacy.db"
    with sqlite3.connect(db_file) as conn:
        # Pre-upgrade schema lacking incidents.pager_key and notification_deliveries.created_at
        conn.executescript(
            """
            CREATE TABLE incidents (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                fingerprint VARCHAR(128) NOT NULL,
                service VARCHAR(255) NOT NULL,
                name VARCHAR(255) NOT NULL,
                summary TEXT NOT NULL,
                labels JSON NOT NULL,
                origin VARCHAR(16) NOT NULL,
                started_at DATETIME NOT NULL,
                opened_at DATETIME NOT NULL,
                resolved_at DATETIME,
                root_cause TEXT,
                fix TEXT
            );
            CREATE TABLE notification_deliveries (
                key VARCHAR(255) NOT NULL PRIMARY KEY,
                fingerprint VARCHAR(128) NOT NULL,
                incident_id INTEGER,
                channel VARCHAR(16) NOT NULL,
                event VARCHAR(16) NOT NULL,
                payload JSON NOT NULL,
                done BOOLEAN NOT NULL
            );
            INSERT INTO incidents (
                id, fingerprint, service, name, summary, labels, origin, started_at, opened_at, resolved_at
            )
            VALUES (1, 'fp-legacy', 'auth-service', 'HighLatency', 'slow', '{}', 'critical',
                    '2026-10-01T00:00:00+00:00', '2026-10-01T00:00:00+00:00', '2026-10-01T00:20:00+00:00');
            INSERT INTO notification_deliveries (key, fingerprint, incident_id, channel, event, payload, done)
            VALUES ('incident:1:open:pager', 'fp-legacy', 1, 'pager', 'open',
                    '{"dedup_key": "fp-legacy:incident:1"}', 1),
                   ('orphan:done', 'fp-orphan', NULL, 'slack', 'open', '{"text": "old"}', 1),
                   ('incident:1:resolve:slack', 'fp-legacy', NULL, 'slack', 'resolve', '{"text": "pending"}', 0);
            """
        )

    store = Store(f"sqlite:///{db_file}")
    inc = store.get_incident(1)
    assert inc is not None and inc.service == "auth-service"
    assert [d["key"] for d in store.pending_deliveries()] == ["incident:1:resolve:slack"]

    # Purge removes both closed-incident deliveries and backfilled orphan deliveries, while preserving pager_key.
    purged = store.purge(datetime(2027, 1, 1, tzinfo=timezone.utc))
    assert purged["deliveries"] == 2
    assert store.pager_key(inc) == "fp-legacy:incident:1"
