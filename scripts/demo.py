#!/usr/bin/env python3
"""Offline end-to-end incident lifecycle demonstration without external credentials.

Run:  python -X utf8 scripts/demo.py

Prometheus, Loki, GitHub, Slack, and PagerDuty are mocked at the HTTP transport layer while the
full IncidentLens application runs locally. Generated digests, postmortems, and ROI reports are
written to demo-output/.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil

from incidentlens.actions.runner import ActionsConfig, ActionSpec
from incidentlens.reports.roi import Baseline, BaselineBefore
from incidentlens.testing import Clock, SimulatedWorld, make_alert, simulated_service

OUT = Path("demo-output")
START = datetime(2026, 11, 12, 2, 14, tzinfo=timezone.utc)


def step(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def show_slack(world: SimulatedWorld, since: int) -> int:
    for message in world.slack[since:]:
        print("\n[Slack]\n" + message["text"])
        buttons = [
            e["text"]["text"]
            for b in message.get("blocks", [])
            if b["type"] == "actions"
            for e in b["elements"]
        ]
        if buttons:
            print("[Buttons] " + "  |  ".join(buttons))
    return len(world.slack)


async def main() -> None:
    shutil.rmtree(OUT, ignore_errors=True)
    clock = Clock(START + timedelta(minutes=2))
    world = SimulatedWorld(START)
    actions = ActionsConfig(
        actions={
            "rollback": ActionSpec(
                label="🔄 Rollback",
                approvers=["U_ALICE"],
                command=["kubectl", "rollout", "undo", "deployment/{service}", "-n", "production"],
            )
        }
    )
    baseline = Baseline(oncall_headcount=4, before=BaselineBefore(mttr_minutes=52))
    lens = simulated_service(OUT, clock, world, actions=actions, baseline=baseline)
    seen = 0

    step("1. 02:16 — Critical alert arrives alongside 6 lower-priority alerts")
    noise = [
        make_alert(name=n, service=s, severity=sev, starts_at=START, summary=text)
        for n, s, sev, text in [
            ("MemoryHigh", "auth-service", "warning", "Pod memory reached 85% of limit"),
            ("DiskSpaceLow", "db-replica-02", "warning", "Disk usage at 85%"),
            ("QueueGrowing", "payment-worker", "warning", "Worker queue growing slowly"),
            ("CertExpiresSoon", "payment-worker", "info", "TLS certificate expires in 20 days"),
            ("StaleMetric", "user-db", "info", "Metric has not updated for 10 minutes"),
        ]
    ]
    noise.append(
        make_alert(
            name="ThirdPartyTimeout",
            service="payment-worker",
            severity="info",
            status="resolved",
            starts_at=START - timedelta(minutes=30),
            ends_at=START - timedelta(minutes=26),
            summary="12 timeouts calling third-party API",
        )
    )
    counts = await lens.handle_alerts(
        [make_alert(starts_at=START, summary="p95 latency 450ms (normal 50ms)"), *noise]
    )
    print(f"Received: {counts}")
    print(f"PagerDuty pages sent: {len(world.pages)} (critical alert only)")
    await lens.drain()
    seen = show_slack(world, seen)

    step("2. 02:20 — Mallory (unauthorized) then Alice (authorized) click Rollback")
    clock.now = START + timedelta(minutes=6)
    print(await lens.handle_interaction("act_rollback", "1:rollback", "U_MALLORY", "mallory", None))
    print(await lens.handle_interaction("act_rollback", "1:rollback", "U_ALICE", "alice", None))

    step("3. 02:25 — Alice confirms hypothesis 1 is correct")
    clock.now = START + timedelta(minutes=11)
    print(await lens.handle_interaction("fb_1", "1:1", "U_ALICE", "alice", None))

    step("4. 02:45 — Incident resolves → postmortem draft written")
    clock.now = START + timedelta(minutes=31)
    await lens.handle_alerts([make_alert(status="resolved", starts_at=START, ends_at=clock.now)])
    await lens.drain()
    seen = show_slack(world, seen)
    print("\n" + (OUT / "postmortems" / "INC-0001.md").read_text(encoding="utf-8"))

    step("5. 06:14 — Scheduled digest for 🟡⚪ alerts (with hypotheses for ongoing action items)")
    clock.now = START + timedelta(hours=4)
    path = await lens.run_digest()
    assert path is not None
    print(path.read_text(encoding="utf-8"))

    step("6. 06:20 — Unresolved 🟡 alert exceeds 4 hours → auto-escalates to 🔴")
    clock.now = START + timedelta(hours=4, minutes=6)
    print("Escalated:", await lens.check_escalations())
    await lens.drain()
    seen = len(world.slack)

    step("7. One week later — similar incident recurs → incident memory surfaces prior root cause")
    world.incident_start = clock.now = START + timedelta(days=7)
    world.deploy_minutes_before = None
    await lens.handle_alerts([make_alert(starts_at=clock.now, summary="p95 latency 500ms")])
    await lens.drain()
    seen = show_slack(world, seen)

    step("8. First day of next month — automated monthly ROI report")
    clock.now = datetime(2026, 12, 1, 6, 0, tzinfo=timezone.utc)
    result = await lens.run_maintenance()
    print(Path(result["roi_report"]).read_text(encoding="utf-8"))
    print(f"Generated artifacts in {OUT}/:")
    for file in sorted(p for p in OUT.rglob("*.md")):
        print("  ", file)


if __name__ == "__main__":
    asyncio.run(main())
