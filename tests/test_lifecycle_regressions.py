import asyncio
from datetime import timedelta

from conftest import START
from incidentlens.investigation.base import NoopInvestigator
from incidentlens.outputs.pagerduty import PagerDutyPager
from incidentlens.outputs.slack import SlackNotifier
from incidentlens.testing import make_alert, simulated_service


async def test_failed_escalation_retries_after_restart(tmp_path, clock, world):
    db = f"sqlite:///{tmp_path}/retry.db"
    first = simulated_service(tmp_path / "archive", clock, world, database_url=db)
    first.investigator = NoopInvestigator()
    await first.handle_alerts([make_alert(severity="warning", starts_at=START)])
    clock.now += timedelta(hours=5)
    world.fail_hosts.update({"events.pagerduty.com", "slack.com"})
    await first.check_escalations()
    await first.drain()
    assert not world.pages and not world.slack
    world.fail_hosts.clear()
    second = simulated_service(tmp_path / "archive", clock, world, database_url=db)
    await second.check_escalations()
    assert [p["event_action"] for p in world.pages] == ["trigger"]
    assert len(world.slack) == 1
    assert len(second.store.list_incidents()) == 1
    await second.check_escalations()
    assert len(world.pages) == 1 and len(world.slack) == 1


async def test_retries_only_failed_notification_channel(lens, clock, world):
    lens.investigator = NoopInvestigator()
    await lens.handle_alerts([make_alert(severity="warning", starts_at=START)])
    clock.now += timedelta(hours=5)
    world.fail_hosts.add("slack.com")
    await lens.check_escalations()
    await lens.drain()
    assert len(world.pages) == 1 and not world.slack
    world.fail_hosts.clear()
    await lens.check_escalations()
    assert len(world.pages) == 1 and len(world.slack) == 1


async def test_concurrent_escalation_checks_create_one_incident(lens, clock, world):
    lens.investigator = NoopInvestigator()
    await lens.handle_alerts([make_alert(severity="warning", starts_at=START)])
    clock.now += timedelta(hours=5)
    await asyncio.gather(*(lens.check_escalations() for _ in range(5)))
    await lens.drain()
    assert len(lens.store.list_incidents()) == 1
    assert len(world.pages) == 1 and len(world.slack) == 1


async def test_recovery_during_digest_remains_pending(lens, clock):
    lens.investigator = NoopInvestigator()
    entered, release = asyncio.Event(), asyncio.Event()

    class Changes:
        async def recent_changes(self, service, since):
            entered.set()
            await release.wait()
            return []

    lens.changes = Changes()
    alert = make_alert(severity="warning", starts_at=START)
    await lens.handle_alerts([alert])
    running = asyncio.create_task(lens.run_digest())
    await asyncio.wait_for(entered.wait(), 2)
    clock.now += timedelta(minutes=1)
    await lens.handle_alerts([alert.model_copy(update={"status": "resolved", "ends_at": clock.now})])
    release.set()
    first = await running
    assert "ongoing" in first.read_text(encoding="utf-8")
    recovery = await lens.run_digest()
    assert recovery is not None and "resolved" in recovery.read_text(encoding="utf-8")
    assert await lens.run_digest() is None
    await lens.drain()


async def test_new_episode_preserves_pending_resolution(lens, clock, world):
    lens.investigator = NoopInvestigator()
    alert = make_alert(starts_at=START)
    await lens.handle_alerts([alert])
    old_key = world.pages[-1]["dedup_key"]
    world.fail_hosts.add("events.pagerduty.com")
    await lens.handle_alerts([alert.model_copy(update={"status": "resolved", "ends_at": clock.now})])
    clock.now += timedelta(hours=1)
    await lens.handle_alerts([alert.model_copy(update={"starts_at": clock.now})])
    world.fail_hosts.clear()
    await lens.check_escalations()
    await lens.drain()
    triggers = [p["dedup_key"] for p in world.pages if p["event_action"] == "trigger"]
    resolves = [p["dedup_key"] for p in world.pages if p["event_action"] == "resolve"]
    assert resolves == [old_key]
    assert len(triggers) == 2 and triggers[0] != triggers[1]
    assert lens.store.get_incident(2).resolved_at is None


async def test_failed_escalation_resolution_retries(lens, clock, world):
    lens.investigator = NoopInvestigator()
    alert = make_alert(severity="warning", starts_at=START)
    await lens.handle_alerts([alert])
    clock.now += timedelta(hours=5)
    await lens.check_escalations()
    world.fail_hosts.add("events.pagerduty.com")
    await lens.handle_alerts([alert.model_copy(update={"status": "resolved", "ends_at": clock.now})])
    world.fail_hosts.clear()
    await lens.check_escalations()
    await lens.drain()
    assert [p["event_action"] for p in world.pages] == ["trigger", "resolve"]


async def test_resolved_webhook_recovers_interrupted_local_close(lens, clock, world):
    lens.investigator = NoopInvestigator()
    alert = make_alert(severity="warning", starts_at=START)
    await lens.handle_alerts([alert])
    clock.now += timedelta(hours=5)
    await lens.check_escalations()
    # Simulate shutdown after saving closure but before queuing notifications.
    recovered = alert.model_copy(update={"status": "resolved", "ends_at": clock.now})
    lens.store.record(lens.router.classify(recovered), clock.now)
    lens.store.close_incident(alert.fingerprint, clock.now)
    await lens.handle_alerts([recovered])
    await lens.drain()
    assert [p["event_action"] for p in world.pages] == ["trigger", "resolve"]
    assert world.pages[0]["dedup_key"] == world.pages[1]["dedup_key"]


async def test_resolution_cancels_failed_trigger(lens, clock, world):
    lens.investigator = NoopInvestigator()
    alert = make_alert(severity="warning", starts_at=START)
    await lens.handle_alerts([alert])
    clock.now += timedelta(hours=5)
    world.fail_hosts.update({"events.pagerduty.com", "slack.com"})
    await lens.check_escalations()
    await lens.handle_alerts([alert.model_copy(update={"status": "resolved", "ends_at": clock.now})])
    world.fail_hosts.clear()
    await lens.check_escalations()
    await lens.drain()
    assert [p["event_action"] for p in world.pages] == ["resolve"]
    assert len(world.slack) == 1 and "Resolved:" in world.slack[0]["text"]


async def test_concurrent_resolution_leaves_closed_incident(lens, clock):
    lens.investigator = NoopInvestigator()
    entered, release = asyncio.Event(), asyncio.Event()
    calls = []

    class Pager:
        async def trigger(self, **kwargs):
            entered.set()
            await release.wait()
            calls.append("trigger")
            return True

        async def resolve(self, key):
            calls.append("resolve")
            return True

    lens.pager = Pager()
    alert = make_alert(starts_at=START)
    firing = asyncio.create_task(lens.handle_alerts([alert]))
    await asyncio.wait_for(entered.wait(), 2)
    recovery = asyncio.create_task(
        lens.handle_alerts([alert.model_copy(update={"status": "resolved", "ends_at": clock.now})])
    )
    await asyncio.sleep(0)
    release.set()
    await asyncio.gather(firing, recovery)
    await lens.drain()
    assert lens.store.get_incident(1).resolved_at == clock.now
    assert calls == ["trigger", "resolve"]


async def test_stale_recovery_does_not_close_new_episode(lens, clock, world):
    lens.investigator = NoopInvestigator()
    old = make_alert(starts_at=START)
    recovered = old.model_copy(update={"status": "resolved", "ends_at": clock.now})
    await lens.handle_alerts([old, recovered])
    clock.now += timedelta(hours=1)
    await lens.handle_alerts([old.model_copy(update={"starts_at": clock.now})])
    await lens.handle_alerts([recovered])
    await lens.drain()
    assert lens.store.get(old.fingerprint).status == "firing"
    assert lens.store.get_incident(2).resolved_at is None
    assert world.pages[-1]["event_action"] == "trigger"


async def test_stale_firing_does_not_reopen_resolved_episode(lens, clock):
    lens.investigator = NoopInvestigator()
    alert = make_alert(starts_at=START)
    await lens.handle_alerts([alert, alert.model_copy(update={"status": "resolved", "ends_at": clock.now})])
    await lens.handle_alerts([alert])
    await lens.drain()
    assert lens.store.get(alert.fingerprint).status == "resolved"
    assert len(lens.store.list_incidents()) == 1


async def test_digested_warning_publishes_recovery_once(lens, clock):
    alert = make_alert(severity="warning", starts_at=START)
    await lens.handle_alerts([alert])
    await lens.run_digest()
    clock.now += timedelta(minutes=30)
    recovered = alert.model_copy(update={"status": "resolved", "ends_at": clock.now})
    await lens.handle_alerts([recovered])
    path = await lens.run_digest()
    assert path is not None and "resolved" in path.read_text(encoding="utf-8")
    await lens.handle_alerts([recovered])
    assert await lens.run_digest() is None
    await lens.drain()


async def test_unconfigured_pagerduty_is_not_treated_as_failure_or_queued(lens, clock, world):
    lens.investigator = NoopInvestigator()
    lens.pager = PagerDutyPager(None, world.client())

    alert = make_alert(starts_at=START)
    await lens.handle_alerts([alert])
    await lens.drain()

    assert world.pages == []
    assert len(world.slack) == 1
    assert "<!channel>" not in world.slack[0]["text"]
    assert lens.store.pending_deliveries() == []

    clock.now += timedelta(minutes=1)
    await lens.check_escalations()
    assert len(world.slack) == 1
    assert lens.store.pending_deliveries() == []

    clock.now += timedelta(minutes=10)
    await lens.handle_alerts([alert.model_copy(update={"status": "resolved", "ends_at": clock.now})])
    await lens.drain()
    assert len(world.slack) == 2
    assert lens.store.pending_deliveries() == []


async def test_unconfigured_slack_and_pagerduty_escalation_and_resolution_leave_no_queue(lens, clock, world):
    lens.investigator = NoopInvestigator()
    lens.pager = PagerDutyPager(None, world.client())
    lens.notifier = SlackNotifier(world.client())

    warn = make_alert(name="DiskSpaceLow", service="db-replica-02", severity="warning", starts_at=START)
    await lens.handle_alerts([warn])
    clock.now += timedelta(hours=5)
    assert await lens.check_escalations() == ["db-replica-02-DiskSpaceLow"]
    assert lens.store.pending_deliveries() == []

    postmortem = lens.archive.root / "postmortems" / "INC-0001.md"
    postmortem.parent.mkdir(parents=True, exist_ok=True)
    postmortem.write_text("Custom edited postmortem", encoding="utf-8")

    clock.now += timedelta(minutes=10)
    await lens.handle_alerts([warn.model_copy(update={"status": "resolved", "ends_at": clock.now})])
    await lens.drain()
    assert lens.store.pending_deliveries() == []
    assert postmortem.read_text(encoding="utf-8") == "Custom edited postmortem"
