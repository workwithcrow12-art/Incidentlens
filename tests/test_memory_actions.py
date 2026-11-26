import asyncio
from datetime import timedelta
import sys

from conftest import START
from incidentlens.actions.runner import ActionRunner, ActionsConfig, ActionSpec
from incidentlens.memory.similarity import IncidentMemory, similarity
from incidentlens.models import IncidentRecord, InvestigationTarget
from incidentlens.testing import CONFIG, make_alert, simulated_service


def incident(**kw):
    base = dict(
        id=1,
        fingerprint="f",
        service="auth-service",
        name="HighLatency",
        summary="p95 latency 450ms",
        origin="critical",
        started_at=START,
        opened_at=START,
        resolved_at=START + timedelta(minutes=20),
    )
    base.update(kw)
    return IncidentRecord(**base)


def tgt(**kw):
    base = dict(
        fingerprint="f2",
        service="auth-service",
        name="HighLatency",
        summary="p95 latency 500ms",
        started_at=START + timedelta(days=1),
    )
    base.update(kw)
    return InvestigationTarget(**base)


def test_similarity_scores():
    same = similarity(tgt(), incident())
    other_service = similarity(tgt(service="payment-worker"), incident())
    other_alert = similarity(tgt(name="DiskSpaceLow", summary="disk 85%"), incident())
    assert same > other_service > other_alert
    assert same >= 0.7 and other_alert < 0.5


async def test_memory_prefers_incidents_with_known_cause(lens, clock):
    for n in range(2):
        fp = f"auth-HighLatency-{n}"
        await lens.handle_alerts([make_alert(fp=fp, starts_at=START)])
        await lens.drain()
        if n == 1:
            lens.store.set_resolution(2, root_cause="connection pool exhausted", fix="increase max_connections")
        await lens.handle_alerts(
            [make_alert(fp=fp, status="resolved", starts_at=START, ends_at=START + timedelta(minutes=22))]
        )
    similar = IncidentMemory(lens.store).find_similar(tgt())
    assert [s.incident_id for s in similar] == [2, 1]
    assert similar[0].root_cause == "connection pool exhausted" and similar[0].duration_minutes == 22
    assert IncidentMemory(lens.store).find_similar(tgt(name="Other", service="x", summary="zzz")) == []


# ---------- Human-approved actions ----------

SPEC = {
    "echo": ActionSpec(
        label="Echo",
        command=[sys.executable, "-c", "import sys; print('ran', sys.argv[1])", "{service}"],
        services=["auth-service"],
        approvers=["U1"],
    ),
    "fail": ActionSpec(
        label="Fail",
        command=[sys.executable, "-c", "import sys; print('token=abc123'); sys.exit(3)"],
        approvers=["U1"],
    ),
    "slow": ActionSpec(
        label="Slow",
        command=[sys.executable, "-c", "import time; time.sleep(5)"],
        approvers=["U1"],
        timeout_seconds=1,
    ),
    "missing": ActionSpec(label="Missing", command=["/no/such/binary"], approvers=["U1"]),
}


def runner(enabled=True):
    return ActionRunner(ActionsConfig(actions=SPEC), enabled=enabled)


async def test_action_runs_for_approver():
    result = await runner().run("echo", "auth-service", "U1")
    assert result.status == "executed" and result.exit_code == 0 and "ran auth-service" in result.output


async def test_action_denied_cases():
    r = runner()
    assert (await r.run("echo", "auth-service", "U2")).status == "denied"  # unauthorized user
    assert (await r.run("echo", "payment-worker", "U1")).status == "denied"  # disallowed service
    assert (await r.run("rm-rf", "auth-service", "U1")).status == "denied"  # unknown action
    assert (await r.run("fail", "x; rm -rf /", "U1")).status == "denied"  # unsafe service name


async def test_dry_run_by_default_does_not_execute():
    calls = []

    async def executor(argv, timeout):
        calls.append(argv)
        return 0, ""

    r = ActionRunner(ActionsConfig(actions=SPEC), executor=executor)  # enabled defaults to False
    result = await r.run("echo", "auth-service", "U1")
    assert result.status == "dry-run" and calls == [] and "auth-service" in result.output


async def test_failure_timeout_and_missing_binary():
    r = runner()
    failed = await r.run("fail", "auth-service", "U1")
    assert failed.status == "failed" and failed.exit_code == 3
    assert "abc123" not in failed.output  # command output is also redacted
    assert (await r.run("slow", "auth-service", "U1")).status == "failed"
    assert (await r.run("missing", "auth-service", "U1")).status == "failed"


def test_shipped_actions_have_no_approvers_by_default():
    cfg = ActionsConfig.from_yaml(CONFIG / "actions.yaml")
    assert cfg.actions and all(spec.approvers == [] for spec in cfg.actions.values())
    r = ActionRunner(cfg)
    assert [n for n, _ in r.available_for("auth-service")] == ["rollback", "restart"]
    assert [n for n, _ in r.available_for("user-db")] == ["restart"]
    assert r.available_for("bad name") == []


async def test_two_approvers_clicking_at_once_execute_only_once(tmp_path, clock, world):
    executed = []
    entered = asyncio.Event()
    release = asyncio.Event()

    async def slow_executor(argv, timeout):
        executed.append(argv)
        entered.set()
        await release.wait()
        return 0, "rolled back"

    cfg = ActionsConfig(
        actions={
            "rollback": ActionSpec(
                label="Rollback",
                command=["kubectl", "rollout", "undo", "deployment/{service}"],
                approvers=["U1", "U2"],
                cooldown_seconds=300,
            )
        }
    )
    lens = simulated_service(tmp_path, clock, world, actions=cfg, actions_enabled=True)
    lens.actions._executor = slow_executor
    await lens.handle_alerts([make_alert(starts_at=START)])
    await lens.drain()

    first = asyncio.create_task(lens.run_action(1, "rollback", "U1", "alice"))
    await asyncio.wait_for(entered.wait(), 2)
    second = asyncio.create_task(lens.run_action(1, "rollback", "U2", "bob"))
    await asyncio.sleep(0)
    release.set()
    r1, r2 = await asyncio.gather(first, second)

    assert executed == [["kubectl", "rollout", "undo", "deployment/auth-service"]]
    assert r1.startswith("✅")
    assert r2.startswith("⛔")
    statuses = [a.status for a in lens.store.actions_for_incident(1)]
    assert statuses == ["executed", "denied"]


async def test_action_cooldown_blocks_repeat_until_expired(tmp_path, clock, world):
    executed = []

    async def track_executor(argv, timeout):
        executed.append(argv)
        return 0, "rolled back"

    cfg = ActionsConfig(
        actions={
            "rollback": ActionSpec(
                label="Rollback",
                command=["kubectl", "rollout", "undo", "deployment/{service}"],
                approvers=["U1", "U2"],
                cooldown_seconds=300,
            )
        }
    )
    lens = simulated_service(tmp_path, clock, world, actions=cfg, actions_enabled=True)
    lens.actions._executor = track_executor
    await lens.handle_alerts([make_alert(starts_at=START)])
    await lens.drain()

    assert (await lens.run_action(1, "rollback", "U1", "alice")).startswith("✅")
    clock.now += timedelta(seconds=120)
    assert (await lens.run_action(1, "rollback", "U2", "bob")).startswith("⛔")
    assert len(executed) == 1

    clock.now += timedelta(seconds=181)
    assert (await lens.run_action(1, "rollback", "U2", "bob")).startswith("✅")
    assert len(executed) == 2


async def test_action_refused_on_resolved_incident(tmp_path, clock, world):
    executed = []

    async def track_executor(argv, timeout):
        executed.append(argv)
        return 0, "rolled back"

    cfg = ActionsConfig(
        actions={
            "rollback": ActionSpec(
                label="Rollback",
                command=["kubectl", "rollout", "undo", "deployment/{service}"],
                approvers=["U1"],
            )
        }
    )
    lens = simulated_service(tmp_path, clock, world, actions=cfg, actions_enabled=True)
    lens.actions._executor = track_executor
    await lens.handle_alerts([make_alert(starts_at=START)])
    await lens.drain()
    clock.now = START + timedelta(minutes=15)
    await lens.handle_alerts([make_alert(status="resolved", starts_at=START, ends_at=clock.now)])
    await lens.drain()

    msg = await lens.run_action(1, "rollback", "U1", "alice")
    assert msg.startswith("⛔")
    assert executed == []
    assert [a.status for a in lens.store.actions_for_incident(1)] == ["denied"]
