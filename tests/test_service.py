"""Các luồng nghiệp vụ đầy đủ, chạy trên toàn bộ mã nguồn thật với hệ thống bên ngoài giả lập."""

import subprocess
from datetime import timedelta

from conftest import START, texts
from incidentlens.actions.runner import ActionsConfig, ActionSpec
from incidentlens.investigation.base import NoopInvestigator
from incidentlens.models import Investigation
from incidentlens.testing import SimulatedWorld, make_alert, simulated_service

CRIT = dict(starts_at=START, summary="p95 latency 450ms")


# ---------- 🔴 Khẩn cấp ----------


async def test_critical_pages_first_then_investigates(lens, world):
    await lens.handle_alerts([make_alert(**CRIT)])
    # Đã gọi on-call và báo Slack TRƯỚC khi cuộc điều tra kết thúc
    assert len(world.pages) == 1 and world.pages[0]["event_action"] == "trigger"
    assert len(world.slack) == 1 and "INC-0001" in world.slack[0]["text"]

    await lens.drain()
    card = world.slack[1]
    assert "Điều tra tự động" in card["text"] and "*[Cao]*" in card["text"]
    action_ids = [e["action_id"] for b in card["blocks"] if b["type"] == "actions" for e in b["elements"]]
    assert action_ids == ["runbook", "act_rollback", "act_restart", "fb_1", "fb_2", "fb_0"]
    assert all(len(b["text"]["text"]) <= 3000 for b in card["blocks"] if b["type"] == "section")


async def test_resend_does_not_spam_or_reinvestigate(lens, world):
    for _ in range(3):  # Alertmanager gửi lại định kỳ
        await lens.handle_alerts([make_alert(**CRIT)])
    await lens.drain()
    assert len(world.pages) == 3  # PagerDuty tự khử trùng lặp qua dedup_key
    assert len({p["dedup_key"] for p in world.pages}) == 1
    assert len(world.slack) == 2  # 1 thông báo + 1 thẻ điều tra
    assert len(lens.store.list_incidents()) == 1


async def test_pager_failure_falls_back_to_loud_slack(lens, world):
    world.fail_hosts.add("events.pagerduty.com")
    await lens.handle_alerts([make_alert(**CRIT)])
    assert "<!channel>" in world.slack[0]["text"]


async def test_broken_investigation_never_blocks_paging(lens, world):
    class Exploding:
        async def investigate(self, target):
            raise RuntimeError("boom")

    lens.investigator = Exploding()
    await lens.handle_alerts([make_alert(**CRIT)])
    await lens.drain()
    assert len(world.pages) == 1 and len(world.slack) == 1


async def test_slow_investigation_is_cut_off(lens, world):
    import asyncio

    class Slow:
        async def investigate(self, target):
            await asyncio.sleep(10)

    lens.investigator, lens._investigation_timeout = Slow(), 0.05
    await lens.handle_alerts([make_alert(**CRIT)])
    await lens.drain()
    assert len(world.pages) == 1 and len(world.slack) == 1


async def test_slack_text_from_alerts_is_escaped(lens, world):
    await lens.handle_alerts([make_alert(starts_at=START, summary="<!channel> <https://evil.example|bấm đây>")])
    assert "<!channel>" not in world.slack[0]["text"] and "&lt;!channel&gt;" in world.slack[0]["text"]


# ---------- Phản hồi, hành động, hồi phục, trí nhớ ----------


async def test_full_incident_lifecycle(tmp_path, clock):
    world = SimulatedWorld(START)
    actions = ActionsConfig(actions={"rollback": ActionSpec(
        label="🔄 Rollback", command=["kubectl", "rollout", "undo", "deployment/{service}"], approvers=["U1"])})
    lens = simulated_service(tmp_path, clock, world, actions=actions)

    await lens.handle_alerts([make_alert(**CRIT)])
    await lens.drain()

    # Kỹ sư xác nhận giả thuyết 1 → thành nguyên nhân của sự cố
    msg = await lens.handle_interaction("fb_1", "1:1", "U1", "alice", "https://hooks.slack.com/actions/x")
    assert msg.startswith("✅") and world.slack[-1]["text"] == msg
    assert "a1b2c3d" in lens.store.get_incident(1).root_cause

    # Người không có quyền bị từ chối; người có quyền thì chạy (ở đây là chế độ thử)
    denied = await lens.handle_interaction("act_rollback", "1:rollback", "U9", "mallory", None)
    assert denied.startswith("⛔")
    dry = await lens.handle_interaction("act_rollback", "1:rollback", "U1", "alice", None)
    assert dry.startswith("🧪") and "kubectl rollout undo deployment/auth-service" in dry
    log = lens.store.actions_for_incident(1)
    assert [(a.user, a.status) for a in log] == [("mallory (U9)", "denied"), ("alice (U1)", "dry-run")]
    assert lens.store.get_incident(1).fix is None  # chạy thử không được tính là đã sửa

    # Hồi phục → đóng sự cố, báo PagerDuty, viết postmortem
    clock.now = START + timedelta(minutes=31)
    await lens.handle_alerts([make_alert(status="resolved", starts_at=START, ends_at=clock.now)])
    await lens.drain()
    assert world.pages[-1]["event_action"] == "resolve"
    assert "Đã hồi phục" in world.slack[-1]["text"] and "31 phút" in world.slack[-1]["text"]
    incident = lens.store.get_incident(1)
    assert incident.duration_minutes == 31

    post = (tmp_path / "postmortems" / "INC-0001.md").read_text(encoding="utf-8")
    assert "Thời gian xử lý:** 31 phút" in post
    assert "xác nhận bởi alice" in post and "a1b2c3d" in post
    assert "mallory (U9) bấm hành động `rollback` → denied" in post
    assert post.index("— Sự cố bắt đầu") < post.index("— Gọi on-call") < post.index("— Hồi phục")

    # Một tuần sau cùng sự cố lặp lại → thẻ điều tra nhắc lại sự cố cũ
    world.incident_start = clock.now = START + timedelta(days=7)
    world.deploy_minutes_before = None
    await lens.handle_alerts([make_alert(starts_at=clock.now, summary="p95 latency 500ms")])
    await lens.drain()
    card = world.slack[-1]["text"]
    assert "INC-0002" in card and "Sự cố tương tự:* INC-0001" in card
    assert "Thời gian xử lý: 31 phút" in card


async def test_executed_action_becomes_the_fix(tmp_path, clock):
    import sys
    actions = ActionsConfig(actions={"restart": ActionSpec(
        label="♻️ Restart", command=[sys.executable, "-c", "print('restarted')"], approvers=["U1"])})
    lens = simulated_service(tmp_path, clock, SimulatedWorld(START), actions=actions, actions_enabled=True)
    await lens.handle_alerts([make_alert(**CRIT)])
    await lens.drain()
    msg = await lens.run_action(1, "restart", "U1", "alice")
    assert msg.startswith("✅")
    assert lens.store.get_incident(1).fix == "♻️ Restart (duyệt bởi alice)"
    assert lens.store.actions_for_incident(1)[0].output.strip() == "restarted"


async def test_bad_interactions_are_rejected_politely(lens):
    assert (await lens.handle_interaction("fb_1", "999:1", "U1", "a", None)).startswith("⚠️")
    assert (await lens.handle_interaction("fb_1", "abc", "U1", "a", None)).startswith("⚠️")
    assert (await lens.handle_interaction("act_x", "999:x", "U1", "a", None)).startswith("⚠️")
    assert await lens.handle_interaction("unknown", "1", "U1", "a", None) is None


async def test_feedback_down(lens):
    await lens.handle_alerts([make_alert(**CRIT)])
    await lens.drain()
    assert lens.record_feedback(1, 0, "bob").startswith("👎")
    rec = lens.store.get_investigation(1)
    assert rec.feedback == "down" and rec.feedback_by == "bob"
    assert lens.store.get_incident(1).root_cause is None


# ---------- 🟡 Digest và leo thang ----------


async def test_warning_is_not_paged_but_escalates_later(lens, world, clock):
    await lens.handle_alerts([make_alert(name="DiskSpaceLow", service="db-replica-02", severity="warning",
                                         starts_at=clock.now)])
    assert world.pages == [] and world.slack == []
    assert await lens.check_escalations() == []

    clock.now += timedelta(hours=5)
    assert await lens.check_escalations() == ["db-replica-02-DiskSpaceLow"]
    await lens.drain()
    assert world.pages[0]["payload"]["summary"].startswith("[Leo thang]")
    assert "Leo thang tự động" in world.slack[0]["text"]
    incident = lens.store.list_incidents()[0]
    assert incident.origin == "escalated"
    assert await lens.check_escalations() == []  # không gọi lại lần hai

    # Khi cảnh báo 🟡 đã leo thang hồi phục, PagerDuty cũng được báo
    await lens.handle_alerts([make_alert(name="DiskSpaceLow", service="db-replica-02", severity="warning",
                                         status="resolved", starts_at=incident.started_at, ends_at=clock.now)])
    assert world.pages[-1]["event_action"] == "resolve"


async def test_escalation_uses_real_start_time(lens, clock):
    old = make_alert(name="DiskSpaceLow", service="db-replica-02", severity="warning",
                     starts_at=clock.now - timedelta(hours=5))
    await lens.handle_alerts([old])
    assert await lens.check_escalations() == ["db-replica-02-DiskSpaceLow"]


async def test_digest_with_hypothesis(lens, world, clock, tmp_path):
    await lens.handle_alerts([
        make_alert(name="MemoryHigh", severity="warning", starts_at=START, summary="Bộ nhớ 85%"),
        make_alert(name="Timeout", service="payment-worker", severity="info", status="resolved",
                   starts_at=START, ends_at=START + timedelta(minutes=1)),
        make_alert(**CRIT),  # 🔴 không vào digest
    ])
    await lens.drain()
    world.slack.clear()
    clock.now += timedelta(hours=2)
    path = await lens.run_digest()
    text = path.read_text(encoding="utf-8")

    assert "2 sự cố" in text and "**Ưu tiên: #1**" in text
    assert "🟡 #1 MemoryHigh" in text and "Platform Team" in text
    assert "**Giả thuyết [Cao]:** Deploy `a1b2c3d`" in text and "Bằng chứng: [" in text
    assert "HighLatency" not in text
    assert "- [x] ⚪ #2 `payment-worker` Timeout" in text
    assert len(world.slack) == 1 and "Digest mới" in world.slack[0]["text"]  # điều tra trong digest không gửi thẻ


async def test_digest_window_survives_restart(tmp_path, clock, world):
    db = f"sqlite:///{tmp_path}/il.db"
    first = simulated_service(tmp_path / "a", clock, world, database_url=db)
    await first.handle_alerts([make_alert(name="A", severity="info", status="resolved", starts_at=START)])
    await first.run_digest()
    stamp = clock.now

    clock.now += timedelta(hours=4)
    second = simulated_service(tmp_path / "a", clock, world, database_url=db)  # "khởi động lại"
    await second.handle_alerts([make_alert(name="B", severity="info", status="resolved", starts_at=clock.now)])
    text = (await second.run_digest()).read_text(encoding="utf-8")
    assert f"{stamp:%H:%M}–{clock.now:%H:%M}" in text
    assert "`auth-service` B" in text and "`auth-service` A" not in text


async def test_resolved_alert_not_repeated_and_refire_is_new_episode(lens, clock):
    alert = make_alert(name="DiskSpaceLow", service="db-replica-02", severity="warning", starts_at=clock.now)
    await lens.handle_alerts([alert])
    await lens.handle_alerts([alert.model_copy(update={"status": "resolved"})])
    assert await lens.run_digest() is not None
    clock.now += timedelta(hours=4)
    assert await lens.run_digest() is None

    await lens.handle_alerts([alert.model_copy(update={"starts_at": clock.now})])
    record = lens.store.get("db-replica-02-DiskSpaceLow")
    assert record.first_seen == clock.now and record.receive_count == 1
    assert lens.store.count_episodes(START, clock.now + timedelta(minutes=1)) == 2


async def test_digest_investigation_budget(lens, clock):
    lens._digest_investigations = 1
    await lens.handle_alerts([make_alert(name=f"W{i}", severity="warning", starts_at=START) for i in range(3)])
    await lens.run_digest()
    assert len(lens.store.investigations_between(START, clock.now + timedelta(days=1))) == 1


async def test_noop_investigator_still_works(lens, world):
    lens.investigator = NoopInvestigator()
    await lens.handle_alerts([make_alert(**CRIT), make_alert(name="W", severity="warning", starts_at=START)])
    await lens.drain()
    assert len(world.slack) == 1
    assert await lens.run_digest() is not None


# ---------- Lưu trữ Git ----------


def git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, check=True).stdout


async def test_digest_is_committed_and_pushed(tmp_path, clock, world):
    remote, repo = tmp_path / "remote.git", tmp_path / "digests"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    git(repo, "remote", "add", "origin", str(remote))

    lens = simulated_service(repo, clock, world, git_push=True)
    await lens.handle_alerts([make_alert(name="W", severity="warning", starts_at=START)])
    await lens.run_digest()
    await lens.drain()

    assert "Digest 2026-11-12" in git(repo, "log", "--oneline")
    assert "digest-20261112-0216.md" in git(remote, "ls-tree", "-r", "--name-only", "HEAD")
    assert lens.archive.sync("không có gì mới") is False


async def test_git_problems_do_not_break_digest(tmp_path, clock, world):
    lens = simulated_service(tmp_path / "not-a-repo", clock, world, git_push=True)
    await lens.handle_alerts([make_alert(name="W", severity="warning", starts_at=START)])
    assert (await lens.run_digest()).exists()
    await lens.drain()


def test_investigation_model_caps_hypotheses():
    import pytest
    from pydantic import ValidationError
    from incidentlens.models import Hypothesis, InvestigationTarget
    t = InvestigationTarget(fingerprint="f", service="s", name="n", summary="x", started_at=START)
    h = Hypothesis(statement="x", confidence="low", evidence_ids=["E1"])
    with pytest.raises(ValidationError):
        Investigation(target=t, hypotheses=[h] * 4)
    with pytest.raises(ValidationError):
        Hypothesis(statement="x", confidence="low", evidence_ids=[])  # không có bằng chứng thì không hợp lệ
