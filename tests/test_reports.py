from datetime import datetime, timedelta, timezone
from pathlib import Path

from conftest import START
from incidentlens.reports.roi import Baseline, BaselineBefore, compute_roi, render_roi
from incidentlens.testing import SimulatedWorld, make_alert, simulated_service

NOV = datetime(2026, 11, 1, tzinfo=timezone.utc)


async def month_of_activity(lens, clock):
    """1 sự cố 🔴 (xử lý 30 phút, giả thuyết được xác nhận) + 3 cảnh báo 🟡 + 1 ⚪."""
    await lens.handle_alerts([make_alert(starts_at=START)])
    await lens.handle_alerts([make_alert(name=f"W{i}", severity="warning", starts_at=START) for i in range(3)])
    await lens.handle_alerts([make_alert(name="Noise", severity="info", starts_at=START)])
    await lens.handle_alerts([make_alert(starts_at=START)])  # gửi lại, không tính là đợt mới
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
    assert r.interruptions_before == 5 / 2 / 11 and r.interruptions_before_estimated
    assert r.mttr_now == 30 and r.mttr_before is None
    assert (r.feedback_up, r.feedback_total, r.accuracy) == (1, 1, 1.0)
    assert round(r.hours_saved, 2) == 0.33

    text = render_roi(r)
    assert "5 lần cảnh báo xảy ra, chỉ 1 lần phải gọi on-call" in text
    assert "| -80% |" in text and "100% (1/1 có đánh giá)" in text
    assert "Trước khi dùng (ước tính)" in text  # nói rõ đây là số ước tính


async def test_roi_with_measured_baseline(tmp_path, clock):
    baseline = Baseline(oncall_headcount=2, before=BaselineBefore(
        interruptions_per_person_per_day=1.0, mttr_minutes=60, critical_incidents_per_month=4))
    lens = simulated_service(tmp_path, clock, SimulatedWorld(START), baseline=baseline)
    await month_of_activity(lens, clock)
    text = render_roi(compute_roi(lens.store, baseline, NOV, clock.now))
    assert "| MTTR trung bình | 60 phút | 30 phút | -50% |" in text
    assert "| Sự cố phải gọi on-call | 4 | 1 | -75% |" in text
    assert "ước tính):** chưa có số đo thật" not in text


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
    assert any("Báo cáo tháng 11/2026" in m["text"] for m in world.slack)
    assert (await lens.run_maintenance())["roi_report"] is None  # chỉ phát hành một lần

    lens._retention = timedelta(days=10)
    purged = (await lens.run_maintenance())["purged"]
    assert purged["alerts"] == 1 and purged["episodes"] == 5
    assert lens.store.get("auth-service-Old") is None
    assert lens.store.get("auth-service-W0") is not None  # vẫn đang xảy ra nên được giữ
    assert lens.store.get_incident(1) is not None  # trí nhớ sự cố không bao giờ bị xóa
    assert lens.store.get_investigation(1) is not None


async def test_postmortem_for_unresolved_incident(lens):
    await lens.handle_alerts([make_alert(starts_at=START)])
    await lens.drain()
    text = lens.write_postmortem(1).read_text(encoding="utf-8")
    assert "chưa hồi phục" in text and "Chưa xác định" in text
    assert "### Giả thuyết của hệ thống" in text
