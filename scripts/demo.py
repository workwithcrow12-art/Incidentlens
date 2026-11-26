#!/usr/bin/env python3
"""Demo trọn vòng đời sự cố, không cần tài khoản hay hệ thống nào bên ngoài.

Chạy:  python scripts/demo.py

Prometheus, Loki, GitHub, Slack và PagerDuty được giả lập ở tầng HTTP; toàn bộ mã nguồn
của IncidentLens chạy thật. Kết quả (digest, postmortem, báo cáo) nằm trong thư mục demo-output/.
"""

import asyncio
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

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
        buttons = [e["text"]["text"] for b in message.get("blocks", []) if b["type"] == "actions"
                   for e in b["elements"]]
        if buttons:
            print("[Nút bấm] " + "  |  ".join(buttons))
    return len(world.slack)


async def main() -> None:
    shutil.rmtree(OUT, ignore_errors=True)
    clock = Clock(START + timedelta(minutes=2))
    world = SimulatedWorld(START)
    actions = ActionsConfig(actions={"rollback": ActionSpec(
        label="🔄 Rollback", approvers=["U_ALICE"],
        command=["kubectl", "rollout", "undo", "deployment/{service}", "-n", "production"])})
    baseline = Baseline(oncall_headcount=4, before=BaselineBefore(mttr_minutes=52))
    lens = simulated_service(OUT, clock, world, actions=actions, baseline=baseline)
    seen = 0

    step("1. 02:16 — Cảnh báo 🔴 tới, kèm 6 cảnh báo ít quan trọng hơn")
    noise = [make_alert(name=n, service=s, severity=sev, starts_at=START, summary=text)
             for n, s, sev, text in [
                 ("MemoryHigh", "auth-service", "warning", "Bộ nhớ pod đạt 85% giới hạn"),
                 ("DiskSpaceLow", "db-replica-02", "warning", "Disk đã dùng 85%"),
                 ("QueueGrowing", "payment-worker", "warning", "Hàng đợi tăng chậm"),
                 ("CertExpiresSoon", "payment-worker", "info", "Chứng chỉ hết hạn sau 20 ngày"),
                 ("StaleMetric", "user-db", "info", "Metric không cập nhật 10 phút"),
             ]]
    noise.append(make_alert(name="ThirdPartyTimeout", service="payment-worker", severity="info", status="resolved",
                            starts_at=START - timedelta(minutes=30), ends_at=START - timedelta(minutes=26),
                            summary="12 lỗi timeout tới API bên thứ ba"))
    counts = await lens.handle_alerts(
        [make_alert(starts_at=START, summary="p95 latency 450ms (bình thường 50ms)"), *noise])
    print(f"Đã nhận: {counts}")
    print(f"Số lần gọi PagerDuty: {len(world.pages)} (chỉ cảnh báo 🔴)")
    await lens.drain()
    seen = show_slack(world, seen)

    step("2. 02:20 — Mallory (không có quyền) rồi Alice (có quyền) bấm nút Rollback")
    clock.now = START + timedelta(minutes=6)
    print(await lens.handle_interaction("act_rollback", "1:rollback", "U_MALLORY", "mallory", None))
    print(await lens.handle_interaction("act_rollback", "1:rollback", "U_ALICE", "alice", None))

    step("3. 02:25 — Alice xác nhận giả thuyết 1 là đúng")
    clock.now = START + timedelta(minutes=11)
    print(await lens.handle_interaction("fb_1", "1:1", "U_ALICE", "alice", None))

    step("4. 02:45 — Sự cố hồi phục → bản nháp postmortem")
    clock.now = START + timedelta(minutes=31)
    await lens.handle_alerts([make_alert(status="resolved", starts_at=START, ends_at=clock.now)])
    await lens.drain()
    seen = show_slack(world, seen)
    print("\n" + (OUT / "postmortems" / "INC-0001.md").read_text(encoding="utf-8"))

    step("5. 06:14 — Digest định kỳ cho các cảnh báo 🟡⚪ (kèm giả thuyết cho mục đang xảy ra)")
    clock.now = START + timedelta(hours=4)
    path = await lens.run_digest()
    print(path.read_text(encoding="utf-8"))

    step("6. 06:20 — Cảnh báo 🟡 quá 4 giờ chưa hồi phục → tự leo thang lên 🔴")
    clock.now = START + timedelta(hours=4, minutes=6)
    print("Leo thang:", await lens.check_escalations())
    await lens.drain()
    seen = len(world.slack)  # bỏ qua phần in thẻ cho gọn

    step("7. Một tuần sau — cùng sự cố lặp lại → trí nhớ sự cố nhắc lại lần trước")
    world.incident_start = clock.now = START + timedelta(days=7)
    world.deploy_minutes_before = None
    await lens.handle_alerts([make_alert(starts_at=clock.now, summary="p95 latency 500ms")])
    await lens.drain()
    seen = show_slack(world, seen)

    step("8. Ngày 1 tháng sau — báo cáo ROI tự động")
    clock.now = datetime(2026, 12, 1, 6, 0, tzinfo=timezone.utc)
    result = await lens.run_maintenance()
    print(Path(result["roi_report"]).read_text(encoding="utf-8"))
    print(f"Các file đã tạo trong {OUT}/:")
    for file in sorted(p for p in OUT.rglob("*.md")):
        print("  ", file)


if __name__ == "__main__":
    asyncio.run(main())
