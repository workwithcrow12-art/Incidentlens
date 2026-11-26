"""Bộ điều phối: nối định tuyến, lưu trữ, gọi on-call, điều tra, digest, hành động và báo cáo."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from datetime import datetime, timedelta, timezone
from pathlib import Path
from weakref import WeakValueDictionary

from incidentlens.actions.runner import ActionRunner
from incidentlens.catalog import ServiceCatalog
from incidentlens.changes.github import ChangeProvider, NoChanges
from incidentlens.digest.builder import group_alerts
from incidentlens.digest.render import render_digest
from incidentlens.investigation.base import Investigator, NoopInvestigator
from incidentlens.models import (
    Alert,
    AlertRecord,
    Change,
    IncidentRecord,
    InvestigationRecord,
    InvestigationTarget,
    RoutedAlert,
    Severity,
)
from incidentlens.outputs.archive import DigestArchive
from incidentlens.outputs.cards import esc, investigation_card, link
from incidentlens.outputs.pagerduty import Pager
from incidentlens.outputs.slack import Notifier
from incidentlens.reports.postmortem import render_postmortem
from incidentlens.reports.roi import Baseline, compute_roi, render_roi
from incidentlens.routing.rules import Router
from incidentlens.store import Store

log = logging.getLogger(__name__)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IncidentLens:
    def __init__(
        self,
        *,
        router: Router,
        store: Store,
        catalog: ServiceCatalog,
        notifier: Notifier,
        pager: Pager,
        archive: DigestArchive,
        changes: ChangeProvider | None = None,
        investigator: Investigator | None = None,
        actions: ActionRunner | None = None,
        baseline: Baseline | None = None,
        change_lookback: timedelta = timedelta(hours=12),
        investigation_timeout: float = 240,
        digest_investigation_limit: int = 5,
        retention: timedelta = timedelta(days=180),
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.router = router
        self.store = store
        self.catalog = catalog
        self.notifier = notifier
        self.pager = pager
        self.archive = archive
        self.changes = changes or NoChanges()
        self.investigator = investigator or NoopInvestigator()
        self.actions = actions or ActionRunner()
        self.baseline = baseline or Baseline()
        self._lookback = change_lookback
        self._investigation_timeout = investigation_timeout
        self._digest_investigations = digest_investigation_limit
        self._retention = retention
        self._clock = clock
        self._tasks: set[asyncio.Task] = set()
        self._alert_locks = WeakValueDictionary()
        self._digest_lock = asyncio.Lock()

    def _spawn(self, coro: Coroutine) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def drain(self) -> None:
        """Chờ mọi việc nền (điều tra, đồng bộ Git) hoàn tất."""
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    # ---------- Nhận cảnh báo ----------

    def _alert_lock(self, fingerprint: str) -> asyncio.Lock:
        return self._alert_locks.setdefault(fingerprint, asyncio.Lock())

    async def handle_alerts(self, alerts: list[Alert]) -> dict[str, int]:
        counts = {"received": len(alerts), "critical": 0, "action": 0, "info": 0}
        for alert in alerts:
            async with self._alert_lock(alert.fingerprint):
                now = self._clock()
                routed = self.router.classify(alert)
                counts[routed.severity.value] += 1
                previous = self.store.get(alert.fingerprint)
                record = self.store.record(routed, now)
                if record is None:
                    continue
                if previous and record.first_seen > previous.first_seen:
                    # Keep old resolves: their PagerDuty keys belong to separate incidents.
                    self.store.cancel_deliveries(alert.fingerprint, "open")
                    old = self.store.close_incident(alert.fingerprint, record.first_seen)
                    if old:
                        self._queue_resolve(old)
                if alert.status == "firing" and record.receive_count == 1:
                    self.store.log_episode(record, now)
                if alert.status == "resolved":
                    await self._handle_resolved(routed, now)
                elif routed.severity is Severity.CRITICAL:
                    await self._handle_critical(routed, record, now)
        return counts

    def _queue_open(self, incident: IncidentRecord, page: dict, text: str,
                    repeat: bool = False, created: bool = False) -> None:
        key = f"incident:{incident.id}:open"
        page["dedup_key"] = (f"{incident.fingerprint}:incident:{incident.id}" if created
                             else self.store.pager_key(incident))
        self.store.queue_delivery(key + ":pager", incident.fingerprint, incident.id,
                                  "pager", "open", page, repeat=repeat)
        self.store.queue_delivery(key + ":slack", incident.fingerprint, incident.id,
                                  "slack", "open", {"text": text})

    def _queue_resolve(self, incident: IncidentRecord) -> None:
        self.store.queue_delivery(f"incident:{incident.id}:resolve:pager", incident.fingerprint, incident.id,
                                  "pager", "resolve", {"dedup_key": self.store.pager_key(incident)})

    async def _deliver_notifications(self, fingerprint: str) -> None:
        for delivery in self.store.pending_deliveries(fingerprint):
            payload = delivery["payload"]
            try:
                if delivery["channel"] == "pager":
                    sent = (await self.pager.trigger(**payload) if delivery["event"] == "open"
                            else await self.pager.resolve(payload["dedup_key"]))
                else:
                    text = payload["text"]
                    if delivery["event"] == "open" and any(
                        d["channel"] == "pager" and d["event"] == "open"
                        for d in self.store.pending_deliveries(fingerprint)
                    ):
                        text = "<!channel> ⚠️ Không gọi được PagerDuty — cần người nhận xử lý ngay!\n" + text
                    sent = await self.notifier.send(text)
                if sent:
                    self.store.finish_delivery(delivery["key"])
            except Exception:
                log.exception("Notification delivery failed: %s", delivery["key"])

    async def retry_notifications(self) -> None:
        fingerprints = dict.fromkeys(d["fingerprint"] for d in self.store.pending_deliveries())
        for fingerprint in fingerprints:
            async with self._alert_lock(fingerprint):
                await self._deliver_notifications(fingerprint)

    async def _handle_critical(self, routed: RoutedAlert, record: AlertRecord, now: datetime) -> None:
        alert = routed.alert
        incident, created = self.store.open_incident(record, "critical", now)
        text = f"🔴 *{esc(alert.name)}* trên `{esc(alert.service)}` · {incident.code}\n{esc(alert.summary)}"
        if alert.source_url:
            text += "\n" + link(alert.source_url, "Xem nguồn")
        self._queue_open(incident, dict(
            dedup_key=alert.fingerprint, summary=f"{alert.name} trên {alert.service}: {alert.summary}",
            source=alert.service, details=alert.labels, link=alert.source_url), text, repeat=True, created=created)
        await self._deliver_notifications(alert.fingerprint)
        if created:
            self._spawn(self.investigate(InvestigationTarget.from_record(record), incident))

    async def _handle_resolved(self, routed: RoutedAlert, now: datetime) -> None:
        alert = routed.alert
        incident = self.store.close_incident(alert.fingerprint, alert.ends_at or now)
        self.store.cancel_deliveries(alert.fingerprint, "open")
        if incident is None:
            incident = self.store.episode_incident(alert.fingerprint, min(alert.starts_at, now))
        if incident is None:
            # Existing queued resolves are retried even for escalated warning alerts.
            if routed.severity is Severity.CRITICAL and not self.store.pending_deliveries(alert.fingerprint):
                await self.pager.resolve(alert.fingerprint)
            await self._deliver_notifications(alert.fingerprint)
            return
        key = f"incident:{incident.id}:resolve"
        self._queue_resolve(incident)
        path = self.write_postmortem(incident.id)
        text = (f"✅ Đã hồi phục: *{esc(incident.name)}* trên `{esc(incident.service)}` · {incident.code} · "
                f"{incident.duration_minutes} phút\nBản nháp postmortem: `{path}`")
        self.store.queue_delivery(key + ":slack", alert.fingerprint, incident.id,
                                  "slack", "resolve", {"text": text})
        await self._deliver_notifications(alert.fingerprint)
        self._spawn(asyncio.to_thread(self.archive.sync, f"Postmortem {incident.code}"))

    # ---------- Điều tra ----------

    async def investigate(self, target: InvestigationTarget, incident: IncidentRecord | None = None,
                          announce: bool = True) -> InvestigationRecord | None:
        try:
            result = await asyncio.wait_for(self.investigator.investigate(target), self._investigation_timeout)
        except Exception:
            # Điều tra thất bại không bao giờ được ảnh hưởng tới việc gọi on-call
            log.exception("Điều tra tự động thất bại cho %s", target.fingerprint)
            return None
        if result is None:
            return None
        record = self.store.save_investigation(result, incident.id if incident else None, self._clock())
        if announce:
            actions = self.actions.available_for(target.service) if incident else []
            text, blocks = investigation_card(record, incident, actions, self.catalog.get(target.service).runbook)
            await self.notifier.send(text, blocks)
        return record

    def record_feedback(self, investigation_id: int, choice: int, user: str) -> str:
        """choice = 0: không giả thuyết nào đúng; choice = n: giả thuyết thứ n đúng."""
        record = self.store.get_investigation(investigation_id)
        if record is None:
            raise LookupError("Không tìm thấy cuộc điều tra")
        hypotheses = record.investigation.hypotheses
        if not 0 <= choice <= len(hypotheses):
            raise ValueError("Lựa chọn không hợp lệ")
        if choice == 0:
            self.store.set_feedback(investigation_id, "down", None, user, self._clock())
            return "👎 Đã ghi nhận: không giả thuyết nào đúng. Cảm ơn bạn, phản hồi này giúp hệ thống cải thiện."
        self.store.set_feedback(investigation_id, "up", choice, user, self._clock())
        if record.incident_id:
            # Giả thuyết được xác nhận trở thành nguyên nhân của sự cố → đi vào trí nhớ sự cố
            self.store.set_resolution(record.incident_id, root_cause=hypotheses[choice - 1].statement)
        return f"✅ Đã ghi nhận giả thuyết {choice} là đúng. Cảm ơn bạn!"

    # ---------- Hành động có người duyệt ----------

    async def run_action(self, incident_id: int, action: str, user_id: str, user_name: str) -> str:
        incident = self.store.get_incident(incident_id)
        if incident is None:
            raise LookupError("Không tìm thấy sự cố")
        result = await self.actions.run(action, incident.service, user_id)
        self.store.log_action(self._clock(), incident_id, action, incident.service, f"{user_name} ({user_id})",
                              result.status, result.exit_code, result.output)
        if result.status == "executed":
            self.store.set_resolution(incident_id, fix=f"{self.actions.label(action)} (duyệt bởi {user_name})",
                                      only_if_empty=True)
        icon = {"executed": "✅", "dry-run": "🧪", "denied": "⛔", "failed": "❌"}[result.status]
        return f"{icon} {incident.code}: {result.message}"

    async def handle_interaction(self, action_id: str, value: str, user_id: str, user_name: str,
                                 response_url: str | None) -> str | None:
        """Xử lý một lần bấm nút trên Slack (đã xác thực chữ ký ở lớp web)."""
        try:
            if action_id.startswith("fb_"):
                investigation_id, choice = value.split(":")
                message = self.record_feedback(int(investigation_id), int(choice), user_name)
            elif action_id.startswith("act_"):
                incident_id, name = value.split(":", 1)
                message = await self.run_action(int(incident_id), name, user_id, user_name)
            else:
                return None
        except (ValueError, LookupError) as exc:
            message = f"⚠️ {exc}"
        await self.notifier.respond(response_url, message)
        return message

    # ---------- Leo thang ----------

    async def check_escalations(self) -> list[str]:
        await self.retry_notifications()
        escalated = []
        for candidate in self.store.escalation_candidates():
            async with self._alert_lock(candidate.fingerprint):
                now = self._clock()
                record = self.store.get(candidate.fingerprint)
                reason = self.router.escalation_reason(record, now) if record else None
                if not reason:
                    continue
                incident, created = self.store.open_incident(record, "escalated", now)
                text = (f"⬆️🔴 *Leo thang tự động:* {esc(record.name)} trên `{esc(record.service)}` · "
                        f"{incident.code} — {reason}")
                self._queue_open(incident, dict(
                    dedup_key=record.fingerprint,
                    summary=f"[Leo thang] {record.name} trên {record.service}: {reason}",
                    source=record.service,
                    details={"reason": reason, "first_seen": record.first_seen.isoformat()},
                    link=record.source_url), text, created=created)
                self.store.mark_escalated(record.fingerprint, now)
                await self._deliver_notifications(record.fingerprint)
                if created:
                    self._spawn(self.investigate(InvestigationTarget.from_record(record), incident))
                escalated.append(record.fingerprint)
        return escalated

    # ---------- Digest ----------

    async def run_digest(self) -> Path | None:
        async with self._digest_lock:
            return await self._run_digest()

    async def _run_digest(self) -> Path | None:
        now = self._clock()
        records = self.store.pending_for_digest()
        last = self.store.kv_get("last_digest_at")
        window_start = datetime.fromisoformat(last) if last else (
            min(r.first_seen for r in records) if records else now)
        if not records:
            log.info("Không có cảnh báo nào cho digest")
            return None

        groups = group_alerts(records, self.catalog)
        cache: dict[str, list[Change]] = {}
        budget = self._digest_investigations
        for group in groups:
            if group.service not in cache:
                cache[group.service] = await self.changes.recent_changes(
                    group.service, group.first_seen - self._lookback)
            group.changes = cache[group.service]
            if budget > 0 and group.is_ongoing and group.severity is Severity.ACTION:
                budget -= 1
                result = await self.investigate(InvestigationTarget.from_record(group.records[0]), announce=False)
                group.investigation = result.investigation if result else None

        path = self.archive.write(render_digest(groups, window_start, now), now)
        self.store.mark_digest_snapshot(records)
        self.store.kv_set("last_digest_at", now.isoformat())
        ongoing = sum(1 for g in groups if g.is_ongoing)
        await self.notifier.send(f"📋 Digest mới: {len(groups)} mục ({ongoing} đang xảy ra) · `{path}`")
        self._spawn(asyncio.to_thread(self.archive.sync, f"Digest {now:%Y-%m-%d %H:%M}"))
        return path

    # ---------- Postmortem, báo cáo, bảo trì ----------

    def write_postmortem(self, incident_id: int) -> Path:
        incident = self.store.get_incident(incident_id)
        if incident is None:
            raise LookupError("Không tìm thấy sự cố")
        markdown = render_postmortem(
            incident, self.store.investigations_for_incident(incident_id),
            self.store.actions_for_incident(incident_id), self.catalog.get(incident.service).team)
        return self.archive.write_named(f"postmortems/{incident.code}.md", markdown)

    async def publish_roi(self, month_start: datetime, announce: bool = True) -> tuple[Path, str]:
        report = compute_roi(self.store, self.baseline, month_start, self._clock())
        markdown = render_roi(report)
        path = self.archive.write_named(f"reports/roi-{month_start:%Y-%m}.md", markdown)
        if announce:
            accuracy = "chưa có đánh giá" if report.accuracy is None else f"{report.accuracy * 100:.0f}%"
            await self.notifier.send(
                f"📊 Báo cáo tháng {report.month}: {report.episodes} cảnh báo → {report.interruptions} lần gọi on-call · "
                f"giả thuyết đúng {accuracy} · tiết kiệm ~{report.hours_saved:.1f} giờ · `{path}`")
            self._spawn(asyncio.to_thread(self.archive.sync, f"Báo cáo ROI {month_start:%Y-%m}"))
        return path, markdown

    async def run_maintenance(self) -> dict:
        """Chạy hằng ngày: dọn dữ liệu cũ và phát hành báo cáo ROI của tháng trước (một lần)."""
        now = self._clock()
        purged = self.store.purge(now - self._retention)
        previous = (now.replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)).replace(day=1)
        label = f"{previous:%Y-%m}"
        report = None
        if self.store.kv_get("last_roi_month") != label:
            end = (previous + timedelta(days=32)).replace(day=1)
            if self.store.count_episodes(previous, end) or self.store.incidents_between(previous, end):
                path, _ = await self.publish_roi(previous)
                report = str(path)
            self.store.kv_set("last_roi_month", label)
        return {"purged": purged, "roi_report": report}
