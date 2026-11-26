"""Core workflow orchestrator: connects routing, storage, paging, investigation, digests, actions, and reports."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from datetime import datetime, timedelta, timezone
import logging
from pathlib import Path
from typing import Any
from weakref import WeakValueDictionary

from incidentlens.actions.runner import ActionResult, ActionRunner
from incidentlens.catalog import ServiceCatalog
from incidentlens.changes.github import ChangeProvider, NoChanges
from incidentlens.digest.builder import group_alerts
from incidentlens.digest.render import render_digest
from incidentlens.investigation.base import Investigator, NoopInvestigator
from incidentlens.models import (
    Alert,
    AlertRecord,
    Change,
    DeliveryStatus,
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
        self._tasks: set[asyncio.Task[Any]] = set()
        self._alert_locks: WeakValueDictionary[str, asyncio.Lock] = WeakValueDictionary()
        self._service_locks: WeakValueDictionary[str, asyncio.Lock] = WeakValueDictionary()
        self._digest_lock = asyncio.Lock()

    def _spawn(self, coro: Coroutine[Any, Any, Any]) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def drain(self) -> None:
        """Await all in-flight background tasks (investigations and Git archive syncs)."""
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    # ---------- Alert ingestion ----------

    def _alert_lock(self, fingerprint: str) -> asyncio.Lock:
        return self._alert_locks.setdefault(fingerprint, asyncio.Lock())

    def _service_lock(self, service: str) -> asyncio.Lock:
        return self._service_locks.setdefault(service, asyncio.Lock())

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

    def _pager_configured(self) -> bool:
        return bool(getattr(self.pager, "configured", True))

    def _notifier_configured(self) -> bool:
        return bool(getattr(self.notifier, "configured", True))

    def _queue_open(
        self,
        incident: IncidentRecord,
        page: dict[str, Any],
        text: str,
        repeat: bool = False,
        created: bool = False,
    ) -> None:
        key = f"incident:{incident.id}:open"
        page["dedup_key"] = (
            f"{incident.fingerprint}:incident:{incident.id}" if created else self.store.pager_key(incident)
        )
        if self._pager_configured():
            self.store.queue_delivery(
                key + ":pager", incident.fingerprint, incident.id, "pager", "open", page, repeat=repeat
            )
        if self._notifier_configured():
            self.store.queue_delivery(key + ":slack", incident.fingerprint, incident.id, "slack", "open", {"text": text})

    def _queue_resolve(self, incident: IncidentRecord) -> None:
        if self._pager_configured():
            self.store.queue_delivery(
                f"incident:{incident.id}:resolve:pager",
                incident.fingerprint,
                incident.id,
                "pager",
                "resolve",
                {"dedup_key": self.store.pager_key(incident)},
            )

    async def _deliver_notifications(self, fingerprint: str) -> None:
        for delivery in self.store.pending_deliveries(fingerprint):
            payload = delivery["payload"]
            try:
                if delivery["channel"] == "pager":
                    sent = (
                        await self.pager.trigger(**payload)
                        if delivery["event"] == "open"
                        else await self.pager.resolve(payload["dedup_key"])
                    )
                else:
                    text = payload["text"]
                    if delivery["event"] == "open" and any(
                        d["channel"] == "pager" and d["event"] == "open"
                        for d in self.store.pending_deliveries(fingerprint)
                    ):
                        text = "<!channel> ⚠️ Could not reach PagerDuty — immediate human attention required!\n" + text
                    sent = await self.notifier.send(text)
                if sent or sent == DeliveryStatus.NOT_CONFIGURED:
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
        text = f"🔴 *{esc(alert.name)}* on `{esc(alert.service)}` · {incident.code}\n{esc(alert.summary)}"
        if alert.source_url:
            text += "\n" + link(alert.source_url, "View source")
        page: dict[str, Any] = dict(
            dedup_key=alert.fingerprint,
            summary=f"{alert.name} on {alert.service}: {alert.summary}",
            source=alert.service,
            details=alert.labels,
            link=alert.source_url,
        )
        self._queue_open(incident, page, text, repeat=True, created=created)
        if not self._pager_configured():
            await self.pager.trigger(**page)
        if not self._notifier_configured():
            await self.notifier.send(text)
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
        if not self._pager_configured():
            await self.pager.resolve(self.store.pager_key(incident))
        path = self.write_postmortem(incident.id, overwrite=False)
        text = (
            f"✅ Resolved: *{esc(incident.name)}* on `{esc(incident.service)}` · {incident.code} · "
            f"{incident.duration_minutes} minutes\nPostmortem draft: `{path}`"
        )
        if self._notifier_configured():
            self.store.queue_delivery(key + ":slack", alert.fingerprint, incident.id, "slack", "resolve", {"text": text})
        else:
            await self.notifier.send(text)
        await self._deliver_notifications(alert.fingerprint)
        self._spawn(asyncio.to_thread(self.archive.sync, f"Postmortem {incident.code}"))

    # ---------- Investigation & feedback ----------

    async def investigate(
        self,
        target: InvestigationTarget,
        incident: IncidentRecord | None = None,
        announce: bool = True,
    ) -> InvestigationRecord | None:
        try:
            result = await asyncio.wait_for(self.investigator.investigate(target), self._investigation_timeout)
        except Exception:
            # Investigation failures must never disrupt paging or alert ingestion.
            log.exception("Automated investigation failed for %s", target.fingerprint)
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
        """Record hypothesis feedback (choice=0: none correct; choice=n: nth hypothesis correct)."""
        record = self.store.get_investigation(investigation_id)
        if record is None:
            raise LookupError("Investigation not found")
        hypotheses = record.investigation.hypotheses
        if not 0 <= choice <= len(hypotheses):
            raise ValueError("Invalid hypothesis choice")
        if choice == 0:
            self.store.set_feedback(investigation_id, "down", None, user, self._clock())
            if record.incident_id:
                self.store.apply_hypothesis_feedback(record.incident_id, investigation_id, None)
            return "👎 Recorded: none of the hypotheses were correct. Thank you for the feedback."
        self.store.set_feedback(investigation_id, "up", choice, user, self._clock())
        if record.incident_id:
            self.store.apply_hypothesis_feedback(record.incident_id, investigation_id, hypotheses[choice - 1].statement)
        return f"✅ Recorded hypothesis {choice} as correct. Thank you!"

    # ---------- Human-approved actions ----------

    async def run_action(self, incident_id: int, action: str, user_id: str, user_name: str) -> str:
        incident = self.store.get_incident(incident_id)
        if incident is None:
            raise LookupError("Incident not found")
        async with self._service_lock(incident.service):
            incident = self.store.get_incident(incident_id)
            if incident is None:
                raise LookupError("Incident not found")
            now = self._clock()
            if incident.resolved_at is not None:
                result = ActionResult(
                    status="denied",
                    message="Incident is already resolved; actions are disabled",
                )
            elif (denied := self.actions.authorize(action, incident.service, user_id)) is not None:
                result = denied
            else:
                cooldown = timedelta(seconds=self.actions.cooldown_for(action))
                last = self.store.last_executed_action(incident.service)
                if cooldown > timedelta(0) and last is not None and (now - last.at) < cooldown:
                    remaining = max(1, int((cooldown - (now - last.at)).total_seconds()))
                    result = ActionResult(
                        status="denied",
                        message=f"Service `{incident.service}` is in cooldown after `{last.action}` ({remaining}s remaining)",
                    )
                else:
                    result = await self.actions.run(action, incident.service, user_id)
            self.store.log_action(
                self._clock(),
                incident_id,
                action,
                incident.service,
                f"{user_name} ({user_id})",
                result.status,
                result.exit_code,
                result.output,
            )
            if result.status == "executed":
                self.store.set_resolution(
                    incident_id,
                    fix=f"{self.actions.label(action)} (approved by {user_name})",
                    only_if_empty=True,
                )
        icon = {"executed": "✅", "dry-run": "🧪", "denied": "⛔", "failed": "❌"}[result.status]
        return f"{icon} {incident.code}: {result.message}"

    async def handle_interaction(
        self,
        action_id: str,
        value: str,
        user_id: str,
        user_name: str,
        response_url: str | None,
    ) -> str | None:
        """Process a Slack button interaction (after Slack HMAC verification at the HTTP layer)."""
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

    # ---------- Escalation ----------

    async def check_escalations(self) -> list[str]:
        await self.retry_notifications()
        escalated: list[str] = []
        for candidate in self.store.escalation_candidates():
            async with self._alert_lock(candidate.fingerprint):
                now = self._clock()
                record = self.store.get(candidate.fingerprint)
                if record is None:
                    continue
                reason = self.router.escalation_reason(record, now)
                if not reason:
                    continue
                incident, created = self.store.open_incident(record, "escalated", now)
                text = (
                    f"⬆️🔴 *Auto-escalated:* {esc(record.name)} on `{esc(record.service)}` · "
                    f"{incident.code} — {reason}"
                )
                page: dict[str, Any] = dict(
                    dedup_key=record.fingerprint,
                    summary=f"[Escalated] {record.name} on {record.service}: {reason}",
                    source=record.service,
                    details={"reason": reason, "first_seen": record.first_seen.isoformat()},
                    link=record.source_url,
                )
                self._queue_open(incident, page, text, created=created)
                self.store.mark_escalated(record.fingerprint, now)
                if not self._pager_configured():
                    await self.pager.trigger(**page)
                if not self._notifier_configured():
                    await self.notifier.send(text)
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
        window_start = (
            datetime.fromisoformat(last)
            if last
            else (min(r.first_seen for r in records) if records else now)
        )
        if not records:
            log.info("No pending alerts for digest")
            return None

        groups = group_alerts(records, self.catalog)
        cache: dict[str, list[Change]] = {}
        budget = self._digest_investigations
        for group in groups:
            if group.service not in cache:
                cache[group.service] = await self.changes.recent_changes(
                    group.service, group.first_seen - self._lookback
                )
            group.changes = cache[group.service]
            if budget > 0 and group.is_ongoing and group.severity is Severity.ACTION:
                budget -= 1
                result = await self.investigate(InvestigationTarget.from_record(group.records[0]), announce=False)
                group.investigation = result.investigation if result else None

        path = self.archive.write(render_digest(groups, window_start, now), now)
        self.store.mark_digest_snapshot(records)
        self.store.kv_set("last_digest_at", now.isoformat())
        ongoing = sum(1 for g in groups if g.is_ongoing)
        await self.notifier.send(f"📋 New digest: {len(groups)} group(s) ({ongoing} ongoing) · `{path}`")
        self._spawn(asyncio.to_thread(self.archive.sync, f"Digest {now:%Y-%m-%d %H:%M}"))
        return path

    # ---------- Postmortem, ROI, and maintenance ----------

    def _render_incident_postmortem(self, incident: IncidentRecord) -> str:
        return render_postmortem(
            incident,
            self.store.investigations_for_incident(incident.id),
            self.store.actions_for_incident(incident.id),
            self.catalog.get(incident.service).team,
        )

    def read_postmortem(self, incident_id: int) -> str:
        incident = self.store.get_incident(incident_id)
        if incident is None:
            raise LookupError("Incident not found")
        path = self.archive.root / f"postmortems/{incident.code}.md"
        if path.exists():
            return path.read_text(encoding="utf-8")
        return self._render_incident_postmortem(incident)

    def write_postmortem(self, incident_id: int, *, overwrite: bool = True) -> Path:
        incident = self.store.get_incident(incident_id)
        if incident is None:
            raise LookupError("Incident not found")
        relative = f"postmortems/{incident.code}.md"
        path = self.archive.root / relative
        if not overwrite and path.exists():
            return path
        return self.archive.write_named(relative, self._render_incident_postmortem(incident))

    async def publish_roi(self, month_start: datetime, announce: bool = True) -> tuple[Path, str]:
        report = compute_roi(self.store, self.baseline, month_start, self._clock())
        markdown = render_roi(report)
        path = self.archive.write_named(f"reports/roi-{month_start:%Y-%m}.md", markdown)
        if announce:
            accuracy = "unrated" if report.accuracy is None else f"{report.accuracy * 100:.0f}%"
            await self.notifier.send(
                f"📊 Monthly report {report.month}: {report.episodes} episodes → {report.interruptions} pages · "
                f"confirmed hypotheses {accuracy} · saved ~{report.hours_saved:.1f} hours · `{path}`"
            )
            self._spawn(asyncio.to_thread(self.archive.sync, f"ROI report {month_start:%Y-%m}"))
        return path, markdown

    async def run_maintenance(self) -> dict[str, Any]:
        """Run daily retention cleanup and publish the previous month's ROI report once."""
        now = self._clock()
        purged = self.store.purge(now - self._retention)
        previous = (now.replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)).replace(day=1)
        label = f"{previous:%Y-%m}"
        report: str | None = None
        if self.store.kv_get("last_roi_month") != label:
            end = (previous + timedelta(days=32)).replace(day=1)
            if self.store.count_episodes(previous, end) or self.store.incidents_between(previous, end):
                path, _ = await self.publish_roi(previous)
                report = str(path)
            self.store.kv_set("last_roi_month", label)
        return {"purged": purged, "roi_report": report}
