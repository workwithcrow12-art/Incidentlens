"""AI Investigation Engine.

Thiết kế hai lớp để vừa đáng tin vừa kiểm thử được:

1. THU THẬP bằng chứng bằng mã cố định (chỉ đọc): metric, log, deploy, dịch vụ phụ thuộc, sự cố cũ.
   Mỗi bằng chứng bắt buộc có link về dữ liệu gốc.
2. SUY LUẬN: luật cố định tạo giả thuyết nháp; nếu có cấu hình LLM thì LLM viết lại cho rõ,
   nhưng chỉ được trích dẫn bằng chứng đã thu thập. Giả thuyết không có bằng chứng bị loại.
   Mức tin cậy luôn do mã nguồn tính, không lấy từ LLM.

Nếu LLM lỗi hoặc không được cấu hình, hệ thống vẫn chạy bằng luật.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from incidentlens.catalog import ServiceCatalog
from incidentlens.changes.github import ChangeProvider
from incidentlens.investigation.base import confidence_for
from incidentlens.investigation.loki import LokiClient, top_patterns
from incidentlens.investigation.prometheus import PrometheusClient
from incidentlens.investigation.signals import SignalConfig, compare, fmt
from incidentlens.memory.similarity import IncidentMemory
from incidentlens.models import Evidence, Hypothesis, Investigation, InvestigationTarget, Severity, SimilarIncident
from incidentlens.redact import is_safe_name, redact
from incidentlens.store import Store

log = logging.getLogger(__name__)

_RANK = {"high": 0, "medium": 1, "low": 2}


@dataclass
class Finding:
    """Bằng chứng thô kèm dữ liệu có cấu trúc để luật suy luận dùng."""

    kind: str
    description: str
    url: str
    meta: dict = field(default_factory=dict)
    id: str = ""


def _hypothesis(statement: str, findings: list[Finding]) -> Hypothesis:
    return Hypothesis(statement=statement, confidence=confidence_for({f.kind for f in findings}),
                      evidence_ids=[f.id for f in findings])


def rule_hypotheses(target: InvestigationTarget, findings: list[Finding]) -> list[Hypothesis]:
    """Tạo giả thuyết bằng luật cố định. Không có bằng chứng thì không có giả thuyết."""
    by_kind: dict[str, list[Finding]] = {}
    for f in findings:
        by_kind.setdefault(f.kind, []).append(f)
    direct = by_kind.get("metric", []) + by_kind.get("log", [])
    hypotheses: list[Hypothesis] = []

    # 1. Deploy gần nhất trước khi sự cố bắt đầu
    deploys = sorted((f for f in by_kind.get("change", []) if f.meta["created_at"] <= target.started_at),
                     key=lambda f: f.meta["created_at"], reverse=True)
    if deploys:
        d = deploys[0]
        minutes = int((target.started_at - d.meta["created_at"]).total_seconds() // 60)
        timing = f"sự cố bắt đầu {minutes} phút sau deploy" if minutes > 0 else "sự cố bắt đầu gần như cùng lúc với deploy"
        who = f" của {d.meta['author']}" if d.meta.get("author") else ""
        caveat = "" if direct else " (mới chỉ trùng thời điểm, chưa có bằng chứng trực tiếp)"
        hypotheses.append(_hypothesis(
            f"Deploy `{d.meta['ref']}`{who} lúc {d.meta['created_at']:%H:%M} UTC có thể là nguyên nhân: {timing}{caveat}",
            [d, *direct]))

    # 2. Sự cố lan từ dịch vụ phụ thuộc
    by_dep: dict[str, list[Finding]] = {}
    for f in by_kind.get("dependency", []):
        by_dep.setdefault(f.meta["service"], []).append(f)
    for dep, items in by_dep.items():
        names = ", ".join(sorted({f.meta["name"] for f in items}))
        hypotheses.append(_hypothesis(
            f"Sự cố có thể lan từ dịch vụ phụ thuộc `{dep}`, nơi đang có cảnh báo {names}", items))

    # 3. Cạn tài nguyên
    saturated = [f for f in by_kind.get("metric", []) if f.meta.get("category") in ("saturation", "restarts")]
    if saturated:
        titles = ", ".join(f.meta["title"] for f in saturated)
        hypotheses.append(_hypothesis(
            f"Tài nguyên của `{target.service}` bị quá tải hoặc không ổn định: {titles}",
            [*saturated, *by_kind.get("log", [])]))

    # 4. Lặp lại sự cố cũ đã biết nguyên nhân
    for f in by_kind.get("memory", []):
        if f.meta.get("root_cause"):
            hypotheses.append(_hypothesis(
                f"Có thể lặp lại {f.meta['code']}, khi đó nguyên nhân là: {f.meta['root_cause']}", [f]))
            break

    hypotheses.sort(key=lambda h: _RANK[h.confidence])
    return hypotheses[:3]


class EvidenceEngine:
    def __init__(
        self,
        *,
        store: Store,
        catalog: ServiceCatalog,
        changes: ChangeProvider,
        memory: IncidentMemory,
        signals: SignalConfig | None = None,
        prometheus: PrometheusClient | None = None,
        loki: LokiClient | None = None,
        synthesizer=None,
        public_url: str = "http://localhost:8000",
        change_window: timedelta = timedelta(hours=2),
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._store = store
        self._catalog = catalog
        self._changes = changes
        self._memory = memory
        self._signals = signals or SignalConfig()
        self._prometheus = prometheus
        self._loki = loki
        self._synthesizer = synthesizer
        self._public_url = public_url.rstrip("/")
        self._change_window = change_window
        self._clock = clock

    async def investigate(self, target: InvestigationTarget) -> Investigation:
        t0 = time.monotonic()
        now = self._clock()
        collected = await asyncio.gather(
            self._metrics(target, now), self._logs(target, now), self._deploys(target),
            return_exceptions=True,
        )
        findings: list[Finding] = []
        for name, result in zip(("metric", "log", "deploy"), collected):
            if isinstance(result, BaseException):
                # Một nguồn lỗi không được làm hỏng cả cuộc điều tra
                log.warning("Không thu thập được bằng chứng %s cho %s: %r", name, target.service, result)
            else:
                findings.extend(result)
        findings.extend(self._dependencies(target))
        similar = self._memory.find_similar(target)
        findings.extend(self._memory_findings(similar))
        for n, f in enumerate(findings, 1):
            f.id = f"E{n}"

        evidence = [Evidence(id=f.id, kind=f.kind, description=f.description, url=f.url) for f in findings]
        hypotheses, engine = rule_hypotheses(target, findings), "rules"
        if self._synthesizer and evidence:
            refined = await self._synthesizer.refine(target, evidence, hypotheses)
            if refined:
                hypotheses, engine = refined, "llm"

        return Investigation(target=target, hypotheses=hypotheses, evidence=evidence, similar=similar,
                             engine=engine, duration_seconds=round(time.monotonic() - t0, 3))

    # ---------- Thu thập bằng chứng ----------

    def _windows(self, target: InvestigationTarget, now: datetime):
        guard = timedelta(minutes=self._signals.guard_minutes)
        base_end = target.started_at - guard - timedelta(minutes=10)
        base_start = base_end - timedelta(minutes=self._signals.baseline_minutes)
        cur_start = max(target.started_at - guard, now - timedelta(minutes=60))
        if cur_start >= now:
            cur_start = now - timedelta(minutes=5)
        return base_start, base_end, cur_start

    async def _metrics(self, target: InvestigationTarget, now: datetime) -> list[Finding]:
        if not self._prometheus or not self._signals.signals or not is_safe_name(target.service):
            return []
        base_start, base_end, cur_start = self._windows(target, now)

        async def check(signal) -> Finding | None:
            query = signal.query.replace("{service}", target.service)
            base, cur = await asyncio.gather(
                self._prometheus.query_range(query, base_start, base_end),
                self._prometheus.query_range(query, cur_start, now),
            )
            anomaly = compare(signal, base, cur)
            if anomaly is None:
                return None
            ratio = f" (×{anomaly.ratio:.1f})" if anomaly.ratio and signal.direction == "up" else ""
            return Finding(
                "metric",
                f"{signal.title}: {fmt(anomaly.baseline, signal.unit)} → {fmt(anomaly.current, signal.unit)}{ratio}",
                self._prometheus.graph_url(query, now),
                {"category": signal.category, "title": signal.title},
            )

        results = await asyncio.gather(*(check(s) for s in self._signals.signals), return_exceptions=True)
        findings = []
        for signal, result in zip(self._signals.signals, results):
            if isinstance(result, BaseException):
                log.warning("Tín hiệu %s lỗi: %r", signal.name, result)
            elif result is not None:
                findings.append(result)
        return findings

    async def _logs(self, target: InvestigationTarget, now: datetime) -> list[Finding]:
        cfg = self._signals.logs
        if not self._loki or not cfg or not is_safe_name(target.service):
            return []
        query = cfg.query.replace("{service}", target.service)
        guard = self._signals.guard_minutes * 60
        window = max(300, min(3600, int((now - target.started_at).total_seconds()) + guard))
        before_at = target.started_at - timedelta(seconds=guard + 600)
        current, before = await asyncio.gather(
            self._loki.count(query, now, window), self._loki.count(query, before_at, window))
        if current < cfg.min_lines or current < 2 * before:
            return []
        start = now - timedelta(seconds=window)
        patterns = top_patterns(await self._loki.lines(query, start, now))
        text = f"{current} dòng log lỗi trong {window // 60} phút gần nhất (cùng khoảng thời gian trước sự cố: {before})"
        if patterns:
            text += ". Phổ biến nhất: " + "; ".join(f"“{p}” ×{n}" for p, n in patterns)
        return [Finding("log", text, self._loki.explore_url(query, start, now))]

    async def _deploys(self, target: InvestigationTarget) -> list[Finding]:
        since = target.started_at - self._change_window
        findings = []
        for ch in await self._changes.recent_changes(target.service, since):
            if not ch.url or ch.created_at > target.started_at:
                continue
            who = f" bởi {ch.author}" if ch.author else ""
            findings.append(Finding(
                "change", f"{ch.kind} `{ch.ref}`{who} lúc {ch.created_at:%H:%M} UTC", ch.url,
                {"ref": ch.ref, "author": ch.author, "created_at": ch.created_at}))
        return findings

    def _dependencies(self, target: InvestigationTarget) -> list[Finding]:
        findings = []
        for dep in self._catalog.get(target.service).depends_on:
            for alert in self._store.firing_alerts(dep):
                # Cảnh báo ⚪ thông tin trên dịch vụ phụ thuộc không đủ nặng để coi là bằng chứng lan truyền
                if alert.fingerprint == target.fingerprint or alert.severity is Severity.INFO:
                    continue
                url = alert.source_url or f"{self._public_url}/alerts/{alert.fingerprint}"
                findings.append(Finding(
                    "dependency",
                    f"`{dep}` đang có cảnh báo {alert.name} từ {alert.first_seen:%H:%M} UTC: {redact(alert.summary)}",
                    url, {"service": dep, "name": alert.name}))
        return findings

    def _memory_findings(self, similar: list[SimilarIncident]) -> list[Finding]:
        findings = []
        for s in similar:
            cause = f" Nguyên nhân khi đó: {s.root_cause}." if s.root_cause else ""
            fix = f" Đã sửa bằng: {s.fix}." if s.fix else ""
            findings.append(Finding(
                "memory", f"{s.code} ({s.name} trên `{s.service}`) tương tự sự cố này.{cause}{fix}",
                f"{self._public_url}/incidents/{s.incident_id}/postmortem",
                {"code": s.code, "root_cause": s.root_cause}))
        return findings
