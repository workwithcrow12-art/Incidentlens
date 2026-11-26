"""Two-layer incident investigation engine.

1. DETERMINISTIC COLLECTION (read-only): metrics, logs, deployments, dependency alerts, and
   similar closed incidents. Every piece of evidence carries a link to the primary data source.
2. SYNTHESIS: deterministic rules build draft hypotheses; when an LLM is configured, it may
   rewrite hypotheses for clarity using only collected evidence IDs. Uncited claims are dropped,
   confidence is always computed by code, and any LLM error falls back to the rule hypotheses.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import logging
import time
from typing import Any

from incidentlens.catalog import ServiceCatalog
from incidentlens.changes.github import ChangeProvider
from incidentlens.investigation.base import confidence_for
from incidentlens.investigation.llm import Synthesizer
from incidentlens.investigation.loki import LokiClient, top_patterns
from incidentlens.investigation.prometheus import PrometheusClient
from incidentlens.investigation.signals import Signal, SignalConfig, compare, fmt
from incidentlens.memory.similarity import IncidentMemory
from incidentlens.models import (
    Confidence,
    Evidence,
    EvidenceKind,
    Hypothesis,
    Investigation,
    InvestigationTarget,
    Severity,
    SimilarIncident,
)
from incidentlens.redact import is_safe_name, redact
from incidentlens.store import Store

log = logging.getLogger(__name__)

_RANK: dict[Confidence, int] = {"high": 0, "medium": 1, "low": 2}


@dataclass
class Finding:
    """Raw evidence item paired with structured metadata for rule-based reasoning."""

    kind: EvidenceKind
    description: str
    url: str
    meta: dict[str, Any] = field(default_factory=dict)
    id: str = ""


def _hypothesis(statement: str, findings: list[Finding]) -> Hypothesis:
    return Hypothesis(
        statement=statement,
        confidence=confidence_for({f.kind for f in findings}),
        evidence_ids=[f.id for f in findings],
    )


def rule_hypotheses(target: InvestigationTarget, findings: list[Finding]) -> list[Hypothesis]:
    """Generate hypotheses via deterministic rules. Returns an empty list when evidence is absent."""
    by_kind: dict[EvidenceKind, list[Finding]] = {}
    for f in findings:
        by_kind.setdefault(f.kind, []).append(f)
    direct = by_kind.get("metric", []) + by_kind.get("log", [])
    hypotheses: list[Hypothesis] = []

    # 1. Most recent deployment at or before incident onset
    deploys = sorted(
        (f for f in by_kind.get("change", []) if f.meta["created_at"] <= target.started_at),
        key=lambda f: f.meta["created_at"],
        reverse=True,
    )
    if deploys:
        d = deploys[0]
        minutes = int((target.started_at - d.meta["created_at"]).total_seconds() // 60)
        timing = (
            f"incident started {minutes} minutes after deploy"
            if minutes > 0
            else "incident started right around deploy time"
        )
        who = f" by {d.meta['author']}" if d.meta.get("author") else ""
        caveat = "" if direct else " (timing correlation only; no direct behavioral evidence yet)"
        hypotheses.append(
            _hypothesis(
                f"Deploy `{d.meta['ref']}`{who} at {d.meta['created_at']:%H:%M} UTC may be the cause: {timing}{caveat}",
                [d, *direct],
            )
        )

    # 2. Failure cascading from an upstream/downstream dependency
    by_dep: dict[str, list[Finding]] = {}
    for f in by_kind.get("dependency", []):
        by_dep.setdefault(f.meta["service"], []).append(f)
    for dep, items in by_dep.items():
        names = ", ".join(sorted({f.meta["name"] for f in items}))
        hypotheses.append(
            _hypothesis(
                f"Issue may be cascading from dependency `{dep}`, which has active alert(s) {names}",
                items,
            )
        )

    # 3. Resource saturation or instability
    saturated = [f for f in by_kind.get("metric", []) if f.meta.get("category") in ("saturation", "restarts")]
    if saturated:
        titles = ", ".join(f.meta["title"] for f in saturated)
        hypotheses.append(
            _hypothesis(
                f"Resources on `{target.service}` are saturated or unstable: {titles}",
                [*saturated, *by_kind.get("log", [])],
            )
        )

    # 4. Recurrence of a past incident with a known root cause
    for f in by_kind.get("memory", []):
        if f.meta.get("root_cause"):
            hypotheses.append(
                _hypothesis(
                    f"May be a recurrence of {f.meta['code']}, whose root cause was: {f.meta['root_cause']}",
                    [f],
                )
            )
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
        synthesizer: Synthesizer | None = None,
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
            self._metrics(target, now),
            self._logs(target, now),
            self._deploys(target),
            return_exceptions=True,
        )
        findings: list[Finding] = []
        for name, result in zip(("metric", "log", "deploy"), collected):
            if isinstance(result, BaseException):
                # A single failing evidence collector must never abort the investigation.
                log.warning("Failed to collect %s evidence for %s: %r", name, target.service, result)
            else:
                findings.extend(result)
        findings.extend(self._dependencies(target))
        similar = self._memory.find_similar(target)
        findings.extend(self._memory_findings(similar))
        for n, f in enumerate(findings, 1):
            f.id = f"E{n}"

        evidence = [Evidence(id=f.id, kind=f.kind, description=f.description, url=f.url) for f in findings]
        hypotheses: list[Hypothesis] = rule_hypotheses(target, findings)
        engine: str = "rules"
        if self._synthesizer and evidence:
            refined = await self._synthesizer.refine(target, evidence, hypotheses)
            if refined:
                hypotheses, engine = refined, "llm"

        return Investigation(
            target=target,
            hypotheses=hypotheses,
            evidence=evidence,
            similar=similar,
            engine="llm" if engine == "llm" else "rules",
            duration_seconds=round(time.monotonic() - t0, 3),
        )

    # ---------- Evidence collectors ----------

    def _windows(self, target: InvestigationTarget, now: datetime) -> tuple[datetime, datetime, datetime]:
        guard = timedelta(minutes=self._signals.guard_minutes)
        base_end = target.started_at - guard - timedelta(minutes=10)
        base_start = base_end - timedelta(minutes=self._signals.baseline_minutes)
        cur_start = max(target.started_at - guard, now - timedelta(minutes=60))
        if cur_start >= now:
            cur_start = now - timedelta(minutes=5)
        return base_start, base_end, cur_start

    async def _metrics(self, target: InvestigationTarget, now: datetime) -> list[Finding]:
        prom = self._prometheus
        if prom is None or not self._signals.signals or not is_safe_name(target.service):
            return []
        base_start, base_end, cur_start = self._windows(target, now)

        async def check(signal: Signal) -> Finding | None:
            query = signal.query.replace("{service}", target.service)
            base, cur = await asyncio.gather(
                prom.query_range(query, base_start, base_end),
                prom.query_range(query, cur_start, now),
            )
            anomaly = compare(signal, base, cur)
            if anomaly is None:
                return None
            ratio = f" (×{anomaly.ratio:.1f})" if anomaly.ratio and signal.direction == "up" else ""
            return Finding(
                "metric",
                f"{signal.title}: {fmt(anomaly.baseline, signal.unit)} → {fmt(anomaly.current, signal.unit)}{ratio}",
                prom.graph_url(query, now),
                {"category": signal.category, "title": signal.title},
            )

        results = await asyncio.gather(*(check(s) for s in self._signals.signals), return_exceptions=True)
        findings: list[Finding] = []
        for signal, result in zip(self._signals.signals, results):
            if isinstance(result, BaseException):
                log.warning("Signal %s check failed: %r", signal.name, result)
            elif result is not None:
                findings.append(result)
        return findings

    async def _logs(self, target: InvestigationTarget, now: datetime) -> list[Finding]:
        cfg = self._signals.logs
        loki = self._loki
        if loki is None or cfg is None or not is_safe_name(target.service):
            return []
        query = cfg.query.replace("{service}", target.service)
        guard = self._signals.guard_minutes * 60
        window = max(300, min(3600, int((now - target.started_at).total_seconds()) + guard))
        before_at = target.started_at - timedelta(seconds=guard + 600)
        current, before = await asyncio.gather(
            loki.count(query, now, window),
            loki.count(query, before_at, window),
        )
        if current < cfg.min_lines or current < 2 * before:
            return []
        start = now - timedelta(seconds=window)
        patterns = top_patterns(await loki.lines(query, start, now))
        text = f"{current} error log lines in the last {window // 60} minutes (pre-incident baseline: {before})"
        if patterns:
            text += ". Most common: " + "; ".join(f"“{p}” ×{n}" for p, n in patterns)
        return [Finding("log", text, loki.explore_url(query, start, now))]

    async def _deploys(self, target: InvestigationTarget) -> list[Finding]:
        since = target.started_at - self._change_window
        findings: list[Finding] = []
        for ch in await self._changes.recent_changes(target.service, since):
            if not ch.url or ch.created_at > target.started_at:
                continue
            who = f" by {ch.author}" if ch.author else ""
            findings.append(
                Finding(
                    "change",
                    f"{ch.kind} `{ch.ref}`{who} at {ch.created_at:%H:%M} UTC",
                    ch.url,
                    {"ref": ch.ref, "author": ch.author, "created_at": ch.created_at},
                )
            )
        return findings

    def _dependencies(self, target: InvestigationTarget) -> list[Finding]:
        findings: list[Finding] = []
        for dep in self._catalog.get(target.service).depends_on:
            for alert in self._store.firing_alerts(dep):
                # Informational dependency alerts are too weak to cite as cascading failure evidence.
                if alert.fingerprint == target.fingerprint or alert.severity is Severity.INFO:
                    continue
                url = alert.source_url or f"{self._public_url}/alerts/{alert.fingerprint}"
                findings.append(
                    Finding(
                        "dependency",
                        f"`{dep}` has firing alert {alert.name} since {alert.first_seen:%H:%M} UTC: {redact(alert.summary)}",
                        url,
                        {"service": dep, "name": alert.name},
                    )
                )
        return findings

    def _memory_findings(self, similar: list[SimilarIncident]) -> list[Finding]:
        findings: list[Finding] = []
        for s in similar:
            cause = f" Root cause then: {s.root_cause}." if s.root_cause else ""
            fix = f" Fixed by: {s.fix}." if s.fix else ""
            findings.append(
                Finding(
                    "memory",
                    f"{s.code} ({s.name} on `{s.service}`) is similar to this incident.{cause}{fix}",
                    f"{self._public_url}/incidents/{s.incident_id}/postmortem",
                    {"code": s.code, "root_cause": s.root_cause},
                )
            )
        return findings
