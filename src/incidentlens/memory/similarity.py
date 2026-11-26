"""Incident memory: retrieve closed incidents similar to the current investigation target.

Uses structured similarity (alert name and service) combined with token Jaccard overlap so it runs
on SQLite and PostgreSQL without an external embedding model. Can later be swapped for pgvector
behind the same interface.
"""

from __future__ import annotations

import re

from incidentlens.models import IncidentRecord, InvestigationTarget, SimilarIncident
from incidentlens.store import Store

_WORD = re.compile(r"[^\W\d_]{2,}|\d{2,}", re.UNICODE)
_IGNORED_LABELS = {"alertname", "service", "job", "severity", "instance", "pod"}


def _tokens(summary: str, labels: dict[str, str]) -> set[str]:
    text = summary + " " + " ".join(v for k, v in labels.items() if k not in _IGNORED_LABELS)
    return {w.lower() for w in _WORD.findall(text)}


def similarity(target: InvestigationTarget, incident: IncidentRecord) -> float:
    """Score in [0, 1]: 0.5 for matching alert name, 0.2 for matching service, 0.3 for token overlap."""
    a = _tokens(target.summary, target.labels)
    b = _tokens(incident.summary, incident.labels)
    overlap = len(a & b) / len(a | b) if a and b else 0.0
    return 0.5 * (target.name == incident.name) + 0.2 * (target.service == incident.service) + 0.3 * overlap


class IncidentMemory:
    def __init__(self, store: Store, min_score: float = 0.5, limit: int = 3, scan: int = 500) -> None:
        self._store = store
        self._min_score = min_score
        self._limit = limit
        self._scan = scan

    def find_similar(self, target: InvestigationTarget) -> list[SimilarIncident]:
        scored: list[tuple[float, bool, float, IncidentRecord]] = []
        for incident in self._store.closed_incidents(self._scan):
            if incident.fingerprint == target.fingerprint and incident.started_at == target.started_at:
                continue  # Exclude the exact episode currently under investigation
            score = similarity(target, incident)
            if score >= self._min_score:
                resolved_ts = incident.resolved_at.timestamp() if incident.resolved_at else 0.0
                scored.append((score, bool(incident.root_cause), resolved_ts, incident))
        scored.sort(key=lambda item: item[:3], reverse=True)
        return [
            SimilarIncident(
                incident_id=i.id,
                score=round(score, 3),
                service=i.service,
                name=i.name,
                root_cause=i.root_cause,
                fix=i.fix,
                duration_minutes=i.duration_minutes,
                resolved_at=i.resolved_at,
            )
            for score, _, _, i in scored[: self._limit]
        ]
