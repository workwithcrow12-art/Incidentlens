"""Shared domain models across routing, storage, investigation, actions, and reporting."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal, overload

from pydantic import BaseModel, Field, field_validator

AlertStatus = Literal["firing", "resolved"]
IncidentOrigin = Literal["critical", "escalated"]
FeedbackVerdict = Literal["up", "down"]
EvidenceKind = Literal["metric", "log", "change", "dependency", "memory"]
Confidence = Literal["high", "medium", "low"]
CONFIDENCE_LABEL: dict[Confidence, str] = {"high": "High", "medium": "Medium", "low": "Low"}


@overload
def as_utc(dt: datetime) -> datetime: ...


@overload
def as_utc(dt: None) -> None: ...


def as_utc(dt: datetime | None) -> datetime | None:
    """Normalize datetimes to UTC; naive datetimes are treated as UTC."""
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


class DeliveryStatus(str, Enum):
    SENT = "sent"
    FAILED = "failed"
    NOT_CONFIGURED = "not_configured"

    def __bool__(self) -> bool:
        return self is DeliveryStatus.SENT


class Severity(str, Enum):
    """Alert severity determined strictly by static routing rules, never by an LLM."""

    CRITICAL = "critical"  # Immediate on-call page
    ACTION = "action"  # Grouped into periodic digest
    INFO = "info"  # Recorded only

    @property
    def icon(self) -> str:
        return {"critical": "🔴", "action": "🟡", "info": "⚪"}[self.value]

    @property
    def rank(self) -> int:
        return {"critical": 3, "action": 2, "info": 1}[self.value]


class Alert(BaseModel):
    """Normalized alert independent of upstream source (Alertmanager, Datadog, etc.)."""

    fingerprint: str
    name: str
    status: AlertStatus
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    starts_at: datetime
    ends_at: datetime | None = None
    source_url: str | None = None

    @field_validator("starts_at", "ends_at")
    @classmethod
    def _to_utc(cls, value: datetime | None) -> datetime | None:
        return as_utc(value)

    @property
    def service(self) -> str:
        return self.labels.get("service") or self.labels.get("job") or "unknown"

    @property
    def summary(self) -> str:
        return self.annotations.get("summary") or self.annotations.get("description") or self.name


class RoutedAlert(BaseModel):
    """Alert paired with its classified severity and matched routing rule."""

    alert: Alert
    severity: Severity
    rule: str


class AlertRecord(BaseModel):
    """Stored state of an alert episode."""

    fingerprint: str
    name: str
    service: str
    severity: Severity
    status: AlertStatus
    summary: str
    labels: dict[str, str] = Field(default_factory=dict)
    source_url: str | None = None
    first_seen: datetime
    last_seen: datetime
    receive_count: int
    escalated: bool = False
    escalated_at: datetime | None = None


class Change(BaseModel):
    """Recent service change (deployment, configuration update, etc.)."""

    service: str
    kind: str
    ref: str
    author: str | None = None
    created_at: datetime
    url: str | None = None


# ---------- Investigation ----------


class Evidence(BaseModel):
    """Single piece of collected evidence with a link back to the primary source."""

    id: str
    kind: EvidenceKind
    description: str
    url: str


class Hypothesis(BaseModel):
    statement: str
    confidence: Confidence
    evidence_ids: list[str] = Field(min_length=1)


class SimilarIncident(BaseModel):
    incident_id: int
    score: float
    service: str
    name: str
    root_cause: str | None = None
    fix: str | None = None
    duration_minutes: int | None = None
    resolved_at: datetime | None = None

    @property
    def code(self) -> str:
        return f"INC-{self.incident_id:04d}"


class InvestigationTarget(BaseModel):
    """Target of an automated investigation: a critical incident or an ongoing action group."""

    fingerprint: str
    service: str
    name: str
    summary: str
    started_at: datetime
    labels: dict[str, str] = Field(default_factory=dict)

    @classmethod
    def from_record(cls, record: AlertRecord) -> InvestigationTarget:
        return cls(
            fingerprint=record.fingerprint,
            service=record.service,
            name=record.name,
            summary=record.summary,
            started_at=record.first_seen,
            labels=record.labels,
        )


class Investigation(BaseModel):
    target: InvestigationTarget
    hypotheses: list[Hypothesis] = Field(default_factory=list, max_length=3)
    evidence: list[Evidence] = Field(default_factory=list)
    similar: list[SimilarIncident] = Field(default_factory=list)
    engine: Literal["rules", "llm"] = "rules"
    duration_seconds: float = 0.0

    def evidence_for(self, hypothesis: Hypothesis) -> list[Evidence]:
        by_id = {e.id: e for e in self.evidence}
        return [by_id[i] for i in hypothesis.evidence_ids if i in by_id]


class InvestigationRecord(BaseModel):
    id: int
    incident_id: int | None = None
    created_at: datetime
    investigation: Investigation
    feedback: FeedbackVerdict | None = None
    feedback_hypothesis: int | None = None
    feedback_by: str | None = None


# ---------- Digest ----------


class AlertGroup(BaseModel):
    """Alerts grouped by (service, alert name) for digest rendering."""

    service: str
    name: str
    team: str
    records: list[AlertRecord]
    changes: list[Change] = Field(default_factory=list)
    investigation: Investigation | None = None

    @property
    def severity(self) -> Severity:
        return max((r.severity for r in self.records), key=lambda s: s.rank)

    @property
    def first_seen(self) -> datetime:
        return min(r.first_seen for r in self.records)

    @property
    def last_seen(self) -> datetime:
        return max(r.last_seen for r in self.records)

    @property
    def receive_count(self) -> int:
        return sum(r.receive_count for r in self.records)

    @property
    def is_ongoing(self) -> bool:
        return any(r.status == "firing" for r in self.records)

    @property
    def escalated(self) -> bool:
        return any(r.escalated for r in self.records)

    @property
    def summary(self) -> str:
        return self.records[0].summary

    @property
    def source_url(self) -> str | None:
        return next((r.source_url for r in self.records if r.source_url), None)


# ---------- Paged incidents ----------


class IncidentRecord(BaseModel):
    """An incident that paged on-call (critical or escalated). Closed incidents feed incident memory."""

    id: int
    fingerprint: str
    service: str
    name: str
    summary: str
    labels: dict[str, str] = Field(default_factory=dict)
    origin: IncidentOrigin
    started_at: datetime
    opened_at: datetime
    resolved_at: datetime | None = None
    root_cause: str | None = None
    fix: str | None = None

    @property
    def code(self) -> str:
        return f"INC-{self.id:04d}"

    @property
    def duration_minutes(self) -> int | None:
        if self.resolved_at is None:
            return None
        return max(0, int((self.resolved_at - self.started_at).total_seconds() // 60))


class ActionRecord(BaseModel):
    id: int
    at: datetime
    incident_id: int
    action: str
    service: str
    user: str
    status: str
    exit_code: int | None = None
    output: str = ""
