"""Các kiểu dữ liệu dùng chung trong toàn hệ thống."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator

AlertStatus = Literal["firing", "resolved"]
EvidenceKind = Literal["metric", "log", "change", "dependency", "memory"]
Confidence = Literal["high", "medium", "low"]
CONFIDENCE_LABEL = {"high": "Cao", "medium": "Trung bình", "low": "Thấp"}


def as_utc(dt: datetime | None) -> datetime | None:
    """Chuẩn hóa về UTC. Thời gian không có múi giờ được coi là UTC."""
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


class Severity(str, Enum):
    """Ba mức cảnh báo. Mức do luật định tuyến quyết định, không phải AI."""

    CRITICAL = "critical"  # 🔴 gọi on-call ngay
    ACTION = "action"  # 🟡 gom vào digest
    INFO = "info"  # ⚪ chỉ ghi lại

    @property
    def icon(self) -> str:
        return {"critical": "🔴", "action": "🟡", "info": "⚪"}[self.value]

    @property
    def rank(self) -> int:
        return {"critical": 3, "action": 2, "info": 1}[self.value]


class Alert(BaseModel):
    """Một cảnh báo đã chuẩn hóa, không phụ thuộc nguồn (Alertmanager, Datadog...)."""

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
    def _utc(cls, value: datetime | None) -> datetime | None:
        return as_utc(value)

    @property
    def service(self) -> str:
        return self.labels.get("service") or self.labels.get("job") or "unknown"

    @property
    def summary(self) -> str:
        return self.annotations.get("summary") or self.annotations.get("description") or self.name


class RoutedAlert(BaseModel):
    """Cảnh báo kèm mức đã được xếp và tên luật đã khớp."""

    alert: Alert
    severity: Severity
    rule: str


class AlertRecord(BaseModel):
    """Trạng thái một cảnh báo được lưu trong hệ thống."""

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
    """Một thay đổi gần đây (deploy, config, feature flag...)."""

    service: str
    kind: str
    ref: str
    author: str | None = None
    created_at: datetime
    url: str | None = None


# ---------- Điều tra ----------


class Evidence(BaseModel):
    """Một bằng chứng. Bắt buộc có link về dữ liệu gốc."""

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
    """Thứ cần điều tra: một cảnh báo 🔴 hoặc một nhóm 🟡 trong digest."""

    fingerprint: str
    service: str
    name: str
    summary: str
    started_at: datetime
    labels: dict[str, str] = Field(default_factory=dict)

    @classmethod
    def from_record(cls, record: AlertRecord) -> InvestigationTarget:
        return cls(fingerprint=record.fingerprint, service=record.service, name=record.name,
                   summary=record.summary, started_at=record.first_seen, labels=record.labels)


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
    feedback: Literal["up", "down"] | None = None
    feedback_hypothesis: int | None = None
    feedback_by: str | None = None


# ---------- Digest ----------


class AlertGroup(BaseModel):
    """Nhóm cảnh báo cùng dịch vụ và cùng loại, hiển thị như một mục trong digest."""

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


# ---------- Sự cố đã gọi on-call ----------


class IncidentRecord(BaseModel):
    """Một sự cố đã gọi on-call (🔴 trực tiếp hoặc 🟡 leo thang). Khi đóng lại sẽ thành trí nhớ sự cố."""

    id: int
    fingerprint: str
    service: str
    name: str
    summary: str
    labels: dict[str, str] = Field(default_factory=dict)
    origin: Literal["critical", "escalated"]
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
