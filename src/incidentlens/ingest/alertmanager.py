"""Chuyển payload webhook của Prometheus Alertmanager thành Alert chuẩn hóa."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime

from pydantic import BaseModel, Field

from incidentlens.models import Alert, AlertStatus


class AMAlert(BaseModel):
    status: AlertStatus
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    startsAt: datetime
    endsAt: datetime | None = None
    generatorURL: str | None = None
    fingerprint: str | None = None


class AlertmanagerPayload(BaseModel):
    version: str = "4"
    status: str | None = None
    alerts: list[AMAlert]


def _fallback_fingerprint(labels: dict[str, str]) -> str:
    raw = json.dumps(labels, sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def to_alerts(payload: AlertmanagerPayload) -> list[Alert]:
    alerts = []
    for a in payload.alerts:
        # Alertmanager dùng "0001-01-01T00:00:00Z" cho cảnh báo chưa kết thúc
        ends_at = a.endsAt if a.endsAt and a.endsAt.year > 1970 else None
        alerts.append(
            Alert(
                fingerprint=a.fingerprint or _fallback_fingerprint(a.labels),
                name=a.labels.get("alertname", "unknown"),
                status=a.status,
                labels=a.labels,
                annotations=a.annotations,
                starts_at=a.startsAt,
                ends_at=ends_at,
                source_url=a.generatorURL or None,
            )
        )
    return alerts
