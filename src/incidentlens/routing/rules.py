"""Bộ định tuyến luật: xếp cảnh báo vào 🔴 / 🟡 / ⚪ và quyết định leo thang.

Đây là đường đi của cảnh báo khẩn cấp nên KHÔNG dùng AI: phải nhanh, đoán trước được
và chỉ do con người cấu hình.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

from incidentlens.models import Alert, AlertRecord, RoutedAlert, Severity


class Rule(BaseModel):
    name: str
    severity: Severity
    match: dict[str, str] = Field(default_factory=dict)
    match_re: dict[str, str] = Field(default_factory=dict)

    @field_validator("match_re")
    @classmethod
    def _valid_regex(cls, value: dict[str, str]) -> dict[str, str]:
        for key, pattern in value.items():
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"Regex không hợp lệ cho label '{key}': {exc}") from exc
        return value

    def matches(self, labels: dict[str, str]) -> bool:
        if any(labels.get(k) != v for k, v in self.match.items()):
            return False
        return all(re.fullmatch(p, labels.get(k, "")) for k, p in self.match_re.items())


class EscalationPolicy(BaseModel):
    max_pending_minutes: int | None = 240
    max_receive_count: int | None = None


class RoutingConfig(BaseModel):
    default_severity: Severity = Severity.INFO
    rules: list[Rule] = Field(default_factory=list)
    escalation: EscalationPolicy = Field(default_factory=EscalationPolicy)


class Router:
    def __init__(self, config: RoutingConfig) -> None:
        self.config = config

    @classmethod
    def from_yaml(cls, path: Path) -> Router:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls(RoutingConfig.model_validate(data))

    def classify(self, alert: Alert) -> RoutedAlert:
        for rule in self.config.rules:
            if rule.matches(alert.labels):
                return RoutedAlert(alert=alert, severity=rule.severity, rule=rule.name)
        return RoutedAlert(alert=alert, severity=self.config.default_severity, rule="default")

    def escalation_reason(self, record: AlertRecord, now: datetime) -> str | None:
        """Trả về lý do nếu cảnh báo 🟡 cần nâng lên 🔴, ngược lại trả về None."""
        if record.severity is not Severity.ACTION or record.status != "firing" or record.escalated:
            return None
        policy = self.config.escalation
        if policy.max_pending_minutes is not None:
            age = now - record.first_seen
            if age >= timedelta(minutes=policy.max_pending_minutes):
                return f"vẫn chưa hồi phục sau {int(age.total_seconds() // 60)} phút"
        if policy.max_receive_count is not None and record.receive_count >= policy.max_receive_count:
            return f"đã lặp lại {record.receive_count} lần"
        return None
