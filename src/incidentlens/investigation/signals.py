"""Tín hiệu cần kiểm tra khi điều tra, và phép so sánh "trước sự cố" với "trong sự cố"."""

from __future__ import annotations

from pathlib import Path
from statistics import fmean
from typing import Literal

import yaml
from pydantic import BaseModel, Field


class Signal(BaseModel):
    name: str
    title: str
    query: str  # PromQL, dùng {service} làm chỗ điền tên dịch vụ; nên trả về 1 chuỗi số
    category: Literal["errors", "latency", "saturation", "restarts", "traffic"] = "errors"
    direction: Literal["up", "down"] = "up"
    min_ratio: float = 2.0  # bất thường khi thay đổi ít nhất ngần này lần
    min_abs: float = 0.0  # và chênh lệch tuyệt đối ít nhất ngần này
    unit: Literal["", "s", "ms", "ratio", "bytes"] = ""


class LogQuery(BaseModel):
    query: str  # LogQL, dùng {service}
    min_lines: int = 5


class SignalConfig(BaseModel):
    baseline_minutes: int = 60
    guard_minutes: int = 5
    signals: list[Signal] = Field(default_factory=list)
    logs: LogQuery | None = None

    @classmethod
    def from_yaml(cls, path: Path) -> SignalConfig:
        if not Path(path).exists():
            return cls()
        return cls.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})


class Anomaly(BaseModel):
    baseline: float
    current: float

    @property
    def ratio(self) -> float | None:
        return self.current / self.baseline if self.baseline > 1e-12 else None


def compare(signal: Signal, baseline: list[float], current: list[float]) -> Anomaly | None:
    """Trả về Anomaly nếu giá trị trong sự cố lệch đáng kể so với trước sự cố."""
    if not current:
        return None
    base = fmean(baseline) if baseline else 0.0
    cur = fmean(current)
    if signal.direction == "up":
        big, small = cur, base
    else:
        if not baseline:
            return None  # không có số liệu trước đó thì không thể nói là "giảm"
        big, small = base, cur
    if big - small < signal.min_abs or big <= small:
        return None
    if small > 1e-12 and big / small < signal.min_ratio:
        return None
    return Anomaly(baseline=base, current=cur)


def fmt(value: float, unit: str) -> str:
    if unit == "ratio":
        return f"{value * 100:.3g}%"
    if unit == "bytes":
        for name, size in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
            if abs(value) >= size:
                return f"{value / size:.3g} {name}"
        return f"{value:.0f} B"
    if unit == "s" and abs(value) < 1:
        return f"{value * 1000:.3g}ms"
    return f"{value:.3g}{unit}"
