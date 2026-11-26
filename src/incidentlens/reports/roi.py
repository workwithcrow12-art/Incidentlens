"""Báo cáo ROI hàng tháng (mục 8.3 của kế hoạch). Mọi con số đều kèm cách tính."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from statistics import fmean

import yaml
from pydantic import BaseModel, Field

from incidentlens.store import Store


class BaselineBefore(BaseModel):
    """Số đo TRƯỚC khi dùng sản phẩm. Bỏ trống thì báo cáo ghi rõ là chưa có."""

    interruptions_per_person_per_day: float | None = None
    mttr_minutes: float | None = None
    critical_incidents_per_month: int | None = None


class Baseline(BaseModel):
    oncall_headcount: int = Field(default=1, ge=1)
    minutes_saved_per_correct_investigation: int = 20
    before: BaselineBefore = Field(default_factory=BaselineBefore)

    @classmethod
    def from_yaml(cls, path: Path) -> Baseline:
        if not Path(path).exists():
            return cls()
        return cls.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})


class RoiReport(BaseModel):
    month: str
    days: int
    headcount: int
    episodes: int  # số lần cảnh báo xảy ra (mọi mức)
    interruptions: int  # số lần thật sự gọi on-call
    interruptions_now: float  # mỗi người mỗi ngày
    interruptions_before: float | None
    interruptions_before_estimated: bool
    incidents_before: int | None
    mttr_now: float | None
    mttr_before: float | None
    investigations: int
    feedback_total: int
    feedback_up: int
    memory_hits: int
    minutes_per_correct: int

    @property
    def accuracy(self) -> float | None:
        return self.feedback_up / self.feedback_total if self.feedback_total else None

    @property
    def hours_saved(self) -> float:
        return self.feedback_up * self.minutes_per_correct / 60


def month_bounds(month_start: datetime) -> tuple[datetime, datetime]:
    start = month_start.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end = (start + timedelta(days=32)).replace(day=1)
    return start, end


def compute_roi(store: Store, baseline: Baseline, month_start: datetime, now: datetime) -> RoiReport:
    start, end = month_bounds(month_start)
    effective_end = min(end, now) if now > start else end
    days = max(1, (effective_end - start).days)
    head = baseline.oncall_headcount

    episodes = store.count_episodes(start, end)
    incidents = store.incidents_between(start, end)
    durations = [i.duration_minutes for i in incidents if i.duration_minutes is not None]
    investigations = store.investigations_between(start, end)
    rated = [r for r in investigations if r.feedback]

    before = baseline.before.interruptions_per_person_per_day
    estimated = before is None
    if estimated and episodes:
        # Chưa có số đo thật: giả định trước đây MỌI cảnh báo đều làm phiền người trực
        before = episodes / head / days

    return RoiReport(
        month=f"{start:%m/%Y}", days=days, headcount=head, episodes=episodes,
        interruptions=len(incidents), interruptions_now=len(incidents) / head / days,
        interruptions_before=before, interruptions_before_estimated=estimated,
        incidents_before=baseline.before.critical_incidents_per_month,
        mttr_now=fmean(durations) if durations else None, mttr_before=baseline.before.mttr_minutes,
        investigations=len(investigations), feedback_total=len(rated),
        feedback_up=sum(1 for r in rated if r.feedback == "up"),
        memory_hits=sum(1 for r in investigations if r.investigation.similar),
        minutes_per_correct=baseline.minutes_saved_per_correct_investigation,
    )


def _num(value: float | None, suffix: str = "", digits: int = 1) -> str:
    return "—" if value is None else f"{value:.{digits}f}{suffix}"


def _change(before: float | None, now: float | None) -> str:
    if before is None or now is None or before == 0:
        return "—"
    return f"{(now - before) / before * 100:+.0f}%"


def render_roi(r: RoiReport) -> str:
    star = "*" if r.interruptions_before_estimated and r.interruptions_before is not None else ""
    accuracy = "—" if r.accuracy is None else f"{r.accuracy * 100:.0f}% ({r.feedback_up}/{r.feedback_total} có đánh giá)"
    lines = [
        f"# 📊 Báo cáo tháng {r.month}",
        "",
        f"> {r.episodes} lần cảnh báo xảy ra, chỉ {r.interruptions} lần phải gọi on-call. "
        f"Tính trên {r.headcount} người trực trong {r.days} ngày.",
        "",
        "| Chỉ số | Trước khi dùng | Tháng này | Thay đổi |",
        "| :--- | ---: | ---: | ---: |",
        f"| Lần bị làm phiền / người / ngày | {_num(r.interruptions_before, star, 2)} | "
        f"{_num(r.interruptions_now, digits=2)} | {_change(r.interruptions_before, r.interruptions_now)} |",
        f"| Sự cố phải gọi on-call | {_num(r.incidents_before, digits=0)} | {r.interruptions} | "
        f"{_change(r.incidents_before, r.interruptions)} |",
        f"| MTTR trung bình | {_num(r.mttr_before, ' phút', 0)} | {_num(r.mttr_now, ' phút', 0)} | "
        f"{_change(r.mttr_before, r.mttr_now)} |",
        f"| Giả thuyết đúng (trong top 3) | — | {accuracy} | — |",
        f"| Giờ điều tra tiết kiệm (ước tính) | — | {r.hours_saved:.1f} giờ | — |",
        "",
        f"**Nổi bật:** {r.memory_hits}/{r.investigations} cuộc điều tra có gợi ý từ trí nhớ sự cố.",
        "",
        "## Cách tính",
        "- **Lần bị làm phiền:** số sự cố gọi on-call (🔴 và 🟡 leo thang) chia cho số người trực và số ngày.",
    ]
    if star:
        lines.append("- **\\* Trước khi dùng (ước tính):** chưa có số đo thật, nên giả định trước đây mọi cảnh báo "
                     "đều làm phiền người trực. Điền số đo thật vào `config/baseline.yaml` để chính xác hơn.")
    lines += [
        "- **MTTR:** trung bình thời gian từ lúc sự cố bắt đầu đến lúc hồi phục, chỉ tính sự cố đã đóng.",
        "- **Giả thuyết đúng:** số cuộc điều tra được kỹ sư bấm ✅ chia cho số cuộc có đánh giá.",
        f"- **Giờ tiết kiệm:** số cuộc điều tra được xác nhận đúng × {r.minutes_per_correct} phút. "
        "Đây là ước tính thận trọng: chỉ tính các cuộc đã có người xác nhận.",
        "",
    ]
    return "\n".join(lines)
