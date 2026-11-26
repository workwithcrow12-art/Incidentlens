"""Monthly ROI reporting with explicit methodology for every metric."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from statistics import fmean

import yaml
from pydantic import BaseModel, Field

from incidentlens.store import Store


class BaselineBefore(BaseModel):
    """Measured pre-adoption baseline. Null fields are explicitly labeled in the report."""

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
    episodes: int  # Total alert episodes across all severities
    interruptions: int  # Incidents that actually paged on-call
    interruptions_now: float  # Per responder per day
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
        # Unmeasured baseline: conservatively show what would happen if every episode interrupted on-call.
        before = episodes / head / days

    return RoiReport(
        month=f"{start:%m/%Y}",
        days=days,
        headcount=head,
        episodes=episodes,
        interruptions=len(incidents),
        interruptions_now=len(incidents) / head / days,
        interruptions_before=before,
        interruptions_before_estimated=estimated,
        incidents_before=baseline.before.critical_incidents_per_month,
        mttr_now=fmean(durations) if durations else None,
        mttr_before=baseline.before.mttr_minutes,
        investigations=len(investigations),
        feedback_total=len(rated),
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
    accuracy = "—" if r.accuracy is None else f"{r.accuracy * 100:.0f}% ({r.feedback_up}/{r.feedback_total} rated)"
    lines = [
        f"# 📊 Monthly ROI Report {r.month}",
        "",
        f"> {r.episodes} alert episodes occurred; only {r.interruptions} paged on-call. "
        f"Calculated across {r.headcount} on-call responder(s) over {r.days} day(s).",
        "",
        "| Metric | Pre-adoption | This month | Change |",
        "| :--- | ---: | ---: | ---: |",
        f"| Interruptions / responder / day | {_num(r.interruptions_before, star, 2)} | "
        f"{_num(r.interruptions_now, digits=2)} | {_change(r.interruptions_before, r.interruptions_now)} |",
        f"| On-call incidents | {_num(r.incidents_before, digits=0)} | {r.interruptions} | "
        f"{_change(r.incidents_before, r.interruptions)} |",
        f"| Mean MTTR | {_num(r.mttr_before, ' min', 0)} | {_num(r.mttr_now, ' min', 0)} | "
        f"{_change(r.mttr_before, r.mttr_now)} |",
        f"| Confirmed hypotheses (top 3) | — | {accuracy} | — |",
        f"| Estimated investigation time saved | — | {r.hours_saved:.1f} hours | — |",
        "",
        f"**Highlight:** {r.memory_hits}/{r.investigations} investigations included similar-incident memory.",
        "",
        "## Methodology",
        "- **Interruptions:** paged incidents (🔴 critical and escalated 🟡) divided by headcount and days.",
    ]
    if star:
        lines.append(
            "- **\\* Pre-adoption (estimated):** no measured baseline configured, assuming every alert episode "
            "previously interrupted on-call. Set measured numbers in `config/baseline.yaml` for exact comparisons."
        )
    lines += [
        "- **MTTR:** mean duration from incident start to recovery across closed incidents.",
        "- **Confirmed hypotheses:** investigations marked ✅ divided by all rated investigations.",
        f"- **Time saved:** confirmed investigations × {r.minutes_per_correct} minutes. "
        "Conservative estimate counting only human-confirmed investigations.",
        "",
    ]
    return "\n".join(lines)
