"""Deterministic postmortem draft generator (no LLM required)."""

from __future__ import annotations

from incidentlens.markdown import md_code, md_text, md_url
from incidentlens.models import CONFIDENCE_LABEL, ActionRecord, IncidentRecord, InvestigationRecord

_TODO = "_To be determined — owner review required._"


def render_postmortem(
    incident: IncidentRecord,
    investigations: list[InvestigationRecord],
    actions: list[ActionRecord],
    team: str,
) -> str:
    origin = "🔴 Critical (immediate page)" if incident.origin == "critical" else "⬆️ Escalated from 🟡"
    resolved = f"{incident.resolved_at:%Y-%m-%d %H:%M} UTC" if incident.resolved_at else "unresolved"
    duration = f"{incident.duration_minutes} minutes" if incident.duration_minutes is not None else "—"

    timeline = [(incident.started_at, "Incident started"), (incident.opened_at, "On-call paged")]
    for rec in investigations:
        n = len(rec.investigation.hypotheses)
        timeline.append(
            (
                rec.created_at,
                f"Automated investigation completed ({n} hypotheses, {rec.investigation.duration_seconds:.0f}s)",
            )
        )
    for a in actions:
        timeline.append((a.at, f"{md_text(a.user)} triggered action {md_code(a.action)} → {md_text(a.status)}"))
    if incident.resolved_at:
        timeline.append((incident.resolved_at, "Resolved"))
    timeline.sort(key=lambda item: item[0])

    lines = [
        f"# Postmortem (draft) · {incident.code} · {md_text(incident.name)} on {md_code(incident.service)}",
        "",
        "> Auto-generated draft from recorded incident data. Review and complete before sharing.",
        "",
        "## Summary",
        f"- **Description:** {md_text(incident.summary)}",
        f"- **Service:** {md_code(incident.service)} · **Owner:** {md_text(team)}",
        f"- **Classification:** {origin}",
        f"- **Started:** {incident.started_at:%Y-%m-%d %H:%M} UTC · **Resolved:** {resolved}",
        f"- **Duration:** {duration}",
        "",
        "## Timeline (UTC)",
        *[f"- {at:%m-%d %H:%M} — {text}" for at, text in timeline],
        "",
        "## Root cause",
        md_text(incident.root_cause) if incident.root_cause else _TODO,
    ]

    for rec in investigations:
        inv = rec.investigation
        if not inv.hypotheses:
            continue
        lines += ["", "### System hypotheses"]
        cited: list[str] = []
        for n, h in enumerate(inv.hypotheses, 1):
            mark = ""
            if rec.feedback == "up" and rec.feedback_hypothesis == n:
                mark = f" ✅ _(confirmed by {md_text(rec.feedback_by or '')})_"
            label = CONFIDENCE_LABEL[h.confidence]
            ev_ids = ", ".join(h.evidence_ids)
            lines.append(f"{n}. **[{label}]** {md_text(h.statement)} ({ev_ids}){mark}")
            cited += [i for i in h.evidence_ids if i not in cited]
        if rec.feedback == "down":
            lines.append(f"\n_👎 {md_text(rec.feedback_by or '')} marked: none of the hypotheses were correct._")
        lines += ["", "### Evidence"]
        for e in inv.evidence:
            if e.id not in cited:
                continue
            safe_url = md_url(e.url)
            desc = md_text(e.description)
            lines.append(f"- **{e.id}** [{desc}]({safe_url})" if safe_url else f"- **{e.id}** {desc}")

    lines += [
        "",
        "## Resolution",
        md_text(incident.fix) if incident.fix else _TODO,
        "",
        "## Lessons learned and follow-ups",
        "- [ ] What prevents this incident from recurring?",
        "- [ ] Which signal or alert could detect it earlier?",
        "- [ ] Does the runbook need updates?",
        "",
    ]
    return "\n".join(lines)
