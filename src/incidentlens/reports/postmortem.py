"""Deterministic postmortem draft generator (no LLM required)."""

from __future__ import annotations

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
        timeline.append((a.at, f"{a.user} triggered action `{a.action}` → {a.status}"))
    if incident.resolved_at:
        timeline.append((incident.resolved_at, "Resolved"))
    timeline.sort(key=lambda item: item[0])

    lines = [
        f"# Postmortem (draft) · {incident.code} · {incident.name} on `{incident.service}`",
        "",
        "> Auto-generated draft from recorded incident data. Review and complete before sharing.",
        "",
        "## Summary",
        f"- **Description:** {incident.summary}",
        f"- **Service:** `{incident.service}` · **Owner:** {team}",
        f"- **Classification:** {origin}",
        f"- **Started:** {incident.started_at:%Y-%m-%d %H:%M} UTC · **Resolved:** {resolved}",
        f"- **Duration:** {duration}",
        "",
        "## Timeline (UTC)",
        *[f"- {at:%m-%d %H:%M} — {text}" for at, text in timeline],
        "",
        "## Root cause",
        incident.root_cause or _TODO,
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
                mark = f" ✅ _(confirmed by {rec.feedback_by})_"
            lines.append(
                f"{n}. **[{CONFIDENCE_LABEL[h.confidence]}]** {h.statement} ({', '.join(h.evidence_ids)}){mark}"
            )
            cited += [i for i in h.evidence_ids if i not in cited]
        if rec.feedback == "down":
            lines.append(f"\n_👎 {rec.feedback_by} marked: none of the hypotheses were correct._")
        lines += ["", "### Evidence"]
        lines += [f"- **{e.id}** [{e.description}]({e.url})" for e in inv.evidence if e.id in cited]

    lines += [
        "",
        "## Resolution",
        incident.fix or _TODO,
        "",
        "## Lessons learned and follow-ups",
        "- [ ] What prevents this incident from recurring?",
        "- [ ] Which signal or alert could detect it earlier?",
        "- [ ] Does the runbook need updates?",
        "",
    ]
    return "\n".join(lines)
