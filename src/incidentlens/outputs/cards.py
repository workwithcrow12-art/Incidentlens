"""Slack Block Kit investigation cards."""

from __future__ import annotations

from typing import Any

from incidentlens.actions.runner import ActionSpec
from incidentlens.models import CONFIDENCE_LABEL, IncidentRecord, InvestigationRecord


def esc(text: str) -> str:
    """Escape Slack mrkdwn control characters so untrusted alert/log text cannot inject links or mentions."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def link(url: str, text: str) -> str:
    safe_url = url.replace("|", "%7C").replace(">", "%3E").replace("<", "%3C")
    return f"<{safe_url}|{esc(text).replace('|', '/')}>"


def _short(text: str, limit: int = 280) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _section(text: str) -> dict[str, Any]:
    return {"type": "section", "text": {"type": "mrkdwn", "text": text[:2900]}}


def _button(text: str, action_id: str, value: str, **extra: Any) -> dict[str, Any]:
    return {
        "type": "button",
        "text": {"type": "plain_text", "text": text[:75]},
        "action_id": action_id,
        "value": value,
        **extra,
    }


def investigation_card(
    record: InvestigationRecord,
    incident: IncidentRecord | None,
    actions: list[tuple[str, ActionSpec]],
    runbook: str | None,
) -> tuple[str, list[dict[str, Any]]]:
    inv = record.investigation
    t = inv.target
    code = f" · {incident.code}" if incident else ""
    parts = [f"🔍 *Automated investigation: {esc(t.name)}* on `{esc(t.service)}`{code}\n{esc(t.summary)}"]

    if inv.hypotheses:
        lines = ["*Hypotheses*"]
        cited: list[str] = []
        for n, h in enumerate(inv.hypotheses, 1):
            lines.append(
                f"{n}. *[{CONFIDENCE_LABEL[h.confidence]}]* {esc(h.statement)} _({', '.join(h.evidence_ids)})_"
            )
            cited += [i for i in h.evidence_ids if i not in cited]
        parts.append("\n".join(lines))
        # List each cited evidence item once with a link back to the primary source.
        shown = [e for e in inv.evidence if e.id in cited]
        parts.append("\n".join(["*Evidence*", *[f"• {e.id} {link(e.url, _short(e.description))}" for e in shown]]))
    elif inv.evidence:
        lines = ["_Insufficient basis for a hypothesis. Collected evidence:_"]
        lines += [f"• {link(e.url, _short(e.description))}" for e in inv.evidence]
        parts.append("\n".join(lines))
    else:
        parts.append("_No anomalies found in metrics, logs, deployments, or dependencies._")

    if inv.similar:
        s = inv.similar[0]
        text = f"📎 *Similar incident:* {s.code} ({esc(s.name)} on `{esc(s.service)}`)"
        if s.root_cause:
            text += f"\nPrevious root cause: {esc(s.root_cause)}"
        if s.fix:
            text += f"\nPrevious fix: {esc(s.fix)}"
        if s.duration_minutes is not None:
            text += f"\nResolution time: {s.duration_minutes} minutes"
        parts.append(text)

    blocks = [_section(p) for p in parts]
    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "Machine-generated suggestions; human verification required. "
                    "Actions run only when approved by an authorized responder.",
                }
            ],
        }
    )

    ops: list[dict[str, Any]] = []
    if runbook:
        ops.append(
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "📋 Runbook"},
                "action_id": "runbook",
                "url": runbook,
            }
        )
    if incident:
        for name, spec in actions[:4]:
            question = (spec.confirm or "Run *" + spec.label + "* on `{service}`?").replace("{service}", t.service)
            ops.append(
                _button(
                    spec.label,
                    f"act_{name}",
                    f"{incident.id}:{name}",
                    style="danger",
                    confirm={
                        "title": {"type": "plain_text", "text": "Confirm"},
                        "text": {"type": "mrkdwn", "text": question[:290]},
                        "confirm": {"type": "plain_text", "text": "Run"},
                        "deny": {"type": "plain_text", "text": "Cancel"},
                    },
                )
            )
    if ops:
        blocks.append({"type": "actions", "elements": ops})

    if inv.hypotheses:
        feedback = [
            _button(f"✅ Hypothesis {n} correct", f"fb_{n}", f"{record.id}:{n}")
            for n in range(1, len(inv.hypotheses) + 1)
        ]
        feedback.append(_button("👎 None correct", "fb_0", f"{record.id}:0"))
        blocks.append({"type": "actions", "elements": feedback})

    return "\n\n".join(parts), blocks
